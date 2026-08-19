//! HTTP transport (MCP Streamable HTTP, JSON-response mode). Lets Simvader run as a *service* that
//! MCP clients connect to over HTTP, instead of being spawned per-client over stdio — the shape
//! needed to front server-side deployments. Every request runs through the same `evaluate_call`
//! decision path as the stdio transport, so policy/guard/audit behavior is identical.
//!
//! Synchronous by design (`tiny_http` + a worker-thread pool), matching the rest of the codebase.
//! Downstreams are spawned once at startup; each request/response is correlated by JSON-RPC id under
//! a per-downstream lock. Server-initiated SSE streams (notifications, sampling) are not yet served.

use std::collections::{HashMap, HashSet};
use std::io::{self, BufReader};
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server, StatusCode};

use crate::config::DownstreamServer;
use crate::gateway::{
    build_catalog, evaluate_call, init_one, read_json_response, write_line, CallOutcome, Catalog,
    GatewayConfig, DEFAULT_PROTOCOL, VERSION,
};

/// A live stdio connection to one downstream, used for synchronous request/response.
struct Conn {
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
}

struct HttpState {
    catalog: Catalog,
    cfg: GatewayConfig,
    downstreams: HashMap<String, Mutex<Conn>>,
    /// Calls already handed back for reflection (shared across worker threads).
    reflected: Mutex<HashSet<String>>,
    /// Kept alive so the child processes aren't reaped.
    _children: Vec<Child>,
}

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

fn synth_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Run the gateway as an HTTP server. Blocks until the listener stops.
pub fn serve_http(servers: Vec<DownstreamServer>, cfg: GatewayConfig, addr: &str) -> io::Result<()> {
    let mut per_server: Vec<(String, Vec<Value>)> = Vec::new();
    let mut downstreams: HashMap<String, Mutex<Conn>> = HashMap::new();
    let mut children: Vec<Child> = Vec::new();

    for s in &servers {
        match init_one(s, DEFAULT_PROTOCOL) {
            Ok((child, stdin, reader, tools)) => {
                eprintln!("[simvader] downstream '{}' up: {} tools", s.alias, tools.len());
                per_server.push((s.alias.clone(), tools));
                downstreams.insert(s.alias.clone(), Mutex::new(Conn { stdin, reader }));
                children.push(child);
            }
            Err(e) => eprintln!("[simvader] downstream '{}' failed to start: {e}", s.alias),
        }
    }

    let catalog = build_catalog(&per_server, cfg.options.augment);
    eprintln!(
        "[simvader] http gateway ready: {} tools across {} downstream(s){} on http://{addr}",
        catalog.tools.len(),
        downstreams.len(),
        if cfg.options.audit { " [audit mode]" } else { "" }
    );

    let state = Arc::new(HttpState {
        catalog,
        cfg,
        downstreams,
        reflected: Mutex::new(HashSet::new()),
        _children: children,
    });
    let server = Arc::new(
        Server::http(addr).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
    );

    // A small pool of worker threads all pulling from the shared listener.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        handles.push(thread::spawn(move || {
            while let Ok(req) = server.recv() {
                handle(req, &state);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn handle(mut req: tiny_http::Request, state: &HttpState) {
    // Only POST carries MCP messages. A GET is an SSE-stream probe we don't serve yet.
    if *req.method() != Method::Post {
        let _ = req.respond(
            Response::from_string("simvader MCP gateway: POST newline-delimited JSON-RPC here\n")
                .with_status_code(StatusCode(405)),
        );
        return;
    }

    let mut body = String::new();
    if req.as_reader().read_to_string(&mut body).is_err() {
        let _ = req.respond(Response::from_string("bad request body").with_status_code(StatusCode(400)));
        return;
    }
    let msg: Value = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => {
            let _ = req.respond(Response::from_string("invalid JSON").with_status_code(StatusCode(400)));
            return;
        }
    };

    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let id = msg.get("id").cloned();
    // A notification (no id) gets an empty accept — nothing to route in JSON-response mode.
    let Some(_) = id else {
        let _ = req.respond(Response::from_string("").with_status_code(StatusCode(202)));
        return;
    };
    let id_val = id.unwrap_or(Value::Null);

    let resp_json: Value = match method {
        "initialize" => {
            let pv = msg
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL)
                .to_string();
            json!({
                "jsonrpc": "2.0", "id": id_val,
                "result": {
                    "protocolVersion": pv,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "simvader", "version": VERSION }
                }
            })
        }
        "ping" => json!({ "jsonrpc": "2.0", "id": id_val, "result": {} }),
        "tools/list" => {
            json!({ "jsonrpc": "2.0", "id": id_val, "result": { "tools": state.catalog.tools.clone() } })
        }
        "tools/call" => {
            let name = msg.pointer("/params/name").and_then(Value::as_str).unwrap_or("").to_string();
            let args = msg.pointer("/params/arguments").cloned().unwrap_or_else(|| json!({}));
            let cfg = &state.cfg;
            match evaluate_call(
                &state.catalog, &cfg.policy, &cfg.options, cfg.reflector.as_ref(), &name, &args,
                &id_val, cfg.audit.as_ref(), cfg.learner.as_ref(), &state.reflected,
            ) {
                CallOutcome::Refuse { body } => body,
                CallOutcome::Forward { alias, original } => match state.downstreams.get(&alias) {
                    Some(conn) => {
                        let mut fwd = msg.clone();
                        if let Some(p) = fwd.get_mut("params") {
                            p["name"] = Value::String(original);
                        }
                        match downstream_request(conn, &fwd, &id_val) {
                            Ok(resp) => resp,
                            Err(e) => {
                                eprintln!("[simvader] downstream '{alias}' error: {e}");
                                synth_error(&id_val, -32003, "downstream error")
                            }
                        }
                    }
                    None => synth_error(&id_val, -32004, "downstream unavailable"),
                },
            }
        }
        _ => synth_error(&id_val, -32601, "method not handled by simvader gateway"),
    };

    let session = format!("sv-{}", SESSION_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut response = Response::from_string(serde_json::to_string(&resp_json).unwrap_or_default());
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        response = response.with_header(h);
    }
    if let Ok(h) = Header::from_bytes(&b"Mcp-Session-Id"[..], session.as_bytes()) {
        response = response.with_header(h);
    }
    let _ = req.respond(response);
}

/// Send one request to a downstream and read back its matching response (correlated by JSON-RPC id),
/// serialized per downstream by the lock.
fn downstream_request(conn: &Mutex<Conn>, msg: &Value, id_val: &Value) -> io::Result<Value> {
    // Match read_json_response's id comparison: a string id keeps its text, others stringify.
    let want = match id_val {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let c = &mut *conn.lock().unwrap();
    write_line(&mut c.stdin, msg)?;
    read_json_response(&mut c.reader, &want)
}
