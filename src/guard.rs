//! Stage 3 of SPELLSMITH: the deterministic, sub-millisecond invocation guard. Given a tool's
//! `RiskProfile` and the concrete call arguments, decide Allow / Suspicious / Block. No I/O, no
//! DNS on the fast path (see `--resolve`), no LLM — that keeps the latency floor in microseconds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::Value;
use url::{Host, Url};

use crate::canon;
use crate::risk::{Cwe, RiskProfile};

/// The guard's decision for a single `tools/call`.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// No taint indicators.
    Allow,
    /// Touches a sensitive capability with a weak indicator; escalate to the LLM reflector if
    /// enabled, otherwise log + allow (fail-open).
    Suspicious { cwe: Cwe, param: String, note: String },

    Block { cwe: Cwe, param: String, reason: String, snippet: String },
}

/// Per-parameter check outcome, promoted to a `Verdict` by `guard_call`.
enum Check {
    Clean,
    Suspicious(String),
    Block { reason: String, snippet: String },
}

const SNIPPET_MAX: usize = 160;

fn snippet(s: &str) -> String {
    if s.len() <= SNIPPET_MAX {
        s.to_string()
    } else {
        let mut end = SNIPPET_MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

/// Collect every string leaf of an argument value, at any depth. A payload nested inside an object
/// or an array of objects (not just a bare string or `["a","b"]` argv) is still inspected, closing
/// the "hide it one level down" bypass.
pub(crate) fn string_leaves(value: &Value) -> Vec<&str> {
    let mut out = Vec::new();
    collect_leaves(value, &mut out);
    out
}

fn collect_leaves<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::String(s) => out.push(s.as_str()),
        Value::Array(items) => items.iter().for_each(|v| collect_leaves(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_leaves(v, out)),
        _ => {}
    }
}

/// Run the deterministic guard over a call (SPELLSMITH stage 3). Returns the most severe verdict:
/// the first `Block` short-circuits; otherwise the first `Suspicious`; otherwise `Allow`.
pub fn guard_call(profile: &RiskProfile, arguments: &Value) -> Verdict {
    guard_call_with(profile, arguments, false)
}

/// As `guard_call`, but with `resolve` controlling whether SSRF checks resolve a hostname through
/// DNS to catch a domain that points at an internal address (off the fast path; opt-in via
/// `--resolve`).
pub fn guard_call_with(profile: &RiskProfile, arguments: &Value, resolve: bool) -> Verdict {
    let mut first_suspicious: Option<Verdict> = None;

    for param in &profile.tainted_params {
        let Some(cwe) = profile.param_cwe.get(param).copied() else {
            continue;
        };
        let Some(value) = arguments.get(param) else {
            continue;
        };
        for leaf in string_leaves(value) {
            // Inspect the literal leaf and, if it is base64 that decodes to text, the decoded form
            // too, so a wrapped payload (e.g. base64 of an internal URL) cannot slip past.
            match check_leaf_views(cwe, leaf, resolve) {
                Check::Clean => {}
                Check::Block { reason, snippet } => {
                    return Verdict::Block { cwe, param: param.clone(), reason, snippet };
                }
                Check::Suspicious(note) => {
                    if first_suspicious.is_none() {
                        first_suspicious = Some(Verdict::Suspicious {
                            cwe,
                            param: param.clone(),
                            note,
                        });
                    }
                }
            }
        }
    }

    first_suspicious.unwrap_or(Verdict::Allow)
}

/// Check a leaf and its base64-decoded view (if any), returning the most severe outcome.
fn check_leaf_views(cwe: Cwe, leaf: &str, resolve: bool) -> Check {
    let raw = check_value(cwe, leaf, resolve);
    if matches!(raw, Check::Block { .. }) {
        return raw;
    }
    if let Some(decoded) = canon::decode_base64_utf8(leaf) {
        if decoded != leaf {
            let d = check_value(cwe, &decoded, resolve);
            match (&raw, &d) {
                (_, Check::Block { .. }) => return d,
                (Check::Clean, Check::Suspicious(_)) => return d,
                _ => {}
            }
        }
    }
    raw
}

fn check_value(cwe: Cwe, value: &str, resolve: bool) -> Check {
    match cwe {
        Cwe::PathTraversal => check_path(value),
        Cwe::CommandInjection => check_command(value),
        Cwe::Ssrf => check_ssrf(value, resolve),
        Cwe::SqlInjection => check_sql(value),
        Cwe::CodeInjection => check_code(value),
    }
}

fn check_path(v: &str) -> Check {
    if v.contains('\0') {
        return Check::Block { reason: "NUL byte in path".into(), snippet: snippet(v) };
    }
    // Canonicalize: fully percent-decode (defeats %252e double-encoding) and unify separators, then
    // test for a `..` path *segment* rather than a bare substring (avoids flagging "foo..bar").
    let decoded = canon::percent_decode_all(v).replace('\\', "/");
    if decoded.split('/').any(|seg| seg == "..") {
        return Check::Block {
            reason: "path traversal sequence '..'".into(),
            snippet: snippet(v),
        };
    }
    // Absolute / home paths are plausibly legitimate (e.g. the MCP filesystem server takes
    // absolute paths inside allowed roots), so they are worth a second look, not a hard block.
    let is_abs = decoded.starts_with('/')
        || decoded.starts_with('~')
        || v.starts_with("\\\\")
        || is_windows_drive(&decoded);
    if is_abs {
        return Check::Suspicious("absolute or home-relative path".into());
    }
    Check::Clean
}

fn is_windows_drive(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

fn check_command(v: &str) -> Check {
    // Quote-aware shell lexing detects chaining/substitution/redirection structurally, so a
    // metacharacter inside a quoted literal isn't a false positive and obfuscated forms still hit.
    match canon::shell_injection(v) {
        Some(reason) => Check::Block { reason: format!("shell {reason}"), snippet: snippet(v) },
        None => Check::Clean,
    }
}

fn check_sql(v: &str) -> Check {
    let lower = v.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "' or ", "\" or ", "or 1=1", "union select", "--", "/*", ";", "' --", "'--", "xp_cmdshell",
    ];
    if let Some(hit) = PATTERNS.iter().find(|p| lower.contains(**p)) {
        return Check::Block {
            reason: format!("SQL injection pattern '{}'", hit),
            snippet: snippet(v),
        };
    }
    Check::Clean
}

fn check_code(v: &str) -> Check {
    let lower = v.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "__import__", "import os", "import subprocess", "os.system", "subprocess",
        "eval(", "exec(", "child_process", "require(", "`", "process.env",
    ];
    if let Some(hit) = PATTERNS.iter().find(|p| lower.contains(**p)) {
        return Check::Block {
            reason: format!("code injection indicator '{}'", hit),
            snippet: snippet(v),
        };
    }
    Check::Clean
}

fn check_ssrf(v: &str, resolve: bool) -> Check {
    // Preferred path: parse with the WHATWG URL parser (the `url` crate) — the same interpretation
    // real HTTP clients use, so an attacker can't slip through a parser-divergence gap. It already
    // folds decimal/hex/octal/short-form IPv4 and IPv4-mapped IPv6 into a canonical `Host`.
    if let Ok(url) = Url::parse(v) {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Check::Block {
                reason: format!("non-http(s) URL scheme '{scheme}:'"),
                snippet: snippet(v),
            };
        }
        return match url.host() {
            Some(Host::Ipv4(ip)) => classify_ipv4(&ip, v),
            Some(Host::Ipv6(ip)) => classify_ipv6(&ip, v),
            Some(Host::Domain(d)) => classify_domain(d, v, resolve),
            None => Check::Suspicious("URL with no host".into()),
        };
    }

    // Fallback: not a well-formed absolute URL (e.g. a bare host, or a scheme-less value). Decode
    // and fold it as a bare host so a raw numeric address still gets classified.
    let decoded = canon::percent_decode_all(v);
    let host = extract_host(&decoded);
    if host.is_empty() {
        return Check::Suspicious("URL parameter without an http(s):// scheme".into());
    }
    let host_lower = host.to_ascii_lowercase();
    match canon::canonical_ip(&host_lower) {
        Some(IpAddr::V4(ip)) => classify_ipv4(&ip, v),
        Some(IpAddr::V6(ip)) => classify_ipv6(&ip, v),
        None if is_blocked_host(&host_lower) => Check::Block {
            reason: format!("request to internal host '{host}'"),
            snippet: snippet(v),
        },
        None if resolve && dns_resolves_internal(&host_lower) => Check::Block {
            reason: format!("host '{host}' resolves to an internal address"),
            snippet: snippet(v),
        },
        None => Check::Suspicious("URL parameter without an http(s):// scheme".into()),
    }
}

/// Resolve `host` and report whether any answer is an internal address. Only used when `--resolve`
/// is set (a blocking DNS lookup, kept off the default fast path), to catch a hostname that points
/// at an internal address. A downstream that re-resolves could still be rebound, so pin the
/// resolved IP downstream for full protection.
fn dns_resolves_internal(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|s| s.ip()).any(|ip| addr_is_internal(&ip)),
        Err(_) => false,
    }
}

/// Pure internal-address classifier over a resolved `IpAddr` (unit-testable without DNS).
fn addr_is_internal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_internal(v4),
        IpAddr::V6(v6) => ipv6_is_internal(v6),
    }
}

fn classify_ipv4(ip: &Ipv4Addr, v: &str) -> Check {
    if ipv4_is_internal(ip) {
        Check::Block { reason: format!("request to internal IPv4 {ip}"), snippet: snippet(v) }
    } else {
        Check::Suspicious(format!("URL targets a bare public IP literal {ip}"))
    }
}

fn classify_ipv6(ip: &Ipv6Addr, v: &str) -> Check {
    if ipv6_is_internal(ip) {
        Check::Block { reason: format!("request to internal IPv6 {ip}"), snippet: snippet(v) }
    } else {
        Check::Suspicious(format!("URL targets a bare public IP literal {ip}"))
    }
}

fn classify_domain(domain: &str, v: &str, resolve: bool) -> Check {
    let lower = domain.to_ascii_lowercase();
    if is_blocked_host(&lower) {
        return Check::Block {
            reason: format!("request to internal host '{domain}'"),
            snippet: snippet(v),
        };
    }
    if resolve && dns_resolves_internal(&lower) {
        return Check::Block {
            reason: format!("host '{domain}' resolves to an internal address"),
            snippet: snippet(v),
        };
    }
    Check::Clean
}

fn is_blocked_host(host_lower: &str) -> bool {
    const BLOCKED_HOSTS: &[&str] =
        &["localhost", "ip6-localhost", "metadata.google.internal", "metadata"];
    BLOCKED_HOSTS.contains(&host_lower) || host_lower.ends_with(".localhost")
}

/// Extract the host from a bare authority (no scheme): strip path/query/fragment, userinfo, and
/// port, and unwrap `[...]` IPv6 brackets. Only used on the non-URL fallback path.
fn extract_host(rest: &str) -> String {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(inner) = hostport.strip_prefix('[') {
        return inner.split(']').next().unwrap_or("").to_string();
    }
    hostport.split(':').next().unwrap_or("").to_string()
}

fn ipv4_is_internal(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()   
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
        // Carrier-grade NAT 100.64.0.0/10 (not covered by std helpers).
        || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
}

fn ipv6_is_internal(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_is_internal(&v4);
    }
    let seg0 = ip.segments()[0];
    // Link-local fe80::/10 and unique-local fc00::/7.
    (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ssrf_profile() -> RiskProfile {
        use crate::risk::profile_tool;
        profile_tool(
            "webpage-to-markdown",
            "Convert a webpage to markdown",
            &json!({ "type": "object", "properties": { "url": { "type": "string" } } }),
        )
    }

    fn cmd_profile() -> RiskProfile {
        use crate::risk::profile_tool;
        profile_tool(
            "run_shell",
            "Execute a shell command",
            &json!({ "type": "object", "properties": { "command": { "type": "string" } } }),
        )
    }

    fn path_profile() -> RiskProfile {
        use crate::risk::profile_tool;
        profile_tool(
            "read_file",
            "Read a file from disk",
            &json!({ "type": "object", "properties": { "path": { "type": "string" } } }),
        )
    }

    #[test]
    fn blocks_paper_ssrf_payloads() {
        let p = ssrf_profile();
        // The paper's malicious input.
        assert!(matches!(
            guard_call(&p, &json!({ "url": "https://127.0.0.1:8080/Admin" })),
            Verdict::Block { cwe: Cwe::Ssrf, .. }
        ));
        // Cloud metadata endpoint.
        assert!(matches!(
            guard_call(&p, &json!({ "url": "https://169.254.169.254/latest/meta-data/" })),
            Verdict::Block { cwe: Cwe::Ssrf, .. }
        ));
        // Private range + non-http scheme.
        assert!(matches!(guard_call(&p, &json!({ "url": "http://192.168.0.1/" })), Verdict::Block { .. }));
        assert!(matches!(guard_call(&p, &json!({ "url": "file:///etc/passwd" })), Verdict::Block { .. }));
        assert!(matches!(guard_call(&p, &json!({ "url": "http://[::1]/" })), Verdict::Block { .. }));
    }

    #[test]
    fn allows_benign_url() {
        let p = ssrf_profile();
        assert_eq!(guard_call(&p, &json!({ "url": "https://news.google.com" })), Verdict::Allow);
    }

    #[test]
    fn public_ip_literal_is_suspicious() {
        let p = ssrf_profile();
        assert!(matches!(
            guard_call(&p, &json!({ "url": "https://8.8.8.8/" })),
            Verdict::Suspicious { cwe: Cwe::Ssrf, .. }
        ));
    }

    #[test]
    fn blocks_command_injection() {
        let p = cmd_profile();
        assert!(matches!(
            guard_call(&p, &json!({ "command": "ls; cat /etc/passwd" })),
            Verdict::Block { cwe: Cwe::CommandInjection, .. }
        ));
        assert!(matches!(guard_call(&p, &json!({ "command": "echo $(whoami)" })), Verdict::Block { .. }));
        assert_eq!(guard_call(&p, &json!({ "command": "ls -la" })), Verdict::Allow);
    }

    #[test]
    fn blocks_path_traversal_but_allows_relative() {
        let p = path_profile();
        assert!(matches!(
            guard_call(&p, &json!({ "path": "../../etc/passwd" })),
            Verdict::Block { cwe: Cwe::PathTraversal, .. }
        ));
        assert_eq!(guard_call(&p, &json!({ "path": "notes/todo.md" })), Verdict::Allow);
        assert!(matches!(
            guard_call(&p, &json!({ "path": "/etc/hosts" })),
            Verdict::Suspicious { cwe: Cwe::PathTraversal, .. }
        ));
    }

    #[test]
    fn guards_string_arrays() {
        let p = cmd_profile();
        use crate::risk::profile_tool;
        let argv = profile_tool(
            "spawn",
            "Spawn a process with args",
            &json!({ "type": "object", "properties": { "args": { "type": "array" } } }),
        );
        assert!(matches!(
            guard_call(&argv, &json!({ "args": ["-c", "rm -rf / && echo done"] })),
            Verdict::Block { cwe: Cwe::CommandInjection, .. }
        ));
        let _ = p;
    }

    #[test]
    fn canonicalization_closes_ssrf_encodings() {
        let p = ssrf_profile();
        for url in [
            "http://2130706433/",          
            "http://0x7f000001/",          
            "http://127.1/",               
            "https://2852039166/latest/",  
            "http://[::ffff:127.0.0.1]/",  
        ] {
            assert!(
                matches!(guard_call(&p, &json!({ "url": url })), Verdict::Block { cwe: Cwe::Ssrf, .. }),
                "expected block for {url}"
            );
        }
    }

    #[test]
    fn canonicalization_closes_path_and_command_bypasses() {
        let path = path_profile();
        assert!(matches!(
            guard_call(&path, &json!({ "path": "%252e%252e%252fetc%252fpasswd" })),
            Verdict::Block { cwe: Cwe::PathTraversal, .. }
        ));

        let cmd = cmd_profile();
        assert_eq!(guard_call(&cmd, &json!({ "command": "echo 'hello; world'" })), Verdict::Allow);
        assert!(matches!(
            guard_call(&cmd, &json!({ "command": "echo \"$(cat /etc/passwd)\"" })),
            Verdict::Block { cwe: Cwe::CommandInjection, .. }
        ));
    }

    /// A payload nested inside an object or an array of objects under a tainted param is still
    /// inspected (closes the "hide it one level down" bypass).
    #[test]
    fn inspects_payload_nested_in_object_or_array() {
        let p = ssrf_profile();
        assert!(matches!(
            guard_call(&p, &json!({ "url": ["ok", { "x": "http://169.254.169.254/" }] })),
            Verdict::Block { cwe: Cwe::Ssrf, .. }
        ));
    }

    /// A base64-wrapped internal URL is decoded and caught.
    #[test]
    fn inspects_base64_wrapped_payload() {
        let p = ssrf_profile();
        let wrapped = b64("http://169.254.169.254/");
        assert!(matches!(
            guard_call(&p, &json!({ "url": wrapped })),
            Verdict::Block { cwe: Cwe::Ssrf, .. }
        ));
    }

    /// The pure DNS-answer classifier used by `--resolve` flags internal addresses only.
    #[test]
    fn addr_classifier_flags_internal() {
        assert!(addr_is_internal(&"127.0.0.1".parse().unwrap()));
        assert!(addr_is_internal(&"169.254.169.254".parse().unwrap()));
        assert!(addr_is_internal(&"::1".parse().unwrap()));
        assert!(!addr_is_internal(&"8.8.8.8".parse().unwrap()));
    }

    /// Minimal correct base64 encoder for constructing test inputs (avoids a dev-dependency).
    fn b64(s: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = s.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut n = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                n |= (c as u32) << (16 - 8 * i);
            }
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
            out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
        }
        out
    }
}
