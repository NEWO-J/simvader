<p align="center">
  <img src="simvader.png" width="700" alt="Simvader logo">
</p>
<p align="center">
    <a href="https://crates.io/crates/simvader"><img alt="crates.io" src="https://img.shields.io/crates/v/simvader"/></a>
    <img alt="Rust" src="https://img.shields.io/badge/rust-1.75%2B-orange?logo=rust"/>
    <img alt="License" src="https://img.shields.io/badge/license-MIT-green"/>
    <img alt="MCP" src="https://img.shields.io/badge/MCP-gateway-blue"/>
  </p>

<p align="center">
Simvader lets you run untrusted MCP servers safely.
</p>
Most MCP servers are built with security as an afterthought. [Only 7% of their tool descriptions include explicit security guidance](https://arxiv.org/abs/2607.07461). simvader is a gateway that sits between
your agent and its [MCP](https://modelcontextprotocol.io/) tools. It blocks prompt-injection attacks
(SSRF, command injection, SQL injection, path traversal, code injection) before they reach a server,
logs every tool call, and enforces an allow/deny policy. It needs no changes to the servers it
protects.

![simvader blocking an MCP attack](demo.gif)

## Features
- **Blocks taint-style attacks in real time** in the call path: SSRF, command injection, SQL injection, path
  traversal, and code injection. It normalizes each argument first, so encoded bypasses fold to one
  rule. `http://2852039166/` and `http://0xA9FEA9FE/` resolve to the same blocked address as
  `http://169.254.169.254/`.
- **Hands ambiguous calls back to your agent.** When a call looks risky but is not clearly an attack,
  simvader does not guess. It returns the call to the agent as a tool result and asks it to reconsider,
  now with the risk spelled out. The agent decides again with full context. If it re-issues the same
  call, simvader lets it through and logs it, or blocks it in strict mode. No extra API key, and no
  LLM on the fast path.
- **Adds security notes to every tool.** Most MCP tools ship no security guidance at all. simvader
  rewrites the description the model reads, spelling out each tool's risky inputs and what to refuse,
  so the model steers away from the unsafe call before the guard runs.
- **Writes your policy for you.** Run it in front of your agents and it learns an allow list from real
  traffic. Turn on enforcement and anything off the list is denied.
- **One command to protect a client.** `simvader install` wraps every MCP server in your Claude Desktop
  config and backs up the original.
- **Full audit log.** One JSON line per tool call: tool, decision, reason, CWE. Pipe it to a SIEM.
- **stdio or HTTP.** Run it as a local subprocess or a network service.
- **Too fast to notice.** The simvader layer is built in rust, and only adds about 0.3 µs per call (p99 ~1.2 µs), so it disappears next to an MCP round
  trip.

## Quickstart

Requires Rust.

```sh
git clone <repo> && cd simvader
cargo build --release
```

Put simvader in front of one server:

```sh
simvader run -- npx -y @zcaceres/markdownify-mcp
```

Or protect every server already in your Claude Desktop config at once:

```sh
simvader install
```

## See it block an attack

The repo ships a deliberately unsafe mock server.

```sh
cargo build --release --example mock_mcp_server
{ cat scripts/replay.jsonl; sleep 1; } | \
  target/release/simvader run --verbose -- target/release/examples/mock_mcp_server
```

The safe calls pass. The SSRF and the command injection are blocked before the server sees them:

```
id 3  FETCHED: https://news.google.com                            (allowed)
id 4  Simvader blocked this call: potential Server-Side Request
      Forgery (CWE-918) via parameter 'url' (internal IPv4 169.254.169.254)   (blocked)
id 5  Simvader blocked this call: potential OS Command Injection
      (CWE-78) via parameter 'command' (shell separator ';')                  (blocked)
id 6  RAN: ls -la                                                 (allowed)
```

A blocked call returns a normal tool error, so the model can report the refusal instead of failing.

## Why it exists

The MCP ecosystem is full of servers built fast and shared early, often as prototypes with input
validation as an afterthought. You want to use them now, and you cannot audit or patch code you did
not write.

A study of disclosed MCP server bugs [arXiv:2607.07461](https://arxiv.org/abs/2607.07461))
found:

- 81% are taint-style: untrusted input reaches a risky action.
- 75% fire at the tool call, when the model fills in the arguments.
- Fixes take 37 days on average, and unpatched bugs stay open 92 days.

simvader blocks the exploit in the call path, so an untrusted or unpatched server is contained the
moment you add it. It is virtual patching for taint-based MCP exploits.

## Configure many servers

List your servers in `simvader.json`:

```json
{
  "servers": [
    { "alias": "web", "command": "npx", "args": ["-y", "@zcaceres/markdownify-mcp"] },
    { "alias": "fs",  "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"] }
  ]
}
```

```sh
simvader gateway --config simvader.json
```

Tool names get an alias prefix (`alias__tool`), so two servers can both export a `search` tool.

## Run as an HTTP service

For server deployments, clients connect to a URL instead of spawning a subprocess:

```sh
simvader gateway --config simvader.json --http 127.0.0.1:8080
```

Clients POST MCP JSON-RPC to `/mcp` and get JSON back. Same guard, log, and routing as stdio.

```sh
curl -s -H content-type:application/json http://127.0.0.1:8080/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"web__fetch","arguments":{"url":"http://169.254.169.254/"}}}'
# {"id":1,...,"result":{"isError":true,"content":[{"type":"text",
#   "text":"Simvader blocked this call: potential Server-Side Request Forgery (CWE-918) ..."}]}}
```

## Observe, learn, enforce

The gateway defaults to logging, not blocking, so you can add it to a live setup without breaking a
workflow.

1. Watch. Log every call, block nothing:

```sh
simvader gateway --config simvader.json --audit --audit-log simvader-audit.jsonl
```

2. Learn. Build an allow list from the traffic it saw:

```sh
simvader gateway --config simvader.json --learn
# writes simvader-policy.proposed.json on exit
```

```json
{ "rules": { "web__fetch": { "allow": { "url": ["api.github.com", "news.google.com"] } } } }
```

3. Enforce. Review it, rename it to `policy.json`, turn it on:

```sh
simvader gateway --config simvader.json --policy policy.json
```

A listed call passes. Everything else is denied. Rules match a normalized token (the URL host, the
command's program, the path root), so one rule like `api.github.com` covers every path under it, and a
bare domain covers its subdomains. Tools with no rule fall back to the guard.

An allow list is the strongest layer. The heuristic guard can be bypassed. An allow list cannot,
because a call has to be on it.

## What it catches

| Class | CWE | Examples |
|---|---|---|
| SSRF | CWE-918 | internal IPs (loopback, private, link-local), numeric forms (decimal, hex, octal, short, IPv4-in-IPv6), `localhost`, non-`http(s)` schemes |
| Command injection | CWE-78 | shell chaining, subshells, redirects, found by a quote-aware lexer (a `;` inside quotes is not flagged) |
| Path traversal | CWE-22 | `..` segments after a full decode (catches `%252e%252e` double-encoding), NUL bytes (absolute paths are flagged, not blocked) |
| SQL injection | CWE-89 | `' OR `, `UNION SELECT`, `--`, `;`, `/*` |
| Code injection | CWE-94 | `eval(`, `exec(`, `__import__`, `subprocess`, `require(`, backticks |

## Audit log

One JSON line per call:

```json
{"ts_ms":1783611090837,"tool":"web__fetch","alias":"web","original":"fetch","decision":"blocked","enforced":true,"source":"guard","cwe":"CWE-918","param":"url","reason":"request to internal IPv4 169.254.169.254"}
```

`source` is `policy`, `guard`, `reflect`, or `none`. On a `blocked` line, `enforced:false` means it
would have been blocked in enforce mode.

## Performance

The guard is the only work added per call. Release build, measured on Linux:

| metric | value |
|---|---|
| throughput | ~2.8M calls/s |
| mean | ~0.33 µs |
| p50 | ~0.28 µs |
| p99 | ~1.2 µs |
| p99.9 | ~3 µs |

The optional LLM check runs only on `suspicious` calls and is off by default.

## Flags

- `--audit` log calls but let them all through. Turn on blocking when you trust it.
- `--audit-log <path>` write one JSON line per call to a file.
- `--policy <path>` load an allow/deny list. An allow list is deny-by-default.
- `--learn` watch traffic and write a suggested allow list on exit (turns on `--audit`).
- `--reflect` on a `suspicious` call, hand it back to the agent to reconsider (return a reflection
  tool result) instead of guessing. Allow an identical re-issue and log it. No API key needed.
- `--reflect-strict` like `--reflect`, but block an identical re-issue instead of allowing it.
- `--reflect-llm` send `suspicious` calls to a fast Claude model for a yes/no. Needs `ANTHROPIC_API_KEY`
  and a build with `--features llm`. Set the model with `SIMVADER_REFLECT_MODEL`.
- `--no-augment` do not rewrite tool descriptions.
- `-v`, `--verbose` print each verdict to stderr.

## Internals

- One process is an MCP server to the client and an MCP client to each downstream.
- Blocking threads, no async runtime. Dependencies: `serde`, `clap`, `url`, `tiny_http`. `ureq` only
  under the `llm` feature.
- stdio and HTTP share one function for the per-call decision, so the two transports cannot diverge.
- The URL check uses the `url` crate, the WHATWG parser Firefox and Deno use, so the guard reads a host
  the same way the target HTTP client will.
- A downstream that fails to start is logged and skipped, not fatal.

## Limitations

- Virtual patching shields the path. It does not fix the bug. The vulnerable code is still in the
  server, and a server reached outside the gateway is not covered.
- It covers the taint class (81% of the bugs), not access-control bugs or DNS rebinding.
- The guard is a heuristic. Normalization closes the encoding tricks, but DNS rebinding and
  open-redirect SSRF need a DNS lookup on the fetch path, deferred to a `--resolve` flag.
- The HTTP transport returns JSON only. It does not stream server-sent events yet (notifications,
  sampling). Downstreams are stdio child processes; remote HTTP downstreams are not wired yet.

## Background

Based on "Mitigating Taint-Style Vulnerabilities in MCP Servers via Security-Aware Tool Descriptions",
[arXiv:2607.07461](https://arxiv.org/abs/2607.07461). The paper's defense uses an LLM for
the per-call check. simvader keeps the structure and makes the hot path deterministic, with the LLM as
an optional escalation.

## Development

```sh
cargo test                       # 33 tests: engine, normalization, policy, audit, gateway, install
cargo run --release --example bench_guard
cargo build --features llm
```

