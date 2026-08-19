//! The hybrid escalation layer. The deterministic guard (`guard.rs`) handles the fast path; a
//! `Suspicious` verdict — a call that touches a sensitive capability but shows only a weak
//! indicator — is escalated here. The default `NoopReflector` fails open (allow + the gateway's
//! WARN log); the opt-in `LlmReflector` asks a fast Claude model for a strict ALLOW/BLOCK.
//!
//! Only `Suspicious` calls reach a reflector, so the LLM never sits on the fast path.

use serde_json::Value;

use crate::risk::Cwe;

/// A reflector's decision on an escalated (`Suspicious`) call.
#[derive(Debug, Clone, PartialEq)]
pub enum ReflectOutcome {
    Allow,
    Block { reason: String },
}

/// Escalation strategy for `Suspicious` verdicts. `Send + Sync` so a single boxed reflector can be
/// shared across the gateway's threads.
pub trait Reflector: Send + Sync {
    fn reflect(&self, tool: &str, arguments: &Value, cwe: Cwe, param: &str, note: &str) -> ReflectOutcome;
}

/// Default reflector: fail open. Never breaks a workflow — the gateway already logs a WARN for the
/// `Suspicious` verdict, so this just lets the call through. A future `--fail-closed` flag can swap
/// this for a deny-by-default reflector.
pub struct NoopReflector;

impl Reflector for NoopReflector {
    fn reflect(&self, _tool: &str, _arguments: &Value, _cwe: Cwe, _param: &str, _note: &str) -> ReflectOutcome {
        ReflectOutcome::Allow
    }
}

/// Fail-closed reflector: denies every escalated (`Suspicious`) call. Selected by `--fail-closed`
/// when no LLM reflector is configured, so an ambiguous call is refused rather than allowed through.
pub struct DenyReflector;

impl Reflector for DenyReflector {
    fn reflect(&self, _tool: &str, _arguments: &Value, _cwe: Cwe, _param: &str, _note: &str) -> ReflectOutcome {
        ReflectOutcome::Block {
            reason: "fail-closed: ambiguous call denied (no reflector available to clear it)".into(),
        }
    }
}

/// Opt-in reflector that asks a fast Claude model to judge an ambiguous call. Feature-gated so the
/// default build carries no HTTP/TLS stack and stays fully offline.
#[cfg(feature = "llm")]
pub struct LlmReflector {
    api_key: String,
    model: String,
}

#[cfg(feature = "llm")]
impl LlmReflector {
    const ENDPOINT: &'static str = "https://api.anthropic.com/v1/messages";
    const ANTHROPIC_VERSION: &'static str = "2023-06-01";

    /// Build from the environment. Returns `None` if `ANTHROPIC_API_KEY` is unset. The model is a
    /// fast, low-cost tier by default (Haiku) since this is a latency-sensitive yes/no classifier;
    /// override with `SIMVADER_REFLECT_MODEL`.
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.is_empty())?;
        let model = std::env::var("SIMVADER_REFLECT_MODEL")
            .unwrap_or_else(|_| "claude-haiku-4-5".to_string());
        Some(Self { api_key, model })
    }
}

#[cfg(feature = "llm")]
impl Reflector for LlmReflector {
    fn reflect(&self, tool: &str, arguments: &Value, cwe: Cwe, param: &str, note: &str) -> ReflectOutcome {
        use std::time::Duration;

        let system = "You are a security guard sitting in front of MCP tools. You are shown a \
            single tool call that a deterministic filter flagged as ambiguous for a taint-style \
            vulnerability (SSRF, OS command injection, SQL injection, code injection, or path \
            traversal). Decide whether the concrete arguments constitute a likely exploitation \
            attempt of that vulnerability class. Reply with exactly one word: ALLOW or BLOCK.";
        let user = format!(
            "Tool: {tool}\nFlagged parameter: {param}\nRisk class: {cwe}\nWhy flagged: {note}\n\
             Arguments (JSON): {args}\n\nAnswer ALLOW or BLOCK.",
            args = arguments
        );

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 16,
            "system": system,
            "messages": [{ "role": "user", "content": user }],
        });

        let result = ureq::post(Self::ENDPOINT)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", Self::ANTHROPIC_VERSION)
            .set("content-type", "application/json")
            .timeout(Duration::from_secs(10))
            .send_json(body);

        match result {
            Ok(resp) => {
                let v: Value = resp.into_json().unwrap_or(Value::Null);
                let text = v
                    .pointer("/content/0/text")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if text.to_ascii_uppercase().contains("BLOCK") {
                    ReflectOutcome::Block {
                        reason: "LLM reflection judged this call a likely exploit attempt.".into(),
                    }
                } else {
                    // ALLOW, empty, or unparseable → fail open.
                    ReflectOutcome::Allow
                }
            }
            Err(e) => {
                eprintln!("[simvader] LLM reflection request failed ({e}); failing open");
                ReflectOutcome::Allow
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn noop_reflector_allows() {
        let r = NoopReflector;
        assert_eq!(
            r.reflect("web__fetch", &json!({"url": "https://8.8.8.8/"}), Cwe::Ssrf, "url", "public IP"),
            ReflectOutcome::Allow
        );
    }

    #[test]
    fn deny_reflector_blocks() {
        let r = DenyReflector;
        assert!(matches!(
            r.reflect("web__fetch", &json!({"url": "https://8.8.8.8/"}), Cwe::Ssrf, "url", "public IP"),
            ReflectOutcome::Block { .. }
        ));
    }
}
