//! Structured audit trail. Every `tools/call` produces one `AuditEvent`, written as a JSON line to
//! an append-only sink (a file — never stdout, which carries the MCP protocol). This is the
//! observability half of the tool: a log you can tail, ship to a SIEM, or turn into metrics, and
//! it's useful whether or not anything is attacking you.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::risk::Cwe;

/// One decision about one tool call.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    /// Unix epoch milliseconds.
    pub ts_ms: u128,
    /// Namespaced tool name the client called (`alias__tool`).
    pub tool: String,
    pub alias: String,
    pub original: String,
    /// `"allowed"` or `"blocked"`.
    pub decision: &'static str,
    /// Whether a block was actually enforced. `false` in audit mode means "would have blocked".
    pub enforced: bool,
    /// What made the decision: `"policy"`, `"guard"`, `"reflect"`, or `"none"`.
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditEvent {
    pub fn new(tool: &str, alias: &str, original: &str) -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        AuditEvent {
            ts_ms,
            tool: tool.to_string(),
            alias: alias.to_string(),
            original: original.to_string(),
            decision: "allowed",
            enforced: false,
            source: "none",
            cwe: None,
            param: None,
            reason: None,
        }
    }

    pub fn allowed(&mut self, source: &'static str) -> &mut Self {
        self.decision = "allowed";
        self.source = source;
        self
    }

    /// The call was not forwarded and not hard-blocked; the agent was asked to reconsider it.
    pub fn reflected(&mut self, cwe: Option<Cwe>, param: Option<&str>, note: &str) -> &mut Self {
        self.decision = "reflected";
        self.source = "reflect";
        self.enforced = false;
        self.cwe = cwe.map(|c| c.id().to_string());
        self.param = param.map(str::to_string);
        self.reason = Some(note.to_string());
        self
    }

    pub fn blocked(
        &mut self,
        source: &'static str,
        cwe: Option<Cwe>,
        param: Option<&str>,
        reason: &str,
        enforced: bool,
    ) -> &mut Self {
        self.decision = "blocked";
        self.source = source;
        self.enforced = enforced;
        self.cwe = cwe.map(|c| c.id().to_string());
        self.param = param.map(str::to_string);
        self.reason = Some(reason.to_string());
        self
    }
}

/// Append-only JSONL sink for audit events.
pub struct AuditSink {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl AuditSink {
    pub fn to_file(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditSink { writer: Mutex::new(Box::new(file)) })
    }

    pub fn write(&self, event: &AuditEvent) {
        if let Ok(line) = serde_json::to_string(event) {
            if let Ok(mut w) = self.writer.lock() {
                let _ = w.write_all(line.as_bytes());
                let _ = w.write_all(b"\n");
                let _ = w.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_compactly() {
        let mut e = AuditEvent::new("web__fetch", "web", "fetch");
        e.blocked("guard", Some(Cwe::Ssrf), Some("url"), "internal IPv4", true);
        let j: serde_json::Value = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(j["decision"], "blocked");
        assert_eq!(j["source"], "guard");
        assert_eq!(j["cwe"], "CWE-918");
        assert_eq!(j["enforced"], true);
        assert_eq!(j["tool"], "web__fetch");
    }

    #[test]
    fn allowed_event_omits_none_fields() {
        let mut e = AuditEvent::new("web__fetch", "web", "fetch");
        e.allowed("none");
        let s = serde_json::to_string(&e).unwrap();
        assert!(!s.contains("cwe"));
        assert!(!s.contains("reason"));
    }
}
