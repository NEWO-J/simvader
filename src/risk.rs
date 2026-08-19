//! Infer a coarse taint-style risk profile for an MCP tool
//! from its metadata (name, description, input schema). No I/O, no LLM — pure heuristics.

use std::collections::HashMap;
use std::fmt;

use serde_json::Value;

/// A sensitive capability a tool may expose. Used to explain *why* a parameter is risky
/// and to drive the "clean argument but risky tool" -> `Suspicious` decision in the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Filesystem,
    CommandExec,
    CodeExec,
    Network,
    Database,
    Parsing,
    Credential,
    AuthControl,
}

impl Capability {
    pub fn label(self) -> &'static str {
        match self {
            Capability::Filesystem => "filesystem access",
            Capability::CommandExec => "command execution",
            Capability::CodeExec => "code execution",
            Capability::Network => "network access",
            Capability::Database => "database access",
            Capability::Parsing => "content parsing",
            Capability::Credential => "credential access",
            Capability::AuthControl => "authorization control",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The taint-style vulnerability classes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cwe {
    CommandInjection,
    PathTraversal,
    Ssrf,
    SqlInjection,
    CodeInjection,
}

impl Cwe {
    pub fn id(self) -> &'static str {
        match self {
            Cwe::CommandInjection => "CWE-78",
            Cwe::PathTraversal => "CWE-22",
            Cwe::Ssrf => "CWE-918",
            Cwe::SqlInjection => "CWE-89",
            Cwe::CodeInjection => "CWE-94",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Cwe::CommandInjection => "OS Command Injection",
            Cwe::PathTraversal => "Path Traversal",
            Cwe::Ssrf => "Server-Side Request Forgery",
            Cwe::SqlInjection => "SQL Injection",
            Cwe::CodeInjection => "Code Injection",
        }
    }
}

impl fmt::Display for Cwe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.id())
    }
}

/// The coarse-grained risk profile for a single tool: `R = <C, P, W>`.
#[derive(Debug, Clone, PartialEq)]
pub struct RiskProfile {
    pub tool: String,
    pub capabilities: Vec<Capability>,
    pub tainted_params: Vec<String>,
    pub param_cwe: HashMap<String, Cwe>,
    pub cwes: Vec<Cwe>,
}

impl RiskProfile {
    /// A tool with no capabilities and no tainted parameters carries no taint-style risk.
    pub fn is_risky(&self) -> bool {
        !self.capabilities.is_empty() || !self.tainted_params.is_empty()
    }
}

/// Capability keywords matched against the lowercased tool name + description.
// Add more keywords perhaps? how will this affect runtime
const CAPABILITY_KEYWORDS: &[(Capability, &[&str])] = &[
    (Capability::CommandExec, &["exec", "shell", "command", "terminal", "spawn", "subprocess", "run "]),
    (Capability::Filesystem, &["file", "path", "directory", "folder", "read", "write", "delete", "dir"]),
    (Capability::Network, &["url", "http", "fetch", "request", "download", "webpage", "website", "crawl"]),
    (Capability::Database, &["sql", "query", "database", "sqlite", "postgres", "mysql"]),
    (Capability::CodeExec, &["eval", "code", "script", "render", "template", "execute", "interpret"]),
    (Capability::Parsing, &["parse", "markdown", "convert", "transform", "extract"]),
    (Capability::Credential, &["credential", "token", "secret", "password", "apikey", "api key"]),
    (Capability::AuthControl, &["permission", "role", "authorize", "grant", "access control"]),
];

/// Ordered param-name classifiers. First match wins, so more specific/dangerous classes
/// are listed before ambiguous ones (e.g. a `url` parameter is SSRF even though "l" also
/// appears in many words). 
// Do keywords neeed to be normalized as well?
const PARAM_CLASSIFIERS: &[(Cwe, &[&str])] = &[
    (Cwe::Ssrf, &["url", "uri", "endpoint", "host", "webhook", "href", "link", "address"]),
    (Cwe::SqlInjection, &["query", "sql", "statement", "where"]),
    (Cwe::CommandInjection, &["command", "cmd", "shell", "exec", "argv", "args", "flags"]),
    (Cwe::CodeInjection, &["code", "eval", "expr", "expression", "template", "script", "snippet"]),
    (Cwe::PathTraversal, &["path", "file", "filename", "filepath", "dir", "directory", "folder"]),
];

/// Classify a single parameter name to the taint class it can trigger, if any.
pub fn classify_param(name: &str) -> Option<Cwe> {
    let lower = name.to_ascii_lowercase();
    for (cwe, needles) in PARAM_CLASSIFIERS {
        if needles.iter().any(|n| lower.contains(n)) {
            return Some(*cwe);
        }
    }
    None
}

fn detect_capabilities(name: &str, description: &str) -> Vec<Capability> {
    let hay = format!("{} {}", name, description).to_ascii_lowercase();
    let mut caps = Vec::new();
    for (cap, needles) in CAPABILITY_KEYWORDS {
        if needles.iter().any(|n| hay.contains(n)) {
            caps.push(*cap);
        }
    }
    caps
}

/// Extract the declared parameter names from a JSON Schema `inputSchema` object.
fn schema_param_names(input_schema: &Value) -> Vec<String> {
    input_schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}

/// Build the risk profile for one tool (Stage 1).
pub fn profile_tool(name: &str, description: &str, input_schema: &Value) -> RiskProfile {
    let capabilities = detect_capabilities(name, description);

    let mut param_cwe = HashMap::new();
    let mut tainted_params = Vec::new();
    for param in schema_param_names(input_schema) {
        if let Some(cwe) = classify_param(&param) {
            tainted_params.push(param.clone());
            param_cwe.insert(param, cwe);
        }
    }
    tainted_params.sort();

    // Deduplicate CWEs while preserving a stable, deterministic order.
    let mut cwes: Vec<Cwe> = Vec::new();
    for cwe in param_cwe.values() {
        if !cwes.contains(cwe) {
            cwes.push(*cwe);
        }
    }
    cwes.sort_by_key(|c| c.id());

    RiskProfile {
        tool: name.to_string(),
        capabilities,
        tainted_params,
        param_cwe,
        cwes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Markdownify `webpage-to-markdown` tool (CVE-2025-5276).
    #[test]
    fn profiles_paper_webpage_to_markdown() {
        let schema = json!({
            "type": "object",
            "properties": { "url": { "type": "string", "description": "URL of the webpage to convert" } },
            "required": ["url"]
        });
        let p = profile_tool("webpage-to-markdown", "Convert a webpage to markdown", &schema);

        assert!(p.capabilities.contains(&Capability::Network));
        assert_eq!(p.tainted_params, vec!["url".to_string()]);
        assert_eq!(p.param_cwe.get("url"), Some(&Cwe::Ssrf));
        assert_eq!(p.cwes, vec![Cwe::Ssrf]);
        assert!(p.is_risky());
    }

    #[test]
    fn classifies_common_param_names() {
        assert_eq!(classify_param("url"), Some(Cwe::Ssrf));
        assert_eq!(classify_param("targetUrl"), Some(Cwe::Ssrf));
        assert_eq!(classify_param("command"), Some(Cwe::CommandInjection));
        assert_eq!(classify_param("sqlQuery"), Some(Cwe::SqlInjection));
        assert_eq!(classify_param("filePath"), Some(Cwe::PathTraversal));
        assert_eq!(classify_param("count"), None);
    }

    #[test]
    fn command_tool_gets_command_injection() {
        let schema = json!({
            "type": "object",
            "properties": { "command": { "type": "string" }, "timeout": { "type": "number" } }
        });
        let p = profile_tool("run_shell", "Execute a shell command on the host", &schema);
        assert!(p.capabilities.contains(&Capability::CommandExec));
        assert_eq!(p.param_cwe.get("command"), Some(&Cwe::CommandInjection));
        assert!(!p.tainted_params.contains(&"timeout".to_string()));
    }

    #[test]
    fn benign_tool_is_not_risky() {
        let schema = json!({ "type": "object", "properties": { "count": { "type": "number" } } });
        let p = profile_tool("dice_roll", "Roll a number of dice and return the sum", &schema);
        assert!(p.tainted_params.is_empty());
        assert!(!p.is_risky());
    }
}
