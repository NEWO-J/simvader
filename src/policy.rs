//! Per-tool allow/deny policy — the enforcement layer you graduate into after watching the audit
//! log. Rules match against a *canonical token* per parameter (a URL's host, a command's binary, a
//! path's root) rather than the raw string, so `https://api.github.com/x` and
//! `https://api.github.com/y` are both governed by the rule `api.github.com`.
//!
//! An allowlist is default-deny: if a parameter has an `allow` list and the call's token isn't on
//! it, the call is denied. A tool with no rules yields `NoOpinion`, deferring to the heuristic
//! guard. The `Learner` watches traffic and proposes an allowlist so you don't write it by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::guard::string_leaves;
use crate::risk::{Cwe, RiskProfile};

/// Allow/deny lists for one tool's parameters. Matchers are simple globs (`*`), matched against the
/// canonical token; for URL parameters a bare domain also matches its subdomains.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolRules {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allow: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deny: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Policy {
    /// Keyed by namespaced tool name (`alias__tool`), as the client sees it.
    #[serde(default)]
    pub rules: BTreeMap<String, ToolRules>,
}

#[derive(Debug, PartialEq)]
pub enum PolicyDecision {
    /// The call violates policy.
    Deny { param: String, reason: String },
    /// The call matched an allow rule — pass it, bypassing the heuristic guard.
    Allow,
    /// No rule governs this call; defer to the guard.
    NoOpinion,
}

impl Policy {
    pub fn load(path: &Path) -> io::Result<Policy> {
        let text = fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)?)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate a call against this tool's rules.
    pub fn evaluate(&self, tool: &str, profile: &RiskProfile, args: &Value) -> PolicyDecision {
        let Some(rules) = self.rules.get(tool) else {
            return PolicyDecision::NoOpinion;
        };

        // Deny lists win outright.
        for (param, patterns) in &rules.deny {
            for tok in tokens(profile, param, args) {
                if patterns.iter().any(|p| matches(profile, param, p, &tok)) {
                    return PolicyDecision::Deny {
                        param: param.clone(),
                        reason: format!("value '{tok}' is on the deny list"),
                    };
                }
            }
        }

        // Allowlists are default-deny for the parameters they cover.
        let mut allow_hit = false;
        for (param, patterns) in &rules.allow {
            let toks = tokens(profile, param, args);
            if toks.is_empty() {
                continue; // parameter absent in this call — doesn't constrain it
            }
            if toks.iter().all(|t| patterns.iter().any(|p| matches(profile, param, p, t))) {
                allow_hit = true;
            } else {
                return PolicyDecision::Deny {
                    param: param.clone(),
                    reason: "value is not on the allowlist".to_string(),
                };
            }
        }

        if allow_hit {
            PolicyDecision::Allow
        } else {
            PolicyDecision::NoOpinion
        }
    }
}

/// The canonical tokens for a parameter's argument value(s).
fn tokens(profile: &RiskProfile, param: &str, args: &Value) -> Vec<String> {
    let cwe = profile.param_cwe.get(param).copied();
    match args.get(param) {
        Some(v) => string_leaves(v).into_iter().map(|s| canonical_token(cwe, s)).collect(),
        None => Vec::new(),
    }
}

/// Reduce a raw argument value to the token a policy rule matches against.
pub fn canonical_token(cwe: Option<Cwe>, value: &str) -> String {
    match cwe {
        Some(Cwe::Ssrf) => url::Url::parse(value)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| value.trim().to_string())
            .to_ascii_lowercase(),
        Some(Cwe::CommandInjection) => value
            .split_whitespace()
            .next()
            .unwrap_or("")
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .to_string(),
        Some(Cwe::PathTraversal) => {
            let decoded = crate::canon::percent_decode_all(value).replace('\\', "/");
            if let Some(seg) = decoded.split('/').find(|s| !s.is_empty()) {
                if decoded.starts_with('/') { format!("/{seg}") } else { seg.to_string() }
            } else {
                "/".to_string()
            }
        }
        _ => value.chars().take(64).collect(),
    }
}

/// Match a pattern against a token: case-insensitive glob (`*`), plus domain-suffix matching for
/// URL hosts (`github.com` matches `api.github.com`).
fn matches(profile: &RiskProfile, param: &str, pattern: &str, token: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let t = token.to_ascii_lowercase();
    if glob_match(&p, &t) {
        return true;
    }
    if profile.param_cwe.get(param) == Some(&Cwe::Ssrf) {
        // Bare domain also covers its subdomains.
        return t == p || t.ends_with(&format!(".{p}"));
    }
    false
}

/// Minimal glob: `*` matches any (possibly empty) run of characters. No other metacharacters.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Classic two-pointer wildcard match with backtracking.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Observes real traffic and proposes an allowlist from the tokens it sees — the low-friction way
/// to author a policy: run in `--learn` for a while, then enforce the proposal.
#[derive(Default)]
pub struct Learner {
    /// tool -> param -> observed tokens
    seen: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
}

impl Learner {
    pub fn observe(&mut self, tool: &str, profile: &RiskProfile, args: &Value) {
        for param in &profile.tainted_params {
            for tok in tokens(profile, param, args) {
                if tok.is_empty() {
                    continue;
                }
                self.seen
                    .entry(tool.to_string())
                    .or_default()
                    .entry(param.clone())
                    .or_default()
                    .insert(tok);
            }
        }
    }

    pub fn propose(&self) -> Policy {
        let mut rules = BTreeMap::new();
        for (tool, params) in &self.seen {
            let allow: BTreeMap<String, Vec<String>> = params
                .iter()
                .map(|(param, toks)| (param.clone(), toks.iter().cloned().collect()))
                .collect();
            rules.insert(tool.clone(), ToolRules { allow, deny: BTreeMap::new() });
        }
        Policy { rules }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::profile_tool;
    use serde_json::json;

    fn fetch() -> RiskProfile {
        profile_tool("fetch", "Fetch a URL", &json!({ "type": "object", "properties": { "url": { "type": "string" } } }))
    }

    fn policy(json_str: &str) -> Policy {
        serde_json::from_str(json_str).unwrap()
    }

    #[test]
    fn allowlist_is_default_deny_with_subdomain_match() {
        let p = policy(r#"{ "rules": { "web__fetch": { "allow": { "url": ["github.com", "*.google.com"] } } } }"#);
        let prof = fetch();
        // On the allowlist (subdomain of github.com).
        assert_eq!(
            p.evaluate("web__fetch", &prof, &json!({ "url": "https://api.github.com/x" })),
            PolicyDecision::Allow
        );
        // Glob subdomain of google.com.
        assert_eq!(
            p.evaluate("web__fetch", &prof, &json!({ "url": "https://mail.google.com/" })),
            PolicyDecision::Allow
        );
        // Not on the allowlist -> denied even though the URL is benign.
        assert!(matches!(
            p.evaluate("web__fetch", &prof, &json!({ "url": "https://evil.example.com/" })),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn no_rules_is_no_opinion() {
        let p = Policy::default();
        assert_eq!(
            p.evaluate("web__fetch", &fetch(), &json!({ "url": "https://x.com/" })),
            PolicyDecision::NoOpinion
        );
    }

    #[test]
    fn learner_proposes_observed_hosts() {
        let prof = fetch();
        let mut l = Learner::default();
        l.observe("web__fetch", &prof, &json!({ "url": "https://api.github.com/a" }));
        l.observe("web__fetch", &prof, &json!({ "url": "https://news.google.com/b" }));
        l.observe("web__fetch", &prof, &json!({ "url": "https://api.github.com/c" }));
        let proposed = l.propose();
        let allow = &proposed.rules["web__fetch"].allow["url"];
        assert_eq!(allow, &vec!["api.github.com".to_string(), "news.google.com".to_string()]);
        // The proposed allowlist, enforced, admits a seen host and denies a new one.
        assert_eq!(
            proposed.evaluate("web__fetch", &prof, &json!({ "url": "https://api.github.com/z" })),
            PolicyDecision::Allow
        );
        assert!(matches!(
            proposed.evaluate("web__fetch", &prof, &json!({ "url": "https://other.com/" })),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn command_binary_tokenization() {
        assert_eq!(canonical_token(Some(Cwe::CommandInjection), "/usr/bin/git status"), "git");
        assert_eq!(canonical_token(Some(Cwe::PathTraversal), "/var/log/app.log"), "/var");
        assert_eq!(canonical_token(Some(Cwe::Ssrf), "https://API.GitHub.com/x"), "api.github.com");
    }
}
