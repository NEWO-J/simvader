//! Simvader configuration: the list of downstream MCP servers the gateway fronts, loaded from
//! `simvader.json`. Reuses serde_json (no extra dependency).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One downstream MCP server the gateway spawns and proxies.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DownstreamServer {
    /// Short, client-safe namespace prefix (e.g. `web`, `fs`). Must not contain `__`.
    pub alias: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub servers: Vec<DownstreamServer>,
}

impl Config {
    pub fn load(path: &Path) -> io::Result<Config> {
        let text = fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))
    }

    /// Load if the file exists, else start from an empty config (used by `install`).
    pub fn load_or_default(path: &Path) -> io::Result<Config> {
        if path.exists() {
            Config::load(path)
        } else {
            Ok(Config::default())
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        fs::write(path, text)
    }

    /// Add a downstream, replacing any existing entry with the same alias.
    pub fn upsert(&mut self, server: DownstreamServer) {
        if let Some(existing) = self.servers.iter_mut().find(|s| s.alias == server.alias) {
            *existing = server;
        } else {
            self.servers.push(server);
        }
    }
}

/// Derive a safe alias for the ad-hoc `simvader run -- <command> …` case from the command's
/// basename (stripping any directory, extension, and `__` so namespacing stays unambiguous).
pub fn alias_from_command(command: &str) -> String {
    let base = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command);
    let stem = base.split('.').next().unwrap_or(base);
    let cleaned: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
        .collect();
    let cleaned = cleaned.replace("__", "_");
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "server".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config() {
        let json = r#"{ "servers": [
            { "alias": "web", "command": "npx", "args": ["-y", "markdownify-mcp"] },
            { "alias": "fs", "command": "server-filesystem", "args": ["/data"] }
        ]}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[0].alias, "web");
        assert_eq!(cfg.servers[1].args, vec!["/data".to_string()]);
    }

    #[test]
    fn derives_alias() {
        assert_eq!(alias_from_command("npx"), "npx");
        assert_eq!(alias_from_command("/usr/bin/uvx"), "uvx");
        assert_eq!(alias_from_command("C:\\tools\\server.exe"), "server");
        assert_eq!(alias_from_command("my.mcp.server"), "my");
    }
}
