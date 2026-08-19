//! `simvader install` / `uninstall`: interpose the gateway into MCP client configs.
//!
//! An stdio MCP server's pipes are created by the client at launch, so the only robust place to
//! insert Simvader is the client's launch config. `install` reads a client's `mcpServers` map,
//! migrates every entry into `simvader.json`, backs up the original, and replaces the map with a
//! single `simvader gateway` entry — so every server the client starts now flows through the guard.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::config::{Config, DownstreamServer};

pub struct InstallOptions {
    /// Where the migrated downstream list is written (the gateway's config).
    pub simvader_config: PathBuf,
    /// Target a specific client config; if `None`, scan the known default locations.
    pub client_config: Option<PathBuf>,
    /// Print the planned changes without writing anything.
    pub dry_run: bool,
}

const BACKUP_SUFFIX: &str = ".simvader.bak";
const GATEWAY_ALIAS: &str = "simvader";

/// Candidate MCP client config paths on this platform (currently Claude Desktop).
fn default_client_configs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = claude_desktop_dir() {
        out.push(dir.join("claude_desktop_config.json"));
    }
    out
}

fn claude_desktop_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Claude"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library/Application Support/Claude"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/Claude"))
    }
}

fn targets(client_config: &Option<PathBuf>) -> Vec<PathBuf> {
    match client_config {
        Some(p) => vec![p.clone()],
        None => default_client_configs().into_iter().filter(|p| p.exists()).collect(),
    }
}

fn backup_path(client: &Path) -> PathBuf {
    let mut s = client.as_os_str().to_os_string();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

/// Convert a client `mcpServers` entry into a Simvader downstream.
fn to_downstream(alias: &str, def: &Value) -> DownstreamServer {
    let command = def.get("command").and_then(Value::as_str).unwrap_or_default().to_string();
    let args = def
        .get("args")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let env = def
        .get("env")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    DownstreamServer { alias: alias.to_string(), command, args, env }
}

pub fn install(opts: InstallOptions) -> io::Result<()> {
    let targets = targets(&opts.client_config);
    if targets.is_empty() {
        eprintln!(
            "[simvader] no MCP client config found. Pass --client-config <path>, or point your \
             client at:  simvader gateway --config {}",
            opts.simvader_config.display()
        );
        return Ok(());
    }

    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "simvader".to_string());
    let abs_config = std::fs::canonicalize(&opts.simvader_config)
        .unwrap_or_else(|_| opts.simvader_config.clone());
    let gateway_entry = json!({
        "command": exe,
        "args": ["gateway", "--config", abs_config.display().to_string()],
    });

    let mut sv = Config::load_or_default(&opts.simvader_config)?;
    let mut wrapped_any = false;

    for client in &targets {
        let text = std::fs::read_to_string(client)?;
        let mut root: Value = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", client.display())))?;

        let Some(servers) = root.get("mcpServers").and_then(Value::as_object).cloned() else {
            eprintln!("[simvader] {}: no 'mcpServers' block, skipping", client.display());
            continue;
        };
        if servers.contains_key(GATEWAY_ALIAS) {
            eprintln!("[simvader] {}: already wrapped by simvader, skipping", client.display());
            continue;
        }
        if servers.is_empty() {
            eprintln!("[simvader] {}: no servers to wrap, skipping", client.display());
            continue;
        }

        for (alias, def) in &servers {
            sv.upsert(to_downstream(alias, def));
            eprintln!("[simvader] {}: migrating '{alias}' -> gateway", client.display());
        }

        root["mcpServers"] = json!({ GATEWAY_ALIAS: gateway_entry });

        if opts.dry_run {
            eprintln!("[simvader] (dry-run) would back up {} and rewrite its mcpServers", client.display());
        } else {
            let bak = backup_path(client);
            if !bak.exists() {
                std::fs::copy(client, &bak)?;
            }
            std::fs::write(client, serde_json::to_string_pretty(&root)?)?;
            eprintln!("[simvader] {}: wrapped (backup at {})", client.display(), bak.display());
        }
        wrapped_any = true;
    }

    if wrapped_any && !opts.dry_run {
        sv.save(&opts.simvader_config)?;
        eprintln!(
            "[simvader] wrote {} downstream server(s) to {}. Restart your MCP client to activate.",
            sv.servers.len(),
            opts.simvader_config.display()
        );
    } else if opts.dry_run {
        eprintln!("[simvader] (dry-run) would write {} servers to {}", sv.servers.len(), opts.simvader_config.display());
    }
    Ok(())
}

pub fn uninstall(opts: InstallOptions) -> io::Result<()> {
    let targets = targets(&opts.client_config);
    let mut restored = false;
    for client in &targets {
        let bak = backup_path(client);
        if bak.exists() {
            if opts.dry_run {
                eprintln!("[simvader] (dry-run) would restore {} from {}", client.display(), bak.display());
            } else {
                std::fs::copy(&bak, client)?;
                std::fs::remove_file(&bak)?;
                eprintln!("[simvader] restored {} and removed backup", client.display());
            }
            restored = true;
        }
    }
    if !restored {
        eprintln!("[simvader] no simvader backups found to restore");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_client_servers_and_wraps() {
        let dir = std::env::temp_dir().join(format!("simvader-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let client = dir.join("claude_desktop_config.json");
        let svcfg = dir.join("simvader.json");
        std::fs::write(
            &client,
            r#"{ "mcpServers": {
                "web": { "command": "npx", "args": ["-y", "markdownify-mcp"] },
                "fs":  { "command": "server-fs", "args": ["/data"], "env": { "ROOT": "/data" } }
            }, "other": 1 }"#,
        )
        .unwrap();

        install(InstallOptions {
            simvader_config: svcfg.clone(),
            client_config: Some(client.clone()),
            dry_run: false,
        })
        .unwrap();

        // simvader.json got both downstreams.
        let sv = Config::load(&svcfg).unwrap();
        assert_eq!(sv.servers.len(), 2);
        assert!(sv.servers.iter().any(|s| s.alias == "web" && s.command == "npx"));
        assert!(sv.servers.iter().any(|s| s.alias == "fs" && s.env.get("ROOT").map(String::as_str) == Some("/data")));

        // Client config now has exactly the simvader gateway entry, and unrelated keys survive.
        let root: Value = serde_json::from_str(&std::fs::read_to_string(&client).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers.contains_key(GATEWAY_ALIAS));
        assert_eq!(root["other"], json!(1));
        assert!(backup_path(&client).exists());

        // Uninstall restores the original.
        uninstall(InstallOptions { simvader_config: svcfg, client_config: Some(client.clone()), dry_run: false }).unwrap();
        let restored: Value = serde_json::from_str(&std::fs::read_to_string(&client).unwrap()).unwrap();
        assert_eq!(restored["mcpServers"].as_object().unwrap().len(), 2);
        assert!(!backup_path(&client).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
