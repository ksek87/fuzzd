use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// A single MCP server entry from a Claude Desktop or Cline config file.
#[derive(Debug, Deserialize)]
pub struct McpServerConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment variables to pass to the spawned process.
    /// Values may contain secrets — never log them.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl McpServerConfig {
    /// Full command string for re-spawn (used by protocol/chain fuzzers).
    /// Does a simple join; suitable when args do not contain spaces.
    pub fn spawn_cmd(&self) -> String {
        if self.args.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.args.join(" "))
        }
    }
}

/// Top-level Claude Desktop / Cline config structure.
#[derive(Debug, Deserialize)]
pub struct DesktopConfig {
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: HashMap<String, McpServerConfig>,
}

/// Parse a config file from a string. Returns an error on invalid JSON or
/// unexpected structure; missing optional fields default to empty.
pub fn parse_config(src: &str) -> Result<DesktopConfig> {
    serde_json::from_str(src).context("failed to parse MCP config")
}

/// Load and parse a config file from disk.
pub fn load_config(path: &Path) -> Result<DesktopConfig> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    parse_config(&src)
}

/// Platform-specific paths to search when `--from-config auto` is used.
fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        // macOS
        paths.push(home.join("Library/Application Support/Claude/claude_desktop_config.json"));
        // Linux
        paths.push(home.join(".config/claude/claude_desktop_config.json"));
        // Cline (VS Code extension)
        paths.push(home.join(
            ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ));
    }
    // Windows
    if let Ok(appdata) = std::env::var("APPDATA") {
        paths.push(PathBuf::from(appdata).join("Claude/claude_desktop_config.json"));
    }
    paths
}

/// Search standard platform paths and return the first config found.
/// Returns `None` when no config file exists at any known location.
pub fn auto_detect() -> Option<(PathBuf, DesktopConfig)> {
    for path in default_config_paths() {
        if path.exists() {
            if let Ok(cfg) = load_config(&path) {
                return Some((path, cfg));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {}
            },
            "github": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-github"],
                "env": { "GITHUB_TOKEN": "ghp_secret" }
            }
        }
    }"#;

    #[test]
    fn parse_config_extracts_servers() {
        let cfg = parse_config(FIXTURE).unwrap();
        assert_eq!(cfg.mcp_servers.len(), 2);
        let fs = cfg.mcp_servers.get("filesystem").unwrap();
        assert_eq!(fs.command, "npx");
        assert_eq!(
            fs.args,
            ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        );
        let gh = cfg.mcp_servers.get("github").unwrap();
        assert_eq!(
            gh.env.get("GITHUB_TOKEN").map(String::as_str),
            Some("ghp_secret")
        );
    }

    #[test]
    fn parse_config_empty_mcp_servers() {
        let cfg = parse_config(r#"{"mcpServers": {}}"#).unwrap();
        assert!(cfg.mcp_servers.is_empty());
    }

    #[test]
    fn parse_config_missing_mcp_servers_defaults_to_empty() {
        let cfg = parse_config(r#"{}"#).unwrap();
        assert!(cfg.mcp_servers.is_empty());
    }

    #[test]
    fn parse_config_rejects_invalid_json() {
        assert!(parse_config("not json").is_err());
    }

    #[test]
    fn parse_config_defaults_missing_args_and_env() {
        let cfg = parse_config(r#"{"mcpServers": {"s": {"command": "node"}}}"#).unwrap();
        let s = cfg.mcp_servers.get("s").unwrap();
        assert!(s.args.is_empty());
        assert!(s.env.is_empty());
    }

    #[test]
    fn spawn_cmd_with_args() {
        let s = McpServerConfig {
            command: "npx".to_string(),
            args: vec!["-y".to_string(), "server".to_string()],
            env: HashMap::new(),
        };
        assert_eq!(s.spawn_cmd(), "npx -y server");
    }

    #[test]
    fn spawn_cmd_no_args() {
        let s = McpServerConfig {
            command: "node".to_string(),
            args: vec![],
            env: HashMap::new(),
        };
        assert_eq!(s.spawn_cmd(), "node");
    }
}
