use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::fuzzer::Finding;

#[derive(Debug, Deserialize, Serialize)]
pub struct SuppressEntry {
    pub tool: String,
    pub signal: String,
    pub reason: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SuppressFile {
    #[serde(default)]
    suppress: Vec<SuppressEntry>,
}

pub struct SuppressConfig {
    entries: Vec<SuppressEntry>,
}

impl SuppressConfig {
    /// Load suppressions from `path`. Returns an empty config if the file does not exist.
    pub fn load_or_empty(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                entries: Vec::new(),
            });
        }
        let content = std::fs::read_to_string(path)?;
        let file: SuppressFile = toml::from_str(&content)?;
        Ok(Self {
            entries: file.suppress,
        })
    }

    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        let signal_str = finding.signal.to_string();
        self.entries
            .iter()
            .any(|e| e.tool == finding.tool_name && e.signal == signal_str)
    }

    /// Append a new suppress entry to `path`, creating the file (and parent dirs) as needed.
    /// Returns an error if an entry for `tool`/`signal` already exists.
    pub fn append(path: &Path, tool: &str, signal: &str, reason: &str) -> Result<()> {
        let mut file = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str::<SuppressFile>(&content)?
        } else {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            SuppressFile::default()
        };

        if file
            .suppress
            .iter()
            .any(|e| e.tool == tool && e.signal == signal)
        {
            anyhow::bail!(
                "suppress entry for {tool}/{signal} already exists in {}",
                path.display()
            );
        }

        file.suppress.push(SuppressEntry {
            tool: tool.to_string(),
            signal: signal.to_string(),
            reason: reason.to_string(),
        });

        let content = toml::to_string_pretty(&file)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Returns entries that have no corresponding finding in `findings`.
    /// Used to warn about stale suppressions (the tool may have been fixed).
    pub fn stale_entries<'a>(&'a self, findings: &[Finding]) -> Vec<&'a SuppressEntry> {
        self.entries
            .iter()
            .filter(|e| {
                !findings
                    .iter()
                    .any(|f| f.tool_name == e.tool && f.signal.to_string() == e.signal)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::Severity;
    use crate::fuzzer::Signal;

    fn finding(tool: &str, signal: Signal) -> Finding {
        Finding {
            tool_name: tool.to_string(),
            signal,
            severity: Severity::High,
            matched_text: String::new(),
            detail: String::new(),
            corpus_refs: &[],
            suppressed: false,
        }
    }

    #[test]
    fn empty_config_suppresses_nothing() {
        let cfg = SuppressConfig {
            entries: Vec::new(),
        };
        assert!(!cfg.is_suppressed(&finding("send_email", Signal::MessageHijacking)));
    }

    #[test]
    fn matching_entry_suppresses() {
        let cfg = SuppressConfig {
            entries: vec![SuppressEntry {
                tool: "send_email".into(),
                signal: "message_hijacking".into(),
                reason: "reviewed".into(),
            }],
        };
        assert!(cfg.is_suppressed(&finding("send_email", Signal::MessageHijacking)));
        assert!(!cfg.is_suppressed(&finding("send_email", Signal::CredentialReference)));
        assert!(!cfg.is_suppressed(&finding("other_tool", Signal::MessageHijacking)));
    }

    #[test]
    fn append_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".fuzzd").join("suppress.toml");

        SuppressConfig::append(&path, "my_tool", "privileged_path", "ok").unwrap();
        let loaded = SuppressConfig::load_or_empty(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].tool, "my_tool");
        assert_eq!(loaded.entries[0].signal, "privileged_path");
        assert_eq!(loaded.entries[0].reason, "ok");
    }

    #[test]
    fn append_duplicate_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("suppress.toml");

        SuppressConfig::append(&path, "t", "stealth_language", "reason").unwrap();
        let err = SuppressConfig::append(&path, "t", "stealth_language", "reason2");
        assert!(err.is_err());
    }

    #[test]
    fn load_or_empty_missing_file() {
        let cfg = SuppressConfig::load_or_empty(Path::new("/nonexistent/suppress.toml")).unwrap();
        assert!(cfg.entries.is_empty());
    }

    #[test]
    fn stale_entries_detects_missing_findings() {
        let cfg = SuppressConfig {
            entries: vec![
                SuppressEntry {
                    tool: "fixed_tool".into(),
                    signal: "message_hijacking".into(),
                    reason: "was fixed".into(),
                },
                SuppressEntry {
                    tool: "active_tool".into(),
                    signal: "privileged_path".into(),
                    reason: "reviewed".into(),
                },
            ],
        };
        let findings = vec![finding("active_tool", Signal::PrivilegedPath)];
        let stale = cfg.stale_entries(&findings);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].tool, "fixed_tool");
    }
}
