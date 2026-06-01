use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::fuzzer::Finding;

/// Default path for the suppress file, relative to the working directory.
pub const DEFAULT_SUPPRESS_PATH: &str = ".fuzzd/suppress.toml";

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
    /// Pre-built set of `"tool/signal"` keys for O(1) `is_suppressed` lookup.
    key_set: HashSet<String>,
}

impl SuppressConfig {
    fn build_key_set(entries: &[SuppressEntry]) -> HashSet<String> {
        entries
            .iter()
            .map(|e| format!("{}/{}", e.tool, e.signal))
            .collect()
    }

    /// Load suppressions from `path`. Returns an empty config if the file does not exist.
    pub fn load_or_empty(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                entries: Vec::new(),
                key_set: HashSet::new(),
            });
        }
        let content = std::fs::read_to_string(path)?;
        let file: SuppressFile = toml::from_str(&content)?;
        let key_set = Self::build_key_set(&file.suppress);
        Ok(Self {
            entries: file.suppress,
            key_set,
        })
    }

    /// Returns true if `finding` has a matching suppress entry. O(1) hash lookup.
    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        self.key_set.contains(finding.id().as_str())
    }

    /// Returns entries that have no corresponding finding in `findings`.
    /// Builds a `HashSet` from findings first for O(N+M) total cost.
    pub fn stale_entries<'a>(&'a self, findings: &[Finding]) -> Vec<&'a SuppressEntry> {
        let found: HashSet<String> = findings.iter().map(|f| f.id()).collect();
        self.entries
            .iter()
            .filter(|e| !found.contains(&format!("{}/{}", e.tool, e.signal)))
            .collect()
    }

    /// Append a new suppress entry to `path`, creating the file (and parent dirs) as needed.
    /// Returns an error if an entry for `tool`/`signal` already exists.
    /// Writes atomically via a sibling temp file + rename to prevent corruption on crash.
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
        // Write to a sibling temp file then rename — atomic on Unix, safe on crash.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &content)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(())
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

    fn config(entries: Vec<SuppressEntry>) -> SuppressConfig {
        let key_set = SuppressConfig::build_key_set(&entries);
        SuppressConfig { entries, key_set }
    }

    #[test]
    fn empty_config_suppresses_nothing() {
        let cfg = config(vec![]);
        assert!(!cfg.is_suppressed(&finding("send_email", Signal::MessageHijacking)));
    }

    #[test]
    fn matching_entry_suppresses() {
        let cfg = config(vec![SuppressEntry {
            tool: "send_email".into(),
            signal: "message_hijacking".into(),
            reason: "reviewed".into(),
        }]);
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
        let cfg = config(vec![
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
        ]);
        let findings = vec![finding("active_tool", Signal::PrivilegedPath)];
        let stale = cfg.stale_entries(&findings);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].tool, "fixed_tool");
    }
}
