#![allow(dead_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::warn;

use crate::corpus::schema::{AttackRecord, Category, Severity};

static EMBEDDED: &[&str] = &[
    // Tool poisoning — paradigm 1 (explicit trigger)
    include_str!("../../corpus/tool_poisoning/TPA-001.json"),
    include_str!("../../corpus/tool_poisoning/TPA-002.json"),
    include_str!("../../corpus/tool_poisoning/TPA-003.json"),
    include_str!("../../corpus/tool_poisoning/TPA-004.json"),
    // Tool poisoning — paradigm 2 (implicit trigger)
    include_str!("../../corpus/tool_poisoning/TPA-005.json"),
    include_str!("../../corpus/tool_poisoning/TPA-006.json"),
    include_str!("../../corpus/tool_poisoning/TPA-007.json"),
    include_str!("../../corpus/tool_poisoning/TPA-008.json"),
    // Tool poisoning — paradigm 3 (persistent injection)
    include_str!("../../corpus/tool_poisoning/TPA-009.json"),
    include_str!("../../corpus/tool_poisoning/TPA-010.json"),
    include_str!("../../corpus/tool_poisoning/TPA-011.json"),
    include_str!("../../corpus/tool_poisoning/TPA-012.json"),
    // Tool poisoning — MCPTox Template-1/2/3 + Invariant Labs XML injection
    include_str!("../../corpus/tool_poisoning/TPA-013.json"),
    include_str!("../../corpus/tool_poisoning/TPA-014.json"),
    include_str!("../../corpus/tool_poisoning/TPA-015.json"),
    include_str!("../../corpus/tool_poisoning/TPA-016.json"),
    include_str!("../../corpus/tool_poisoning/TPA-017.json"),
    // Tool poisoning — MCP-UPD parasitic toolchain, Trivial Trojans, message hijacking, unicode evasion
    include_str!("../../corpus/tool_poisoning/TPA-018.json"),
    include_str!("../../corpus/tool_poisoning/TPA-019.json"),
    include_str!("../../corpus/tool_poisoning/TPA-020.json"),
    include_str!("../../corpus/tool_poisoning/TPA-021.json"),
    // Tool shadowing / name squatting
    include_str!("../../corpus/tool_shadowing/TS-001.json"),
    include_str!("../../corpus/tool_shadowing/TS-002.json"),
    include_str!("../../corpus/tool_shadowing/TS-003.json"),
    // Rug pull / sleeper
    include_str!("../../corpus/rug_pull/RUG-001.json"),
    include_str!("../../corpus/rug_pull/RUG-002.json"),
    include_str!("../../corpus/rug_pull/RUG-003.json"),
];

pub struct Corpus {
    pub records: Vec<AttackRecord>,
}

impl Corpus {
    /// The built-in seed corpus embedded at compile time.
    pub fn embedded() -> Self {
        let records = EMBEDDED
            .iter()
            .enumerate()
            .filter_map(|(i, src)| {
                serde_json::from_str::<AttackRecord>(src)
                    .map_err(|e| warn!("embedded record [{}] is invalid: {e}", i))
                    .ok()
            })
            .collect();
        Self { records }
    }

    /// Parse a single record from a JSON file. Returns an error if it fails schema validation.
    pub fn load_file(path: &Path) -> Result<AttackRecord> {
        let src = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_str(&src)
            .with_context(|| format!("invalid AttackRecord in {}", path.display()))
    }

    /// Load all `.json` files from a directory tree. Invalid files are skipped with a warning.
    pub fn load_dir(path: &Path) -> Result<Self> {
        let mut files = Vec::new();
        collect_json_files(path, &mut files)
            .with_context(|| format!("cannot read corpus dir {}", path.display()))?;
        let records = files
            .into_iter()
            .filter_map(|p| {
                Self::load_file(&p)
                    .map_err(|e| warn!("skipping {}: {e}", p.display()))
                    .ok()
            })
            .collect();
        Ok(Self { records })
    }

    /// All records matching the given category.
    pub fn by_category(&self, category: &Category) -> Vec<&AttackRecord> {
        self.records
            .iter()
            .filter(|r| &r.category == category)
            .collect()
    }

    /// All records at or above the given minimum severity.
    pub fn by_min_severity(&self, min: &Severity) -> Vec<&AttackRecord> {
        self.records.iter().filter(|r| &r.severity >= min).collect()
    }
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_json_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn embedded_corpus_loads_without_error() {
        let corpus = Corpus::embedded();
        assert_eq!(corpus.records.len(), 27);
    }

    #[test]
    fn embedded_corpus_contains_all_categories() {
        let corpus = Corpus::embedded();
        let has = |cat: Category| corpus.records.iter().any(|r| r.category == cat);
        assert!(has(Category::ToolPoisoning));
        assert!(has(Category::ToolShadowing));
        assert!(has(Category::RugPull));
    }

    #[test]
    fn by_category_filters_correctly() {
        let corpus = Corpus::embedded();
        let tpa = corpus.by_category(&Category::ToolPoisoning);
        assert_eq!(tpa.len(), 21);
        let shadowing = corpus.by_category(&Category::ToolShadowing);
        assert_eq!(shadowing.len(), 3);
        let rug_pull = corpus.by_category(&Category::RugPull);
        assert_eq!(rug_pull.len(), 3);
        let proto = corpus.by_category(&Category::Protocol);
        assert!(proto.is_empty());
    }

    #[test]
    fn by_min_severity_filters_correctly() {
        let corpus = Corpus::embedded();
        let critical = corpus.by_min_severity(&Severity::Critical);
        // All 12 embedded records are critical or high — at least some must be critical
        assert!(!critical.is_empty());
        // Info threshold should return everything
        let all = corpus.by_min_severity(&Severity::Info);
        assert_eq!(all.len(), corpus.records.len());
    }

    #[test]
    fn load_file_parses_valid_record() {
        let json = r#"{
            "id": "TEST-001",
            "version": "1.0.0",
            "category": "tool_poisoning",
            "subcategory": "test",
            "paradigm": 1,
            "vector": "description_injection",
            "payload": "test payload",
            "injection_point": "tool.description",
            "trigger_condition": "tool_directly_invoked",
            "expected_behavior": "test behavior",
            "detection_signals": ["test_signal"],
            "severity": "high",
            "source": "test",
            "tags": ["test"]
        }"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        let record = Corpus::load_file(tmp.path()).unwrap();
        assert_eq!(record.id, "TEST-001");
        assert_eq!(record.severity, Severity::High);
    }

    #[test]
    fn load_file_rejects_invalid_json() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"not json").unwrap();
        assert!(Corpus::load_file(tmp.path()).is_err());
    }

    #[test]
    fn load_file_rejects_missing_required_field() {
        let json = r#"{"id": "X", "version": "1.0.0"}"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        assert!(Corpus::load_file(tmp.path()).is_err());
    }

    #[test]
    fn load_dir_reads_json_files() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{
            "id": "DIR-001",
            "version": "1.0.0",
            "category": "protocol",
            "subcategory": "test",
            "vector": "protocol_malform",
            "payload": "test",
            "injection_point": "jsonrpc.method",
            "trigger_condition": "always",
            "expected_behavior": "test",
            "detection_signals": [],
            "severity": "low",
            "source": "test",
            "tags": []
        }"#;
        std::fs::write(dir.path().join("record.json"), json).unwrap();
        let corpus = Corpus::load_dir(dir.path()).unwrap();
        assert_eq!(corpus.records.len(), 1);
        assert_eq!(corpus.records[0].id, "DIR-001");
    }

    #[test]
    fn load_dir_skips_non_json_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not json").unwrap();
        let corpus = Corpus::load_dir(dir.path()).unwrap();
        assert!(corpus.records.is_empty());
    }
}
