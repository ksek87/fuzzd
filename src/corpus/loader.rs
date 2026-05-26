use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tracing::warn;

use crate::corpus::schema::{AttackRecord, Category, Severity};
use crate::utils::read_json_file;

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
    // Tool poisoning — MCPTox unrelated-prerequisite/fake-enabling-prerequisite/argument-hijacking + Invariant Labs XML injection
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

static PARSED_EMBEDDED: OnceLock<Vec<AttackRecord>> = OnceLock::new();

impl Corpus {
    /// The built-in seed corpus embedded at compile time.
    /// JSON is parsed once per process and cached; subsequent calls clone the cached records.
    pub fn embedded() -> Self {
        let records = PARSED_EMBEDDED
            .get_or_init(|| {
                EMBEDDED
                    .iter()
                    .enumerate()
                    .filter_map(|(i, src)| {
                        serde_json::from_str::<AttackRecord>(src)
                            .map_err(|e| warn!("embedded record [{}] is invalid: {e}", i))
                            .ok()
                    })
                    .collect()
            })
            .clone();
        Self { records }
    }

    /// Parse a single record from a JSON file. Returns an error if it fails schema validation.
    pub fn load_file(path: &Path) -> Result<AttackRecord> {
        read_json_file(path)
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

    #[allow(dead_code)]
    pub fn by_category<'a>(
        &'a self,
        category: &'a Category,
    ) -> impl Iterator<Item = &'a AttackRecord> {
        self.records.iter().filter(move |r| &r.category == category)
    }

    #[allow(dead_code)]
    pub fn by_min_severity<'a>(
        &'a self,
        min: &'a Severity,
    ) -> impl Iterator<Item = &'a AttackRecord> {
        self.records.iter().filter(move |r| &r.severity >= min)
    }
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
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
        assert_eq!(corpus.by_category(&Category::ToolPoisoning).count(), 21);
        assert_eq!(corpus.by_category(&Category::ToolShadowing).count(), 3);
        assert_eq!(corpus.by_category(&Category::RugPull).count(), 3);
        assert_eq!(corpus.by_category(&Category::Protocol).count(), 0);
    }

    #[test]
    fn by_min_severity_filters_correctly() {
        let corpus = Corpus::embedded();
        assert!(corpus.by_min_severity(&Severity::Critical).next().is_some());
        assert_eq!(
            corpus.by_min_severity(&Severity::Info).count(),
            corpus.records.len()
        );
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
