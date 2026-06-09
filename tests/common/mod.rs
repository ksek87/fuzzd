//! Shared helpers for the end-to-end integration tests. Each `tests/*.rs` file
//! is its own crate, so this module is compiled separately into each; the
//! `allow(dead_code)` keeps `-D warnings` happy when a given test crate only
//! uses a subset of these helpers.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;

/// A `Command` for the freshly built `fuzzd` binary under test.
pub fn fuzzd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fuzzd"))
}

/// Absolute path to a file under `tests/fixtures/`.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
