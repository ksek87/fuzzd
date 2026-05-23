use std::path::Path;

use anyhow::{Context, Result};

/// Read a JSON file and deserialise it into `T`.
pub(crate) fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_str(&src).with_context(|| format!("invalid JSON in {}", path.display()))
}

/// Drain completed SSE events from `buf` in-place, calling `on_event` for each.
/// An SSE event is terminated by `\n\n`. Consumed bytes are removed from `buf`.
#[allow(dead_code)]
pub(crate) fn drain_sse_events(buf: &mut String, mut on_event: impl FnMut(&str)) {
    while let Some(pos) = buf.find("\n\n") {
        on_event(&buf[..pos]);
        buf.drain(..pos + 2);
    }
}

/// Extract the payload from an SSE `data:` line, trimming leading whitespace.
#[allow(dead_code)]
pub(crate) fn sse_data(line: &str) -> Option<&str> {
    line.strip_prefix("data:").map(str::trim)
}

/// Extract a ≤40-char context window around the matched byte range `[start, end)` in `haystack`.
pub(crate) fn extract_snippet(haystack: &str, start: usize, end: usize) -> String {
    const CTX: usize = 40;
    let snip_start = haystack[..start]
        .char_indices()
        .rev()
        .take(CTX)
        .last()
        .map_or(0, |(i, _)| i);
    let snip_end = haystack[end..]
        .char_indices()
        .take(CTX)
        .last()
        .map_or(haystack.len(), |(i, c)| end + i + c.len_utf8());
    let snippet = &haystack[snip_start..snip_end];
    match (snip_start > 0, snip_end < haystack.len()) {
        (true, true) => format!("…{snippet}…"),
        (true, false) => format!("…{snippet}"),
        (false, true) => format!("{snippet}…"),
        (false, false) => snippet.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_sse_events_single() {
        let mut buf = "data: hello\n\nremaining".to_string();
        let mut events = vec![];
        drain_sse_events(&mut buf, |e| events.push(e.to_string()));
        assert_eq!(events, ["data: hello"]);
        assert_eq!(buf, "remaining");
    }

    #[test]
    fn drain_sse_events_multiple() {
        let mut buf = "data: a\n\ndata: b\n\n".to_string();
        let mut events = vec![];
        drain_sse_events(&mut buf, |e| events.push(e.to_string()));
        assert_eq!(events, ["data: a", "data: b"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn drain_sse_events_incomplete_leaves_buf() {
        let mut buf = "data: partial".to_string();
        let mut count = 0;
        drain_sse_events(&mut buf, |_| count += 1);
        assert_eq!(count, 0);
        assert_eq!(buf, "data: partial");
    }

    #[test]
    fn sse_data_extracts_payload() {
        assert_eq!(sse_data("data: hello"), Some("hello"));
        assert_eq!(sse_data("data:hello"), Some("hello"));
        assert_eq!(sse_data("event: ping"), None);
        assert_eq!(sse_data("data:  spaced  "), Some("spaced"));
    }

    #[test]
    fn read_json_file_parses_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        std::fs::write(&path, r#"{"key": "value"}"#).unwrap();
        let val: serde_json::Value = read_json_file(&path).unwrap();
        assert_eq!(val["key"], "value");
    }

    #[test]
    fn read_json_file_errors_on_missing_file() {
        let result = read_json_file::<serde_json::Value>(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot read"));
    }

    #[test]
    fn read_json_file_errors_on_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        let result = read_json_file::<serde_json::Value>(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid JSON"));
    }
}
