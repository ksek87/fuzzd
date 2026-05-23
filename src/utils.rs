// Used by http.rs (transport pending audit CLI wiring).
#![allow(dead_code)]

/// Drain completed SSE events from `buf` in-place, calling `on_event` for each.
/// An SSE event is terminated by `\n\n`. Consumed bytes are removed from `buf`.
pub(crate) fn drain_sse_events(buf: &mut String, mut on_event: impl FnMut(&str)) {
    while let Some(pos) = buf.find("\n\n") {
        on_event(&buf[..pos]);
        buf.drain(..pos + 2);
    }
}

/// Extract the payload from an SSE `data:` line, trimming leading whitespace.
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
}
