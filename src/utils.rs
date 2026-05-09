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
