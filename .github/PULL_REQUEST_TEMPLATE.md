## Summary

<!-- What does this PR do and why? Link the issue it closes. -->

Closes #

## Detection rate impact

<!-- Required for any change to signals, patterns, or scoring. Run ./bench/run.sh and paste the before/after. -->

| Metric | Before | After | Delta |
|---|---|---|---|
| MCPTox actual recall | | | |
| False positives | | | |

_N/A — no detection changes in this PR._

## Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `./bench/run.sh` run and delta reported above (or marked N/A)
- [ ] New corpus records cite a published source (URL in `source_url` field)
- [ ] New `Signal` variants added to `Signal::ALL`, `as_str()`, `rule_id()`, `description()`
- [ ] No `unsafe` blocks introduced
- [ ] No `.unwrap()` in production paths
- [ ] Every new `tokio::spawn` stores its `JoinHandle`
