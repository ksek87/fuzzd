# fuzzd — Claude Guidelines

## Non-negotiable code standards

### No repeated code
- Before writing any new function, search the codebase for existing utilities that do the same thing.
- `src/utils.rs` is the home for shared logic. Put SSE parsing, string helpers, and other reusable pieces there.
- `src/testutil.rs` is the home for shared test infrastructure (`MockTransport`, `ok_response`, `init_response`, `tools_response`). Never duplicate these inline.
- If two places do the same thing, extract it. Three similar lines is the threshold — not three files.

### No unsafe code
- Zero `unsafe` blocks. The entire codebase is safe Rust. Keep it that way.
- Never call `.unwrap()` in production paths. Use `?`, `anyhow::bail!`, or explicit `match`.
- `.expect("msg")` is allowed only to assert invariants the code itself establishes (e.g. `child.stdin.take().expect("stdin piped")` immediately after `.stdin(Stdio::piped())`). If the panic message starts with "should" or "must", that's a smell — use `?` instead.

### Resource management — mandatory checklist
Every `tokio::spawn` **must** have its `JoinHandle` stored and aborted on cleanup:
```rust
// CORRECT — store the handle
struct Foo { task: tokio::task::JoinHandle<()> }
impl Drop for Foo { fn drop(&mut self) { self.task.abort(); } }

// WRONG — handle dropped immediately, task leaks
tokio::spawn(async move { ... });
```

Every `close()` on a transport **must** drain the `PendingMap`:
```rust
self.pending.lock().await.clear(); // drops all senders → waiting rx.await returns Err
```

Never use `String::from_utf8_lossy` on untrusted byte streams — it silently replaces invalid bytes. Use `str::from_utf8` and handle the error explicitly (skip or log).

### Performance
- Acquire locks for the shortest possible scope. Collect work first, then lock once — not once per item.
- Do not clone unless required. Return `&[T]` slices for read-only access; only return `Vec<T>` when the caller needs ownership.
- Independent async operations must run concurrently (`tokio::join!` or `FuturesUnordered`), not sequentially.
- Avoid unbounded data structures. Every `HashMap` that accumulates entries must have a corresponding drain path.
- Background tasks must be abortable (see resource management above).

### Tests
- All tests use `MockTransport` from `src/testutil.rs`. No real network or child processes in unit tests.
- Session tests use `Session::ready(transport)` or set `state = SessionState::Ready` directly — never drive a full initialize handshake just to reach Ready.
- Test names describe the outcome, not the mechanism: `enumerate_tools_uses_cache_on_second_call`, not `test_cache`.

---

## Project structure

```
fuzzd/
├── src/
│   ├── main.rs                        # Entrypoint; wires CLI → commands
│   ├── cli/mod.rs                     # clap derive: Audit/Scan/Corpus subcommands,
│   │                                  #   TransportKind, AttackModule, OutputFormat
│   │
│   ├── protocol/
│   │   ├── mod.rs                     # Re-exports mcp, session, transport
│   │   ├── mcp.rs                     # All MCP/JSON-RPC types + serde impls:
│   │   │                              #   JsonRpcRequest, JsonRpcResponse, RequestId,
│   │   │                              #   ResponseOutcome, ToolDefinition, CallToolResult,
│   │   │                              #   ToolContent, InitializeParams, methods consts
│   │   ├── session.rs                 # Session<T: Transport> state machine:
│   │   │                              #   Unconnected → Initializing → Ready → Closed
│   │   │                              #   initialize(), list_tools(), call_tool(), close()
│   │   │                              #   Per-session AtomicI64 request counter
│   │   └── transport/
│   │       ├── mod.rs                 # Transport trait (send/notify/close),
│   │       │                          #   PendingMap type alias, id_key() helper
│   │       ├── stdio.rs               # StdioTransport: spawns child process,
│   │       │                          #   newline-delimited JSON over stdin/stdout,
│   │       │                          #   background reader task with stored JoinHandle
│   │       └── http.rs                # HttpTransport: POST to /mcp, SSE on /sse,
│   │                                  #   Arc<Client> shared with SSE task,
│   │                                  #   stored JoinHandle, UTF-8 validated chunks
│   │
│   ├── runner/
│   │   ├── mod.rs
│   │   └── harness.rs                 # Harness<T>: high-level wrapper over Session<T>
│   │                                  #   enumerate_tools() with cache, call_tool()
│   │
│   ├── fuzzer/mod.rs                  # (v0.2+) Attack module orchestration
│   ├── analyzer/mod.rs                # (v0.2+) Result analysis, heuristics
│   ├── corpus/
│   │   ├── mod.rs                     # (v0.2+) Corpus loader
│   │   └── schema.rs                  # (v0.2+) Corpus entry schema
│   ├── reporter/mod.rs                # (v0.2+) SARIF/JSON/text output
│   │
│   ├── utils.rs                       # Shared pure utilities:
│   │                                  #   drain_sse_events(), sse_data()
│   └── testutil.rs                    # Test-only (cfg(test)):
│                                      #   MockTransport, ok_response(),
│                                      #   init_response(), tools_response()
│
├── .github/workflows/ci.yml           # cargo fmt --check, clippy -D warnings,
│                                      #   cargo test, cargo build --release
└── Cargo.toml
```

### Key design invariants

| Concept | Rule |
|---|---|
| `Transport` trait | `send()` = request + awaited response; `notify()` = fire-and-forget write. Never use `send()` for notifications — it registers a pending entry that will never be resolved. |
| `PendingMap` | Keyed by `id_key(request.id)`. Must be drained in `close()`. Dropping a sender causes the waiting `rx.await` to return `Err` immediately. |
| Request IDs | Per-session `AtomicI64` counter starting at 1. Never use a global static — concurrent sessions would collide. |
| `SessionState` | `Ready` is the only state that permits `list_tools` and `call_tool`. All methods guard with `require_ready()`. |
| Tool cache | `Session.tools` is populated by `list_tools()`. `Harness.enumerate_tools()` checks `session.tools.is_empty()` before fetching. `Harness.tools()` returns `&[ToolDefinition]` for zero-copy read access. |
| Background tasks | Both transports spawn one background task. The `JoinHandle` is stored as a struct field and `.abort()`ed in `Drop` (and in `close()`). |
