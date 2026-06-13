use anyhow::Result;

use crate::fuzzer::Finding;

/// Capability-escape fuzzer — probes MCP capability negotiation for escalation paths.
/// Currently a no-op stub; full implementation tracked in issue #78.
pub async fn fuzz_escape() -> Result<Vec<Finding>> {
    Ok(vec![])
}
