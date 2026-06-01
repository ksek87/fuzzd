# Security Policy

## Scope

This policy covers **vulnerabilities in fuzzd itself** — the scanner, CLI, and corpus tooling.

**In scope:**
- Command injection via maliciously crafted MCP server responses or tool definitions
- Path traversal in corpus file handling or suppress file operations
- Denial of service via crafted input (e.g. regex catastrophic backtracking, unbounded allocations)
- Incorrect suppression — a finding that should fire but is silently dropped
- False-negative bypass — a pattern that crafted whitespace or encoding renders undetectable

**Out of scope:**
- Vulnerabilities *in the MCP servers that fuzzd scans* — report those to the respective maintainers
- Issues in research datasets (MCPTox, MCPSecBench) — report to their authors
- Theoretical attacks that require modifying fuzzd's own binary
- Missing detection for a *new* attack pattern — open a regular issue instead

## Reporting

**For vulnerabilities in fuzzd itself**, email: **ksekerka87@gmail.com**

Please include:
- A description of the vulnerability and its impact
- A minimal reproduction case (command, input file, or corpus record)
- The fuzzd version (`fuzzd --version`)
- Whether you believe this is exploitable in a realistic deployment

GitHub's private vulnerability reporting is also enabled — use the **"Report a vulnerability"** button on the [Security tab](https://github.com/ksek87/fuzzd/security/advisories/new).

## Response SLA

| Event | Target |
|---|---|
| Initial acknowledgement | ≤ 72 hours |
| Severity assessment | ≤ 5 business days |
| Patch for Critical/High | ≤ 14 days from report |
| Patch for Medium/Low | ≤ 30 days from report |
| Public disclosure | Coordinated with reporter; default 90 days |

## Coordinated Disclosure

We follow coordinated disclosure. Do not open a public GitHub issue for a vulnerability before receiving an acknowledgement. If you do not hear back within 72 hours, follow up by email with "SECURITY FOLLOW-UP" in the subject line.

Once a patch is released, we will publish a GitHub Security Advisory crediting the reporter (unless you prefer to remain anonymous).

## Hall of Fame

Researchers who responsibly disclose valid vulnerabilities are listed here:

*No entries yet — be the first.*
