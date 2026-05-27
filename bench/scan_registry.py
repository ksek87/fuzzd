#!/usr/bin/env python3
"""
bench/scan_registry.py — Scan real-world MCP servers from public registries.

For each server in SERVERS:
  1. Spawns it via `npx -y <package>` (no pre-install needed)
  2. Sends MCP initialize + tools/list over stdio
  3. Collects tool definitions
  4. Writes a combined fuzzd-compatible JSON array to --output

Then (unless --no-scan) runs `fuzzd scan --schema <output>` and prints results.

Usage:
  python3 bench/scan_registry.py [--output FILE] [--no-scan] [--timeout N]

  --output FILE    Where to write collected tool definitions (default: /tmp/registry_tools.json)
  --no-scan        Skip the fuzzd scan step (just collect tools)
  --timeout N      Seconds to wait for each server's tool list (default: 20)

The servers below are all public npm packages that work without API keys
or credentials. They are representative of real-world MCP deployments.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Curated list of public MCP servers that run without API keys.
# Each entry: name, npx command, optional extra notes.
# ---------------------------------------------------------------------------
SERVERS = [
    {
        "name": "mcp-fetch",
        "source": "npm:@modelcontextprotocol/server-fetch",
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-fetch"],
        "env": {},
    },
    {
        "name": "mcp-memory",
        "source": "npm:@modelcontextprotocol/server-memory",
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-memory"],
        "env": {},
    },
    {
        "name": "mcp-time",
        "source": "npm:@modelcontextprotocol/server-time",
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-time"],
        "env": {},
    },
    {
        "name": "mcp-filesystem",
        "source": "npm:@modelcontextprotocol/server-filesystem",
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        "env": {},
    },
    {
        "name": "mcp-sequential-thinking",
        "source": "npm:@modelcontextprotocol/server-sequentialthinking",
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-sequentialthinking"],
        "env": {},
    },
    {
        "name": "mcp-git",
        "source": "npm:mcp-server-git",
        "cmd": ["npx", "-y", "mcp-server-git", "--repository", "."],
        "env": {},
    },
    {
        "name": "mcp-everything",
        "source": "npm:@modelcontextprotocol/server-everything",
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-everything"],
        "env": {},
    },
    {
        "name": "mcp-sqlite",
        "source": "npm:mcp-server-sqlite-npx",
        "cmd": ["npx", "-y", "mcp-server-sqlite-npx", "/tmp/demo.db"],
        "env": {},
    },
    {
        "name": "mcp-playwright",
        "source": "npm:@executeautomation/playwright-mcp-server",
        "cmd": ["npx", "-y", "@executeautomation/playwright-mcp-server"],
        "env": {},
    },
    {
        "name": "mcp-context7",
        "source": "npm:@upstash/context7-mcp",
        "cmd": ["npx", "-y", "@upstash/context7-mcp"],
        "env": {},
    },
    {
        "name": "mcp-eslint",
        "source": "npm:@eslint/mcp",
        "cmd": ["npx", "-y", "@eslint/mcp@latest"],
        "env": {},
    },
    # mcp-pdf: large download / hangs before MCP handshake — excluded
    # {
    #     "name": "mcp-pdf",
    #     "source": "npm:@modelcontextprotocol/server-pdf",
    #     "cmd": ["npx", "-y", "@modelcontextprotocol/server-pdf"],
    # },
    {
        "name": "mcp-git-cyanheads",
        "source": "npm:@cyanheads/git-mcp-server",
        "cmd": ["npx", "-y", "@cyanheads/git-mcp-server"],
        "env": {},
    },
    {
        "name": "mcp-kubernetes",
        "source": "npm:mcp-server-kubernetes",
        "cmd": ["npx", "-y", "mcp-server-kubernetes"],
        "env": {},
    },
    {
        "name": "mcp-code-todo",
        "source": "npm:mcp-code-todo",
        "cmd": ["npx", "-y", "mcp-code-todo"],
        "env": {},
    },
    {
        "name": "mcp-openapi",
        "source": "npm:@ivotoby/openapi-mcp-server",
        "cmd": ["npx", "-y", "@ivotoby/openapi-mcp-server"],
        "env": {},
    },
    {
        "name": "mcp-chrome-devtools",
        "source": "npm:chrome-devtools-mcp",
        "cmd": ["npx", "-y", "chrome-devtools-mcp"],
        "env": {},
    },
    {
        "name": "mcp-desktop-commander",
        "source": "npm:@wonderwhy-er/desktop-commander",
        "cmd": ["npx", "-y", "@wonderwhy-er/desktop-commander"],
        "env": {},
    },
    {
        "name": "mcp-shell",
        "source": "npm:mcp-shell",
        "cmd": ["npx", "-y", "mcp-shell"],
        "env": {},
    },
    {
        "name": "mcp-filesystem-secure",
        "source": "npm:@modelcontextprotocol/server-filesystem",
        "cmd": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home"],
        "env": {},
    },
    {
        "name": "mcp-obsidian",
        "source": "npm:mcp-obsidian",
        "cmd": ["npx", "-y", "mcp-obsidian", "/tmp"],
        "env": {},
    },
    {
        "name": "mcp-docker",
        "source": "npm:mcp-docker",
        "cmd": ["npx", "-y", "mcp-docker"],
        "env": {},
    },
    {
        "name": "mcp-tavily",
        "source": "npm:tavily-mcp",
        "cmd": ["npx", "-y", "tavily-mcp"],
        "env": {"TAVILY_API_KEY": "dummy"},
    },
]

# ---------------------------------------------------------------------------
# MCP handshake helpers
# ---------------------------------------------------------------------------

_INIT_MSG = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "fuzzd-registry-scanner", "version": "0.1"},
    },
}) + "\n"

_INITIALIZED_NOTIFY = json.dumps({
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
    "params": {},
}) + "\n"

_LIST_TOOLS_MSG = json.dumps({
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {},
}) + "\n"


def _read_json_line(proc, deadline: float) -> dict | None:
    """Read lines from proc.stdout until we get a JSON object or deadline passes."""
    buf = b""
    while time.monotonic() < deadline:
        # Check if process died
        if proc.poll() is not None:
            return None
        try:
            chunk = proc.stdout.read(1)
            if not chunk:
                time.sleep(0.01)
                continue
            buf += chunk
            if chunk == b"\n":
                line = buf.strip()
                buf = b""
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue  # stderr noise or progress lines
        except (OSError, ValueError):
            return None
    return None


def enumerate_tools(server: dict, timeout: int) -> list[dict]:
    """Spawn server, run MCP handshake, return list of ToolDefinition dicts."""
    env = {**os.environ, **server.get("env", {})}
    # Suppress stderr from the server so our output stays clean
    try:
        proc = subprocess.Popen(
            server["cmd"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
    except FileNotFoundError as e:
        print(f"  ✗ {server['name']}: command not found ({e})", file=sys.stderr)
        return []

    deadline = time.monotonic() + timeout
    tools = []

    try:
        # Step 1: send initialize
        proc.stdin.write(_INIT_MSG.encode())
        proc.stdin.flush()

        # Step 2: wait for initialize response (id=1)
        resp = None
        while time.monotonic() < deadline:
            resp = _read_json_line(proc, deadline)
            if resp is None:
                break
            if resp.get("id") == 1:
                break

        if resp is None or resp.get("id") != 1:
            return []

        # Step 3: send initialized notification + tools/list
        proc.stdin.write(_INITIALIZED_NOTIFY.encode())
        proc.stdin.write(_LIST_TOOLS_MSG.encode())
        proc.stdin.flush()

        # Step 4: wait for tools/list response (id=2)
        while time.monotonic() < deadline:
            resp = _read_json_line(proc, deadline)
            if resp is None:
                break
            if resp.get("id") == 2:
                result = resp.get("result", {})
                raw_tools = result.get("tools", [])
                for t in raw_tools:
                    tools.append({
                        "name": t.get("name", "unknown"),
                        "description": t.get("description") or "",
                        "inputSchema": t.get("inputSchema", {"type": "object"}),
                        "_meta": {"source": server["source"]},
                    })
                break

    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            proc.kill()
            proc.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

    return tools


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", default="/tmp/registry_tools.json",
                        help="Output file for collected tool definitions")
    parser.add_argument("--no-scan", action="store_true",
                        help="Skip fuzzd scan step")
    parser.add_argument("--timeout", type=int, default=20,
                        help="Seconds to wait per server (default: 20)")
    args = parser.parse_args()

    print(f"\n  fuzzd registry scanner — {len(SERVERS)} servers")
    print("  " + "─" * 68)

    all_tools: list[dict] = []
    server_counts: dict[str, int] = {}

    for server in SERVERS:
        print(f"\n  [{server['name']}]", flush=True)
        print(f"    cmd: {' '.join(server['cmd'][:4])}{'…' if len(server['cmd']) > 4 else ''}")
        tools = enumerate_tools(server, args.timeout)
        if tools:
            print(f"    ✓ {len(tools)} tool(s) collected")
            for t in tools:
                print(f"      • {t['name']}")
            all_tools.extend(tools)
            server_counts[server["name"]] = len(tools)
        else:
            print(f"    ✗ no tools collected (timeout or startup error)")
            server_counts[server["name"]] = 0

    print(f"\n  " + "─" * 68)
    print(f"  Total: {len(all_tools)} tool definitions from {sum(1 for v in server_counts.values() if v > 0)}/{len(SERVERS)} servers")

    if not all_tools:
        print("  No tools collected — nothing to scan.", file=sys.stderr)
        return 1

    with open(args.output, "w") as f:
        json.dump(all_tools, f, indent=2)
    print(f"  Written to: {args.output}")

    if args.no_scan:
        return 0

    print(f"\n  " + "─" * 68)
    print(f"  Running: fuzzd scan --schema {args.output}\n")

    # Determine fuzzd binary — prefer release build, fall back to cargo run
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    release_bin = os.path.join(repo_root, "target", "release", "fuzzd")
    if os.path.isfile(release_bin) and os.access(release_bin, os.X_OK):
        fuzzd_cmd = [release_bin, "scan", "--schema", args.output]
    else:
        fuzzd_cmd = ["cargo", "run", "--quiet", "--", "scan", "--schema", args.output]

    result = subprocess.run(fuzzd_cmd, cwd=repo_root)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
