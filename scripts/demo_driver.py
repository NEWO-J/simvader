#!/usr/bin/env python3
"""Drive one side of the split-screen Simvader demo.

This is the TOP window on either side. It sends the same four MCP tool calls to whatever
--target you point it at:

    raw side:      --target 127.0.0.1:8801   (the mock server's own HTTP listener)
    guarded side:  --target 127.0.0.1:8802   (Simvader, which fronts the mock over stdio)

Two of the four calls are attacks (an SSRF at the cloud-metadata endpoint, and a command
injection). On the raw side every call succeeds. On the guarded side Simvader blocks the two
attacks before they reach the server.

Lining up separate recordings
------------------------------
The two sides are recorded in separate takes, then stacked side by side. For the halves to
line up, each call must fire at the same wall-clock instant on both sides. So pass the SAME
--start epoch to both:

    START=$(( $(date +%s) + 5 ))
    # window 1:  python3 demo_driver.py --side raw     --target 127.0.0.1:8801 --start $START
    # window 2:  python3 demo_driver.py --side guarded --target 127.0.0.1:8802 --start $START

Each call is scheduled at an ABSOLUTE time (start + offset + n*beat), never a cumulative
sleep, so the two windows stay frame-aligned no matter when each process actually launched.
Without --start it just counts down from 3 and runs immediately (fine for solo testing).
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request

# ---- the script: (label shown, tool, arguments, is_attack) -----------------
STEPS = [
    ("fetch(url=https://news.google.com)",
     "fetch", {"url": "https://news.google.com"}, False),
    ("fetch(url=http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
     "fetch", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/demo-app-instance-role"}, True),
    ("run_command(cmd=ls; cat /etc/passwd)",
     "run_command", {"command": "ls; cat /etc/passwd"}, True),
    ("run_command(cmd=ls -la)",
     "run_command", {"command": "ls -la"}, False),
]

BEAT = 2.2          # seconds between call slots
LEAD = 0.6          # gap between printing the request and showing the response
PRE = 0.8           # delay from start gate to the first call

CWE_RE = re.compile(r"CWE-\d+")


def color(enabled):
    if not enabled:
        return {k: "" for k in "G R Y D B X".split()}
    return {"G": "\033[32m", "R": "\033[31m", "Y": "\033[33m",
            "D": "\033[2m", "B": "\033[1m", "X": "\033[0m"}


def post(target, message):
    data = json.dumps(message).encode()
    req = urllib.request.Request(
        f"http://{target}/mcp", data=data,
        headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode()
    return json.loads(raw) if raw.strip() else {}


def discover_tools(target):
    """Return a {bare_name: exact_name} map so the driver works on either side."""
    post(target, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    post(target, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    listed = post(target, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {}
    for t in listed.get("result", {}).get("tools", []):
        exact = t.get("name", "")
        bare = exact.rsplit("__", 1)[-1]
        names[bare] = exact
    return names


def render(c, resp, is_attack):
    """Print a one-line verdict for a tool-call response."""
    result = resp.get("result", {})
    text = (result.get("content") or [{}])[0].get("text", "")
    if result.get("isError"):
        cwe = CWE_RE.search(text)
        tag = f" {cwe.group()}" if cwe else ""
        print(f"      {c['R']}{c['B']}BLOCKED{c['X']}{c['R']}{tag}{c['X']}  "
              f"{c['D']}refused before it reached the server{c['X']}")
    else:
        snippet = " ".join(text.split())
        if len(snippet) > 62:
            snippet = snippet[:62] + "…"
        mark = f"{c['Y']}<- attack got through{c['X']}  " if is_attack else ""
        print(f"      {c['G']}allowed{c['X']}  {mark}{c['D']}{snippet}{c['X']}")


def wait_for_gate(start, c):
    if start is not None:
        delay = start - time.time()
        if delay > 0:
            time.sleep(delay)
        return start
    # solo mode: quick visible countdown
    for n in (3, 2, 1):
        print(f"  {c['D']}starting in {n}…{c['X']}", end="\r", flush=True)
        time.sleep(1)
    print(" " * 24, end="\r")
    return time.time()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", choices=["raw", "guarded"], required=True)
    ap.add_argument("--target", required=True, help="host:port of the MCP endpoint")
    ap.add_argument("--start", type=float, default=None,
                    help="unix epoch to begin firing (pass the same value to both sides)")
    args = ap.parse_args()

    c = color(sys.stdout.isatty() and "NO_COLOR" not in os.environ)

    if args.side == "guarded":
        title = f"{c['B']}simvader{c['X']}  {c['D']}MCP behind the gateway{c['X']}"
    else:
        title = f"{c['B']}direct{c['X']}  {c['D']}MCP with no gateway{c['X']}"

    # Handshake before the gate, so this noise stays out of the recorded window.
    names = discover_tools(args.target)

    print(f"\n  {title}\n")
    t0 = wait_for_gate(args.start, c)

    for i, (label, tool, arguments, is_attack) in enumerate(STEPS):
        slot = t0 + PRE + i * BEAT
        now = time.time()
        if slot > now:
            time.sleep(slot - now)

        note = f"   {c['Y']}<- {'command injection' if tool == 'run_command' else 'prompt-injected SSRF'}{c['X']}" if is_attack else ""
        print(f"   {c['D']}>{c['X']} {label}{note}")

        time.sleep(LEAD)
        call = {"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
                "params": {"name": names.get(tool, tool), "arguments": arguments}}
        try:
            resp = post(args.target, call)
            render(c, resp, is_attack)
        except Exception as e:  # noqa: BLE001 - demo driver, show the failure and keep going
            print(f"      {c['R']}error:{c['X']} {e}")

    print(f"\n  {c['D']}done.{c['X']}\n")


if __name__ == "__main__":
    main()
