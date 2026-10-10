#!/usr/bin/env python3
# apple/pick-simulator.py — prints the UDID of the newest available iPhone simulator (from `xcrun simctl list devices available -j` on stdin).
import sys, json
d = json.load(sys.stdin)["devices"]
cands = [(rt, dev) for rt, devs in d.items() if "iOS" in rt for dev in devs if dev.get("isAvailable") and "iPhone" in dev["name"]]
cands.sort(key=lambda x: x[0], reverse=True)
print(cands[0][1]["udid"] if cands else "")
