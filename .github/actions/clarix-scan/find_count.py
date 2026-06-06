"""Print the number of findings in a SARIF file. Used by the Clarix GitHub Action."""
import json
import sys

if len(sys.argv) < 2:
    print(0)
    sys.exit(0)

try:
    with open(sys.argv[1], encoding="utf-8") as f:
        sarif = json.load(f)
    print(len(sarif.get("runs", [{}])[0].get("results", [])))
except Exception:
    print(0)
