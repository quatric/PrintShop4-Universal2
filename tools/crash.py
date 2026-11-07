"""Print the crashing thread of the newest PS4.arm64 crash report."""
import glob
import json
import os
import sys

files = sorted(glob.glob(os.path.expanduser("~/Library/Logs/DiagnosticReports/PS4.arm64-*.ips")), key=os.path.getmtime)
f = sys.argv[1] if len(sys.argv) > 1 else files[-1]
d = json.loads(open(f).read().split("\n", 1)[1])
print(f, d.get("exception", {}).get("type"), d.get("exception", {}).get("subtype"), d.get("termination", {}).get("indicator"))
th = [x for x in d["threads"] if x.get("triggered")][0]
imgs = d["usedImages"]
for fr in th["frames"][:int(os.environ.get("N", 24))]:
    print(" ", fr.get("symbol", "?"), "+", fr.get("symbolLocation", ""), os.path.basename(imgs[fr["imageIndex"]].get("name", "")))
