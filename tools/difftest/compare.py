#!/usr/bin/env python3
import argparse, json, sys
def idx(d): return {h["input"]: h for h in d.get("hosts", [])}
ap = argparse.ArgumentParser(); ap.add_argument("a"); ap.add_argument("b"); ap.add_argument("--fail-on-verdict-mismatch", action="store_true")
a = ap.parse_args()
A, B = idx(json.load(open(a.a))), idx(json.load(open(a.b)))
m = 0
for h in sorted(set(A)|set(B)):
    if h not in A: print("ONLY_B", h); m += 1
    elif h not in B: print("ONLY_A", h); m += 1
    elif A[h].get("verdict") != B[h].get("verdict"):
        print("MISMATCH", h, A[h].get("verdict"), "vs", B[h].get("verdict")); m += 1
print("total_mismatches", m)
sys.exit(1 if a.fail_on_verdict_mismatch and m else 0)
