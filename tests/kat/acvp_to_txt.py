#!/usr/bin/env python3
"""Flatten the NIST ACVP ML-KEM JSON into "key = hex" text files for the
Ada harness (which has no JSON reader). Only ML-KEM-768 is kept."""
import json, sys, pathlib

V = pathlib.Path(sys.argv[1])
SETS = {"ML-KEM-768": "768", "ML-KEM-1024": "1024"}

def dump(path, rows, keys):
    with open(path, "w") as f:
        for t in rows:
            f.write(f"tcId = {t['tcId']}\n")
            for k in keys:
                v = t[k]
                if isinstance(v, bool):
                    v = "true" if v else "false"
                f.write(f"{k} = {v}\n")
            f.write("\n")

kg = json.load(open(V / "acvp_keygen.json"))
for g in kg["testGroups"]:
    if g["parameterSet"] in SETS:
        sfx = SETS[g["parameterSet"]]
        dump(V / f"acvp_keygen_{sfx}.txt", g["tests"], ["z", "d", "ek", "dk"])

ed = json.load(open(V / "acvp_encapdecap.json"))
for g in ed["testGroups"]:
    if g["parameterSet"] not in SETS:
        continue
    sfx = SETS[g["parameterSet"]]
    fn = g["function"]
    if fn == "encapsulation":
        dump(V / f"acvp_encap_{sfx}.txt", g["tests"], ["ek", "m", "c", "k"])
    elif fn == "decapsulation":
        dump(V / f"acvp_decap_{sfx}.txt", g["tests"], ["dk", "c", "k", "reason"])
    elif fn == "encapsulationKeyCheck":
        dump(V / f"acvp_ekcheck_{sfx}.txt", g["tests"], ["ek", "testPassed", "reason"])
    elif fn == "decapsulationKeyCheck":
        dump(V / f"acvp_dkcheck_{sfx}.txt", g["tests"], ["dk", "testPassed", "reason"])
print("acvp text files written to", V)
