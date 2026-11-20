#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Runs verifier/verify_offline.py with the log checkpoint flags over every case in checkpoint-vectors/manifest.json
# and compares each answer with the case's "expect": "ok" must exit 0 with the checkpoint's PASS sentence; a refusal
# code must exit 6 with "verdict: FAIL (the log checkpoint: <code>)". Offline: opens no network connection.
# Usage: sh checkpoint-test.sh        Exit status 0 only if every case gets its expected answer.
set -u
cd "$(dirname "$0")" || exit 2
exec python3 -I -c '
import json, os, subprocess, sys, tempfile

HOME = "checkpoint-vectors"
PASS = "It is included in a checkpoint of the evaluation environment"
try:
    with open(os.path.join(HOME, "manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
except OSError as error:
    print("cannot read %s/manifest.json: %s" % (HOME, error))
    sys.exit(2)

def at(name):
    return os.path.join(HOME, name)

def run_case(name, record, checkpoint, inclusion_proof, witness_policy, expect,
             held=None, consistency_proof=None, key_transition=None, expect_text=None):
    argv = [sys.executable, "-I", "verifier/verify_offline.py",
            "--arguments", at(manifest["arguments"]), "--act-type", manifest["act_type"],
            "--record", record, "--registry", at(manifest["registry"]),
            "--lab-verify", "verifier/lab-verify",
            "--checkpoint", checkpoint, "--inclusion-proof", inclusion_proof,
            "--witness-policy", witness_policy]
    if held is not None:
        argv += ["--held-size", str(held["size"]), "--held-root", held["root"]]
    if consistency_proof is not None:
        argv += ["--consistency-proof", consistency_proof]
    if key_transition is not None:
        argv += ["--key-transition", key_transition]
    run = subprocess.run(argv, capture_output=True, text=True)
    if expect == "ok":
        good = run.returncode == 0 and PASS in run.stdout
        got = "PASS" if good else "exit %d" % run.returncode
    elif expect == "usage":
        good = run.returncode == 2 and (expect_text is None or expect_text in run.stdout)
        got = "usage error" if good else "exit %d" % run.returncode
    else:
        good = run.returncode == 6 and ("verdict: FAIL (the log checkpoint: %s)" % expect) in run.stdout
        got = "refused, %s" % expect if good else "exit %d" % run.returncode
    print("%-11s %-38s -> %s%s" % ("ok" if good else "UNEXPECTED", name, got,
                                  "" if good else " (expected %s)" % expect))
    return good

bad = 0
for case in manifest["cases"]:
    good = run_case(
        case["name"], at(case["record"]), at(case["checkpoint"]), at(case["inclusion_proof"]),
        at(case["witness_policy"]), case["expect"], held=case["held"],
        consistency_proof=at(case["consistency_proof"]) if case["consistency_proof"] is not None else None,
        key_transition=at(case["key_transition"]) if case["key_transition"] is not None else None,
    )
    bad = bad or not good

with open(at("policies/main.policy"), encoding="utf-8") as handle:
    main_policy = handle.read()
w1_line = next(line for line in main_policy.splitlines() if line.startswith("witness w1 "))
w1_alias = w1_line.replace("witness w1 ", "witness w1b ", 1)

quorum_cases = [
    ("quorum-direct-duplicate",
     main_policy.replace("group quorum-group 2 w1 w2 w3", "group quorum-group 2 w1 w1"),
     "notes/b.one-witness", "usage", "a member is repeated"),
    ("quorum-nested-duplicate",
     main_policy.replace("group quorum-group 2 w1 w2 w3", "group inner 1 w1\ngroup quorum-group 2 inner inner"),
     "notes/b.one-witness", "usage", "a member is repeated"),
    ("quorum-shared-witness-subgroups",
     main_policy.replace("group quorum-group 2 w1 w2 w3", "group g1 1 w1\ngroup g2 1 w1\ngroup quorum-group 2 g1 g2"),
     "notes/b.one-witness", "checkpoint_quorum_not_met", None),
    ("quorum-overlapping-subgroups-one",
     main_policy.replace("group quorum-group 2 w1 w2 w3",
                         "group g1 1 w1 w2\ngroup g2 1 w1 w3\ngroup quorum-group 2 g1 g2"),
     "notes/b.one-witness", "checkpoint_quorum_not_met", None),
    ("quorum-overlapping-subgroups-two",
     main_policy.replace("group quorum-group 2 w1 w2 w3",
                         "group g1 1 w1 w2\ngroup g2 1 w1 w3\ngroup quorum-group 2 g1 g2"),
     "notes/b.cosigned", "ok", None),
    ("quorum-aliased-witness-key",
     main_policy.replace("group quorum-group 2 w1 w2 w3", w1_alias + "\ngroup quorum-group 2 w1 w1b"),
     "notes/b.one-witness", "checkpoint_quorum_not_met", None),
]

with tempfile.TemporaryDirectory() as tmp:
    for name, policy_text, note_path, expect, expect_text in quorum_cases:
        policy_path = os.path.join(tmp, name + ".policy")
        with open(policy_path, "w", encoding="utf-8") as handle:
            handle.write(policy_text)
        good = run_case(
            name, at("records/main-1.json"), at(note_path), at("proofs/inclusion-main-1-at-7.json"),
            policy_path, expect, expect_text=expect_text,
        )
        bad = bad or not good

all_expects = [case["expect"] for case in manifest["cases"]] + [case[3] for case in quorum_cases]
total = len(all_expects)
passes = sum(1 for e in all_expects if e == "ok")
usages = sum(1 for e in all_expects if e == "usage")
refused = total - passes - usages
if bad:
    print("RESULT: FAIL")
else:
    print("RESULT: PASS (%d cases: %d pass, %d refused by name, %d usage error, each as expected)"
          % (total, passes, refused, usages))
sys.exit(1 if bad else 0)
'
