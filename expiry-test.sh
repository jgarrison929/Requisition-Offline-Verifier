#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Tests opt-in validity-window / expiry checks (--check-expiry and --at) in verifier/verify_offline.py:
# historical records still pass by default; expired, not-yet-valid, absent-bound and malformed-timestamp
# cases fail closed. Offline: opens no network connection and leaves this folder untouched.
# Usage: sh expiry-test.sh        Exit status 0 only if every case gets its expected answer.
set -u
cd "$(dirname "$0")" || exit 2
exec python3 -I -c '
import base64, hashlib, json, os, subprocess, sys, tempfile

# Minimal RFC 8032 Ed25519 signer (stdlib only) to build valid dev-key records with malformed or absent
# signed time bounds, so the verifier reaches the validity-window check after signature verification.
P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)

def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x

BY = 4 * pow(5, P - 2, P) % P
B = (_xrecover(BY), BY)

def _ext_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)

def _scalarmult(point, e):
    res = (0, 1, 1, 0)
    add = (point[0], point[1], 1, point[0] * point[1] % P)
    while e > 0:
        if e & 1:
            res = _ext_add(res, add)
        add = _ext_add(add, add)
        e >>= 1
    zi = pow(res[2], P - 2, P)
    return (res[0] * zi % P, res[1] * zi % P)

def _encode_point(pt):
    return (pt[1] | ((pt[0] & 1) << 255)).to_bytes(32, "little")

SEED = bytes(range(32))
_h = hashlib.sha512(SEED).digest()
_a = (int.from_bytes(_h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
_prefix = _h[32:]
PUB_RAW = _encode_point(_scalarmult(B, _a))

def ed25519_sign(msg):
    r = int.from_bytes(hashlib.sha512(_prefix + msg).digest(), "little") % Q
    R = _encode_point(_scalarmult(B, r))
    k = int.from_bytes(hashlib.sha512(R + PUB_RAW + msg).digest(), "little") % Q
    S = (r + k * _a) % Q
    return R + S.to_bytes(32, "little")

def make_dev_fixture(tmp, name, extra_metadata):
    key_id = "requisition_lab_dev_ed25519_v0"
    reg_path = os.path.join(tmp, "dev-keys.json")
    if not os.path.exists(reg_path):
        registry = {
            "schema": "requisition_lab_key_file.v1",
            "entries": [{
                "algorithm": "ed25519",
                "key_id": key_id,
                "profile": "lab",
                "public_key": base64.b64encode(PUB_RAW).decode("ascii"),
                "public_key_fingerprint": hashlib.sha256(PUB_RAW).hexdigest(),
                "signer": "dev",
                "status": "active",
                "status_changed_at": "2026-11-01T00:00:00Z",
                "valid_from": "2026-11-01T00:00:00Z",
                "valid_to": None,
            }],
        }
        with open(reg_path, "w", encoding="utf-8") as f:
            json.dump(registry, f)
    md = {
        "act_hash": "1d175c860a37ab40929be42f3294c9cdf789ff8836976120908e3ef3ea56536d0f144cf922b3f02ed1646483067128f4",
        "act_hash_alg": "sha384+canonical_payload.v3",
        "act_type": "payments.refund_send",
        "display_projection_digest": "4c126399dd08cb1d25dfcd6d9e06c1d86a0f94a4e74b04cf9417701c759461e4",
        "hands": "one-person (G-301)",
        "key_id": key_id,
        "n6_profile": "not_followed",
        "profile": "lab",
        "signer": "dev",
        "verdict": "allow",
    }
    md.update(extra_metadata)
    signed_obj = {
        "chain_scope": "requisition-lab:test",
        "metadata": md,
        "occurred_at": "2026-11-13T15:56:48Z",
        "payload_hash": None,
        "previous_hash": "0" * 64,
        "receipt_type": "requisition.lab.decision.v0",
        "schema_version": "agent_receipt.v1",
        "sequence": 1,
        "status": "recorded",
        "subject_id": "test-subject",
        "subject_type": "requisition.lab.nonce_claim",
    }
    payload = json.dumps(signed_obj, sort_keys=True, separators=(",", ":"))
    sig = base64.b64encode(ed25519_sign(payload.encode("utf-8"))).decode("ascii")
    envelope = {
        "signature": sig,
        "key_id": key_id,
        "signed_payload": payload,
        "receipt_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }
    rec_path = os.path.join(tmp, name + ".json")
    with open(rec_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f)
    return rec_path, reg_path

def run_verifier(record, registry, extra_args):
    argv = [
        sys.executable, "-I", "verifier/verify_offline.py",
        "--arguments", "record/arguments.json",
        "--act-type", "payments.refund_send",
        "--record", record,
        "--registry", registry,
        "--lab-verify", "verifier/lab-verify",
    ] + list(extra_args)
    return subprocess.run(argv, capture_output=True, text=True)

bad = 0
total = 0

def check(name, record, registry, extra_args, expect_rc, expect_substr):
    global bad, total
    total += 1
    proc = run_verifier(record, registry, extra_args)
    combined = proc.stdout + proc.stderr
    ok = proc.returncode == expect_rc and expect_substr in combined
    detail = "exit %d" % proc.returncode
    if ok:
        print("ok          %-46s -> %s" % (name, detail))
    else:
        print("UNEXPECTED  %-46s -> %s (expected exit %d containing %r)" % (name, detail, expect_rc, expect_substr))
        bad = 1

KMS_FLAGS = ["--accept-signer", "kms", "--require-pq"]

# 1. Published 13 Nov fixtures: default offline mode (no clock check) still passes
check("decision default (no expiry flag)", "record/decision.json", "record/public-keys.json",
      KMS_FLAGS, 0, "verdict: PASS")
check("statement default (no expiry flag)", "record/statement.json", "record/public-keys.json",
      KMS_FLAGS, 0, "verdict: PASS")

# 2. Published 13 Nov fixtures: --check-expiry against current UTC clock fails closed (expired)
check("decision --check-expiry (expired now)", "record/decision.json", "record/public-keys.json",
      KMS_FLAGS + ["--check-expiry"], 7, "verdict: FAIL (validity window: expired:")
check("statement --check-expiry (expired now)", "record/statement.json", "record/public-keys.json",
      KMS_FLAGS + ["--check-expiry"], 7, "verdict: FAIL (validity window: expired:")

# 3. Published 13 Nov decision: --at deterministic window checks
#    exec_not_after = 2026-11-13T15:57:48Z, not_after = 2026-11-13T15:58:48Z
check("decision --at inside window", "record/decision.json", "record/public-keys.json",
      KMS_FLAGS + ["--at", "2026-11-13T15:57:00Z"], 0, "Its signed validity window held at 2026-11-13T15:57:00Z (--at).")
check("decision --check-expiry --at inside window", "record/decision.json", "record/public-keys.json",
      KMS_FLAGS + ["--check-expiry", "--at", "2026-11-13T15:57:00Z"], 0, "verdict: PASS")
check("decision --at at exact exec_not_after", "record/decision.json", "record/public-keys.json",
      KMS_FLAGS + ["--at", "2026-11-13T15:57:48Z"], 7, "expired: exec_not_after 2026-11-13T15:57:48Z")
check("decision --at past exec_not_after before not_after", "record/decision.json", "record/public-keys.json",
      KMS_FLAGS + ["--at", "2026-11-13T15:58:00Z"], 7, "expired: exec_not_after 2026-11-13T15:57:48Z")

# 4. Published 13 Nov statement: --at deterministic window checks
#    nbf = 2026-11-13T15:56:38Z, exp = 2026-11-13T16:01:38Z
check("statement --at at exact nbf", "record/statement.json", "record/public-keys.json",
      KMS_FLAGS + ["--at", "2026-11-13T15:56:38Z"], 0, "Its signed validity window held at 2026-11-13T15:56:38Z (--at).")
check("statement --at 1s before nbf", "record/statement.json", "record/public-keys.json",
      KMS_FLAGS + ["--at", "2026-11-13T15:56:37Z"], 7, "not_yet_valid: nbf 2026-11-13T15:56:38Z")
check("statement --at at exact exp", "record/statement.json", "record/public-keys.json",
      KMS_FLAGS + ["--at", "2026-11-13T16:01:38Z"], 7, "expired: exp 2026-11-13T16:01:38Z")

# 5. Malformed --at CLI arguments -> usage error (exit 2)
for label, bad_at in [
    ("cli --at garbage", "not-a-timestamp"),
    ("cli --at 30 Feb", "2026-02-30T00:00:00Z"),
    ("cli --at hour 24", "2026-11-13T24:00:00Z"),
    ("cli --at offset +00:00", "2026-11-13T15:57:00+00:00"),
    ("cli --at fractional seconds", "2026-11-13T15:57:00.000Z"),
]:
    check(label, "record/decision.json", "record/public-keys.json",
          KMS_FLAGS + ["--at", bad_at], 2, "YYYY-MM-DDTHH:MM:SSZ")
check("cli --at given twice", "record/decision.json", "record/public-keys.json",
      KMS_FLAGS + ["--at", "2026-11-13T15:57:00Z", "--at", "2026-11-13T15:57:01Z"], 2, "usage:")

# 6. Malformed or absent signed time bounds on freshly-signed dev-key records
with tempfile.TemporaryDirectory() as tmp:
    rec, reg = make_dev_fixture(tmp, "bad-exec-not-after", {"exec_not_after": "2026-02-30T00:00:00Z", "not_after": "2026-11-13T15:58:48Z"})
    check("signed exec_not_after 30 Feb", rec, reg, ["--at", "2026-11-13T15:57:00Z"], 7, "bound_unreadable: exec_not_after")

    rec, reg = make_dev_fixture(tmp, "bad-exp-int", {"exp": 1794585698})
    check("signed exp integer (not text)", rec, reg, ["--at", "2026-11-13T15:57:00Z"], 7, "bound_unreadable: exp")

    rec, reg = make_dev_fixture(tmp, "bad-not-after-null", {"not_after": None})
    check("signed not_after null", rec, reg, ["--at", "2026-11-13T15:57:00Z"], 7, "bound_unreadable: not_after")

    rec, reg = make_dev_fixture(tmp, "bad-nbf-newline", {"nbf": "2026-11-13T15:56:38Z\n", "exp": "2026-11-13T16:01:38Z"})
    check("signed nbf trailing newline", rec, reg, ["--at", "2026-11-13T15:57:00Z"], 7, "bound_unreadable: nbf")

    rec, reg = make_dev_fixture(tmp, "no-expiry-bounds", {})
    check("no expiry bounds without flag (passes)", rec, reg, [], 0, "verdict: PASS")
    check("no expiry bounds with --at (fails closed)", rec, reg, ["--at", "2026-11-13T15:57:00Z"], 7, "validity window: expiry_absent")

if bad:
    print("RESULT: FAIL")
    sys.exit(1)
print("RESULT: PASS (%d cases, each as expected)" % total)
'
