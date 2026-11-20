#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Tests strict AWS KMS key ARN parsing and key-file kms_key_arn pinning wording in verifier/lab-verify and
# verifier/verify_offline.py. Offline; leaves this folder untouched and works in a temporary directory.
# Usage: sh kms-arn-test.sh        Exit status 0 only if every case gets its expected answer.
set -u
cd "$(dirname "$0")" || exit 2
exec python3 -I -c '
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return (x1 * y2 + x2 * y1) * pow(1 + t, -1, P) % P, (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P


def _mul(pt, n):
    r = (0, 1)
    while n:
        if n & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        n >>= 1
    return r


def _enc(pt):
    return (pt[1] | ((pt[0] & 1) << 255)).to_bytes(32, "little")


def keypair(seed):
    h = hashlib.sha512(seed).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    return a, h[32:], _enc(_mul(B, a))


def sign(a, prefix, pub, msg):
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    R = _enc(_mul(B, r))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % L
    return R + ((r + k * a) % L).to_bytes(32, "little")


BASE_DECISION = json.load(open("record/decision.json", encoding="utf-8"))
BASE_KEYS = json.load(open("record/public-keys.json", encoding="utf-8"))
BASE_SIGNED = json.loads(BASE_DECISION["decision"]["signed_payload"])
ACT_HASH = BASE_SIGNED["metadata"]["act_hash"]
ED_RES = "303190ba-5445-49ec-9d8c-95b804b8c5cf"
PQ_RES = "fd9cf1e7-608c-4f34-b5fe-cdf4cc37620d"
ED_ARN = "arn:aws:kms:us-east-2:847072440326:key/" + ED_RES
PQ_ARN = "arn:aws:kms:us-east-2:847072440326:key/" + PQ_RES

PRIV_A, PRIV_PREFIX, PUB_BYTES = keypair(b"kms-arn-test-seed-00000000000001")
PUB_B64 = base64.b64encode(PUB_BYTES).decode()
PUB_FP = hashlib.sha256(PUB_BYTES).hexdigest()


def make_signed_record(resource, arn, cosign=None):
    kid = "requisition_lab_kms_ed25519_" + resource
    signed = copy.deepcopy(BASE_SIGNED)
    signed["metadata"]["key_id"] = kid
    signed["metadata"]["kms_key_arn"] = arn
    if cosign is None:
        signed["metadata"].pop("cosign", None)
    else:
        signed["metadata"]["cosign"] = cosign
    payload = json.dumps(signed, separators=(",", ":"), sort_keys=True)
    sig = sign(PRIV_A, PRIV_PREFIX, PUB_BYTES, payload.encode("utf-8"))
    env = {
        "key_id": kid,
        "signed_payload": payload,
        "receipt_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "signature": base64.b64encode(sig).decode(),
    }
    return kid, env


def make_registry(kid, pinned_arn=None, extra_entries=()):
    entry = {
        "algorithm": "ed25519",
        "key_id": kid,
        "profile": "lab",
        "signer": "kms",
        "public_key": PUB_B64,
        "public_key_fingerprint": PUB_FP,
        "status": "active",
        "status_changed_at": "2026-11-13T15:37:39Z",
        "valid_from": "2026-11-13T15:37:39Z",
        "valid_to": None,
    }
    if pinned_arn is not None:
        entry["kms_key_arn"] = pinned_arn
    return {"schema": "requisition_lab_key_file.v1", "entries": [entry] + list(extra_entries)}


def run_offline(work, name, rec_obj, reg_obj, extra_args=()):
    rec_p = os.path.join(work, name + ".rec.json")
    reg_p = os.path.join(work, name + ".keys.json")
    with open(rec_p, "w", encoding="utf-8") as fh:
        json.dump(rec_obj, fh)
    with open(reg_p, "w", encoding="utf-8") as fh:
        json.dump(reg_obj, fh)
    return subprocess.run(
        [
            sys.executable, "-I", "verifier/verify_offline.py",
            "--arguments", "record/arguments.json", "--act-type", "payments.refund_send",
            "--record", rec_p, "--registry", reg_p,
            "--lab-verify", "verifier/lab-verify", "--accept-signer", "kms",
        ] + list(extra_args),
        capture_output=True, text=True,
    )


def run_lab_verify(work, name, env, reg_obj):
    rec_p = os.path.join(work, name + ".env.json")
    reg_p = os.path.join(work, name + ".keys.json")
    with open(rec_p, "w", encoding="utf-8") as fh:
        json.dump(env, fh)
    with open(reg_p, "w", encoding="utf-8") as fh:
        json.dump(reg_obj, fh)
    return subprocess.run(
        [
            sys.executable, "-I", "verifier/lab-verify",
            "--receipt", rec_p, "--registry", reg_p,
            "--act-hash", ACT_HASH, "--accept-signer", "kms",
        ],
        capture_output=True, text=True,
    )


bad = 0
total = 0


def check(name, cond, detail):
    global bad, total
    total += 1
    if cond:
        print("ok          %-46s -> %s" % (name, detail))
    else:
        print("UNEXPECTED  %-46s -> %s" % (name, detail))
        bad = 1


with tempfile.TemporaryDirectory() as work:
    # 1. Malformed / alias-injected signed metadata.kms_key_arn must be refused by lab-verify and verify_offline.py.
    malformed = [
        ("alias-injected colon suffix", ED_RES, "arn:aws:kms:eu-west-1:999999999999:alias/not-a-key:key/" + ED_RES),
        ("trailing colon suffix", ED_RES, ED_ARN + ":extra"),
        ("alias resource instead of key", ED_RES, "arn:aws:kms:us-east-2:847072440326:alias/" + ED_RES),
        ("unknown partition", ED_RES, "arn:evil:kms:us-east-2:847072440326:key/" + ED_RES),
        ("wrong service", ED_RES, "arn:aws:iam:us-east-2:847072440326:key/" + ED_RES),
        ("uppercase region", ED_RES, "arn:aws:kms:US-EAST-2:847072440326:key/" + ED_RES),
        ("availability zone as region", ED_RES, "arn:aws:kms:us-east-2a:847072440326:key/" + ED_RES),
        ("empty region", ED_RES, "arn:aws:kms::847072440326:key/" + ED_RES),
        ("short account id", ED_RES, "arn:aws:kms:us-east-2:12345:key/" + ED_RES),
        ("non-digit account id", ED_RES, "arn:aws:kms:us-east-2:84707244032a:key/" + ED_RES),
        ("extra path segment in resource", ED_RES, "arn:aws:kms:us-east-2:847072440326:key/other/key/" + ED_RES),
        ("slash inside key_id resource", "a/b", "arn:aws:kms:us-east-2:847072440326:key/a/b"),
    ]
    for i, (label, res, arn) in enumerate(malformed):
        kid, env = make_signed_record(res, arn)
        reg = make_registry(kid)
        lv = run_lab_verify(work, "mal_%d" % i, env, reg)
        off = run_offline(work, "mal_off_%d" % i, {"decision": env}, reg)
        lv_ok = lv.returncode == 1 and "verdict_code: lab_kms_key_arn_mismatch" in lv.stderr
        off_ok = off.returncode == 3 and "verdict: FAIL" in off.stdout
        check("reject " + label, lv_ok and off_ok,
              "refused (lab-verify exit %d, verify_offline exit %d)" % (lv.returncode, off.returncode))

    # 2. Malformed / alias-injected co-signature cosign.kms_key_arn must be refused by verify_offline.py (exit 4).
    pq_kid = "requisition_lab_kms_mldsa87_" + PQ_RES
    bad_cosign_arn = "arn:aws:kms:eu-west-1:999999999999:alias/not-a-key:key/" + PQ_RES
    cosign_md = {"algorithm": "mldsa87", "key_id": pq_kid, "kms_key_arn": bad_cosign_arn, "signer": "kms", "status": "signed"}
    kid, env = make_signed_record(ED_RES, ED_ARN, cosign=cosign_md)
    dummy_pq_pub = b"\x00" * 2592
    pq_entry = {
        "algorithm": "mldsa87", "key_id": pq_kid, "profile": "lab", "signer": "kms",
        "public_key": base64.b64encode(dummy_pq_pub).decode(),
        "public_key_fingerprint": hashlib.sha256(dummy_pq_pub).hexdigest(),
        "status": "active", "status_changed_at": "2026-11-13T15:37:39Z",
        "valid_from": "2026-11-13T15:37:39Z", "valid_to": None,
    }
    cosig_env = {
        "key_id": pq_kid,
        "signed_payload": env["signed_payload"],
        "receipt_hash": env["receipt_hash"],
        "signature": base64.b64encode(b"\x00" * 4627).decode(),
    }
    off = run_offline(work, "bad_cosig_arn", {"decision": env, "cosignature": cosig_env},
                      make_registry(kid, extra_entries=[pq_entry]), ["--require-pq"])
    check("reject alias-injected cosign kms_key_arn",
          off.returncode == 4 and "not a valid AWS KMS key ARN" in off.stdout,
          "verify_offline exit %d" % off.returncode)

    # 3. Valid alternate AWS partition/region and multi-region key id are accepted.
    mrk_res = "mrk-0123456789abcdef0123456789abcdef"
    gov_arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/" + mrk_res
    kid, env = make_signed_record(mrk_res, gov_arn)
    off = run_offline(work, "valid_gov_mrk", {"decision": env}, make_registry(kid))
    check("accept aws-us-gov mrk ARN (unpinned)",
          off.returncode == 0
          and "the key file given pins as AWS KMS" not in off.stdout
          and "the key file pins as AWS KMS" not in off.stdout
          and "the key file does not pin kms_key_arn" in off.stdout,
          "verify_offline exit %d" % off.returncode)

    # 4. Real record with unmodified key file (no kms_key_arn fields): PASS without claiming pinned.
    off_unpinned = run_offline(work, "real_unpinned", BASE_DECISION, BASE_KEYS, ["--require-pq"])
    check("unpinned wording when key file lacks kms_key_arn",
          off_unpinned.returncode == 0
          and "the key file given pins as AWS KMS" not in off_unpinned.stdout
          and "the key file pins as AWS KMS" not in off_unpinned.stdout
          and "the key file does not pin kms_key_arn" in off_unpinned.stdout,
          "verify_offline exit %d" % off_unpinned.returncode)

    # 5. Real record with matching kms_key_arn pinned on both key file entries: PASS claiming pinned.
    both_pinned = copy.deepcopy(BASE_KEYS)
    for e in both_pinned["entries"]:
        if e["key_id"].endswith(ED_RES):
            e["kms_key_arn"] = ED_ARN
        elif e["key_id"].endswith(PQ_RES):
            e["kms_key_arn"] = PQ_ARN
    off_pinned = run_offline(work, "real_both_pinned", BASE_DECISION, both_pinned, ["--require-pq"])
    check("pinned wording when key file pins kms_key_arn",
          off_pinned.returncode == 0
          and ("the key file given pins as AWS KMS key " + ED_ARN) in off_pinned.stdout
          and ("the key file pins as AWS KMS keys " + ED_ARN + ", " + PQ_ARN) in off_pinned.stdout
          and "does not pin kms_key_arn" not in off_pinned.stdout,
          "verify_offline exit %d" % off_pinned.returncode)

    # 6. Mixed pinning (Ed25519 entry pins kms_key_arn, ML-DSA-87 entry does not): PASS without claiming PQ is pinned.
    ed_only_pinned = copy.deepcopy(BASE_KEYS)
    for e in ed_only_pinned["entries"]:
        if e["key_id"].endswith(ED_RES):
            e["kms_key_arn"] = ED_ARN
    off_mixed = run_offline(work, "real_mixed_pinned", BASE_DECISION, ed_only_pinned, ["--require-pq"])
    check("mixed pinning wording (Ed25519 pinned, PQ not)",
          off_mixed.returncode == 0
          and ("the key file given pins as AWS KMS key " + ED_ARN) in off_mixed.stdout
          and ("the key file pins as AWS KMS keys " + ED_ARN + ", " + PQ_ARN) not in off_mixed.stdout
          and "the key file does not pin kms_key_arn" in off_mixed.stdout,
          "verify_offline exit %d" % off_mixed.returncode)

    # 7. Pinned kms_key_arn mismatch on Ed25519 entry (different account/region, same key id) -> refused.
    ed_mismatch = copy.deepcopy(both_pinned)
    for e in ed_mismatch["entries"]:
        if e["key_id"].endswith(ED_RES):
            e["kms_key_arn"] = "arn:aws:kms:eu-west-1:999999999999:key/" + ED_RES
    off_ed_mm = run_offline(work, "real_ed_pin_mismatch", BASE_DECISION, ed_mismatch, ["--require-pq"])
    check("refuse Ed25519 pinned kms_key_arn mismatch",
          off_ed_mm.returncode == 3 and "verdict_code: lab_kms_key_arn_mismatch" in off_ed_mm.stdout,
          "verify_offline exit %d" % off_ed_mm.returncode)

    # 8. Pinned kms_key_arn mismatch on ML-DSA-87 co-signing entry -> refused (exit 4).
    pq_mismatch = copy.deepcopy(both_pinned)
    for e in pq_mismatch["entries"]:
        if e["key_id"].endswith(PQ_RES):
            e["kms_key_arn"] = "arn:aws:kms:eu-west-1:999999999999:key/" + PQ_RES
    off_pq_mm = run_offline(work, "real_pq_pin_mismatch", BASE_DECISION, pq_mismatch, ["--require-pq"])
    check("refuse ML-DSA-87 pinned kms_key_arn mismatch",
          off_pq_mm.returncode == 4 and "pinned kms_key_arn" in off_pq_mm.stdout,
          "verify_offline exit %d" % off_pq_mm.returncode)

    # 9. Non-string pinned kms_key_arn in key file entry -> refused.
    bad_type = copy.deepcopy(both_pinned)
    for e in bad_type["entries"]:
        if e["key_id"].endswith(ED_RES):
            e["kms_key_arn"] = 12345
    off_bad_type = run_offline(work, "real_bad_pin_type", BASE_DECISION, bad_type, ["--require-pq"])
    check("refuse non-string pinned kms_key_arn in entry",
          off_bad_type.returncode == 3 and "verdict_code: lab_kms_key_arn_mismatch" in off_bad_type.stdout,
          "verify_offline exit %d" % off_bad_type.returncode)

if bad:
    print("RESULT: FAIL")
else:
    print("RESULT: PASS (%d cases, each as expected)" % total)
sys.exit(1 if bad else 0)
'
