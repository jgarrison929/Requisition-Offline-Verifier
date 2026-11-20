#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Verifies the signed statement and the signed decision in record/, checks that they are in their
# proper roles, cryptographically linked, and that the decision verdict is allow. Offline: opens no network connection.
# Usage: sh verify.sh        Exit status 0 only if both records verify and form a linked allow decision.
set -u
cd "$(dirname "$0")" || exit 2
status=0
pair_failed=0
for record in statement decision; do
  echo "######## record/$record.json"
  python3 -I verifier/verify_offline.py \
    --arguments record/arguments.json --act-type payments.refund_send \
    --record "record/$record.json" --registry record/public-keys.json \
    --lab-verify verifier/lab-verify \
    --accept-signer kms --require-pq || status=1
  echo
done
if [ "$status" -eq 0 ]; then
  echo "######## pair: record/statement.json -> record/decision.json"
  python3 -B -I -c '
import hashlib, json, sys

STATEMENT_TYPE = "requisition.lab.statement.v0"
DECISION_TYPE = "requisition.lab.decision.v0"
ENVELOPE = ("signature", "key_id", "signed_payload", "receipt_hash")
MAX_DEPTH = 64
MAX_INTEGER = 9_007_199_254_740_991

def _no_dupes(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError("duplicate member %r" % (k,))
        seen[k] = v
    return seen

def _no_const(name):
    raise ValueError("%s is not JSON" % name)

def _finite_float(lexeme):
    value = float(lexeme)
    if value in (float("inf"), float("-inf")):
        raise ValueError("a number outside the double range")
    return value

def _bounded_int(lexeme):
    value = int(lexeme)
    if not -MAX_INTEGER <= value <= MAX_INTEGER:
        raise ValueError("an integer outside +-(2^53-1)")
    return value

def _check_depth(text):
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "\"":
                in_str = False
        elif ch == "\"":
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("nesting deeper than %d" % MAX_DEPTH)
        elif ch in "]}":
            depth -= 1

def loads_strict(data):
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")
    _check_depth(data)
    return json.loads(
        data,
        object_pairs_hook=_no_dupes,
        parse_constant=_no_const,
        parse_float=_finite_float,
        parse_int=_bounded_int,
    )

def is_env(obj):
    return isinstance(obj, dict) and all(isinstance(obj.get(k), str) for k in ENVELOPE)

def load_record(path, expected_wrapper, forbidden_wrappers):
    with open(path, "rb") as handle:
        doc = loads_strict(handle.read())
    if is_env(doc):
        env = doc
    elif isinstance(doc, dict):
        bad = [k for k in forbidden_wrappers if k in doc]
        if bad:
            raise ValueError("%s carries unexpected wrapper key(s): %s" % (path, ", ".join(bad)))
        env = doc.get(expected_wrapper)
        if not is_env(env):
            raise ValueError("%s does not carry a %s envelope" % (path, expected_wrapper))
    else:
        raise ValueError("%s is not a JSON object" % path)
    digest = hashlib.sha256(env["signed_payload"].encode("utf-8")).hexdigest()
    if digest != env["receipt_hash"]:
        raise ValueError("%s receipt_hash does not match SHA-256 of signed_payload" % path)
    signed = loads_strict(env["signed_payload"])
    if not isinstance(signed, dict) or not isinstance(signed.get("metadata"), dict):
        raise ValueError("%s signed_payload is not an object with metadata" % path)
    return env, signed, signed["metadata"]

try:
    st_env, st_signed, st_md = load_record(
        "record/statement.json", "statement", ("decision", "record", "receipt")
    )
    dec_env, dec_signed, dec_md = load_record(
        "record/decision.json", "decision", ("statement", "record")
    )
except (OSError, ValueError) as error:
    print("  FAIL: %s" % error)
    print("verdict: FAIL (statement/decision pair check failed)")
    sys.exit(1)

errors = []
st_type = st_signed.get("receipt_type")
dec_type = dec_signed.get("receipt_type")
print("  statement: %s (receipt_hash %s)" % (st_type, st_env["receipt_hash"]))
print("  decision: %s (receipt_hash %s)" % (dec_type, dec_env["receipt_hash"]))

if st_type != STATEMENT_TYPE:
    errors.append("record/statement.json receipt_type is %r, expected %r" % (st_type, STATEMENT_TYPE))
if "verdict" in st_md:
    errors.append("record/statement.json carries unexpected metadata.verdict %r" % (st_md.get("verdict"),))
if dec_type != DECISION_TYPE:
    errors.append("record/decision.json receipt_type is %r, expected %r" % (dec_type, DECISION_TYPE))

dec_statement_id = dec_md.get("statement_id")
if type(dec_statement_id) is not str or not dec_statement_id or dec_statement_id != st_env["receipt_hash"]:
    errors.append("decision metadata.statement_id (%r) does not match statement receipt_hash (%r)"
                  % (dec_statement_id, st_env["receipt_hash"]))
    print("  statement_id: MISMATCH (decision %r, statement receipt_hash %r)"
          % (dec_statement_id, st_env["receipt_hash"]))
else:
    print("  statement_id: equal (%s)" % dec_statement_id)

st_act_hash, dec_act_hash = st_md.get("act_hash"), dec_md.get("act_hash")
if not (type(st_act_hash) is str and st_act_hash and st_act_hash == dec_act_hash):
    errors.append("statement and decision act_hash differ (%r vs %r)" % (st_act_hash, dec_act_hash))
    print("  act_hash: MISMATCH (statement %r, decision %r)" % (st_act_hash, dec_act_hash))
else:
    print("  act_hash: equal (%s)" % dec_act_hash)

for field in ("act_type", "act_hash_alg"):
    sv, dv = st_md.get(field), dec_md.get(field)
    if not (type(sv) is str and sv and sv == dv):
        errors.append("statement and decision %s differ (%r vs %r)" % (field, sv, dv))

if "display_digest" in st_md and "display_projection_digest" in dec_md:
    sd, dd = st_md.get("display_digest"), dec_md.get("display_projection_digest")
    if not (type(sd) is str and sd and sd == dd):
        errors.append("statement display_digest (%r) and decision display_projection_digest (%r) differ" % (sd, dd))

st_scope, dec_scope = st_signed.get("chain_scope"), dec_signed.get("chain_scope")
st_seq, dec_seq = st_signed.get("sequence"), dec_signed.get("sequence")
scope_ok = type(st_scope) is str and st_scope != "" and st_scope == dec_scope
seq_ok = type(st_seq) is int and type(dec_seq) is int and dec_seq > st_seq
prev_ok = True
if seq_ok and dec_seq == st_seq + 1:
    prev_ok = dec_signed.get("previous_hash") == st_env["receipt_hash"]
if not scope_ok:
    errors.append("statement and decision chain_scope differ (%r vs %r)" % (st_scope, dec_scope))
if not seq_ok:
    errors.append("decision sequence (%r) must be an integer greater than statement sequence (%r)" % (dec_seq, st_seq))
if not prev_ok:
    errors.append("adjacent decision previous_hash (%r) does not match statement receipt_hash (%r)"
                  % (dec_signed.get("previous_hash"), st_env["receipt_hash"]))
if scope_ok and seq_ok and prev_ok:
    adj = "; previous_hash matches statement" if dec_seq == st_seq + 1 else ""
    print("  chain_scope: equal (%s; sequence %d -> %d%s)" % (dec_scope, st_seq, dec_seq, adj))
else:
    print("  chain_scope: MISMATCH (scope %r vs %r; sequence %r -> %r)" % (st_scope, dec_scope, st_seq, dec_seq))

verdict = dec_md.get("verdict")
if type(verdict) is not str or verdict != "allow":
    errors.append("decision metadata.verdict is %r, expected \"allow\"" % (verdict,))
    print("  signed verdict: REFUSED (%r, expected \"allow\")" % (verdict,))
else:
    print("  signed verdict: allow")

if errors:
    for err in errors:
        print("  FAIL: " + err)
    print("verdict: FAIL (statement/decision pair check failed)")
    sys.exit(1)
print("verdict: PASS -- statement and decision are in their roles, cryptographically linked, and the decision verdict is allow.")
' || { status=1; pair_failed=1; }
  echo
fi
if [ "$status" -eq 0 ]; then
  echo "RESULT: PASS (both records verify)"
elif [ "$pair_failed" -eq 1 ]; then
  echo "RESULT: FAIL (statement/decision pair check failed)"
else
  echo "RESULT: FAIL (at least one record did not verify)"
fi
exit "$status"
