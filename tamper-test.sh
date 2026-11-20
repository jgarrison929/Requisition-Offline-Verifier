#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Negative tests. Each case copies this folder, changes one thing, and expects verify.sh to FAIL.
# Offline. Leaves this folder untouched; works in a temporary directory that is removed at the end.
# Usage: sh tamper-test.sh        Exit status 0 only if the untouched copy passes and every tampered copy fails.
set -u
here=$(cd "$(dirname "$0")" && pwd) || exit 2
work=$(mktemp -d) || exit 2
trap 'rm -r "$work"' EXIT
bad=0

run_case() {  # $1 = name, $2 = expected outcome (passed|failed), $3 = python edit (may be empty)
  dir="$work/$1"
  mkdir "$dir" && cp -R "$here/record" "$here/verifier" "$here/verify.sh" "$dir/" || exit 2
  if [ -n "$3" ]; then (cd "$dir" && python3 -I -c "$3") || exit 2; fi
  if sh "$dir/verify.sh" > "$dir/output.txt" 2>&1; then got=passed; else got=failed; fi
  if [ "$got" = "$2" ]; then echo "ok          $1 -> verification ${got}, as expected"
  else echo "UNEXPECTED  $1 -> verification ${got}, expected $2"; bad=1; fi
}

edit_json='import json,base64
def load(p): return json.load(open(p))
def save(p,o): json.dump(o,open(p,"w"))
def flip(b64,i):
    raw=bytearray(base64.b64decode(b64)); raw[i]^=1; return base64.b64encode(bytes(raw)).decode()
'

run_case "untouched copy" passed ""
run_case "amount changed by one minor unit" failed "$edit_json
a=load('record/arguments.json'); a['args']['amount_minor']+=1; save('record/arguments.json',a)"
run_case "one bit flipped in the Ed25519 signature of the decision" failed "$edit_json
r=load('record/decision.json'); r['decision']['signature']=flip(r['decision']['signature'],10); save('record/decision.json',r)"
run_case "one bit flipped in the ML-DSA-87 signature of the decision" failed "$edit_json
r=load('record/decision.json'); r['cosignature']['signature']=flip(r['cosignature']['signature'],100); save('record/decision.json',r)"
run_case "one bit flipped in the Ed25519 signature of the statement" failed "$edit_json
r=load('record/statement.json'); r['statement']['signature']=flip(r['statement']['signature'],10); save('record/statement.json',r)"
run_case "one character changed in the signed payload of the decision" failed "$edit_json
r=load('record/decision.json'); p=r['decision']['signed_payload']; r['decision']['signed_payload']=p.replace('allow','deny ',1) if 'allow' in p else p[:-2]+'x'+p[-1]; save('record/decision.json',r)"
run_case "Ed25519 public key replaced by another valid key" failed "$edit_json
k=load('record/public-keys.json'); e=k['entries']; t=[x for x in e if x['signer']=='kms' and x['algorithm']=='ed25519'][0]; o=[x for x in e if x['signer']!='kms' and x['algorithm']=='ed25519'][0]
t['public_key']=o['public_key']; t['public_key_fingerprint']=o['public_key_fingerprint']; save('record/public-keys.json',k)"
run_case "Ed25519 public key replaced by the identity point, signature forged to match" failed "$edit_json
import hashlib
k=load('record/public-keys.json'); t=[x for x in k['entries'] if x['signer']=='kms' and x['algorithm']=='ed25519'][0]
ident=bytes([1])+bytes(31); t['public_key']=base64.b64encode(ident).decode(); t['public_key_fingerprint']=hashlib.sha256(ident).hexdigest(); save('record/public-keys.json',k)
B=bytes.fromhex('5866666666666666666666666666666666666666666666666666666666666666')
r=load('record/decision.json'); r['decision']['signature']=base64.b64encode(B+bytes([1])+bytes(31)).decode(); save('record/decision.json',r)"
run_case "ML-DSA-87 co-signature removed from the decision" failed "$edit_json
r=load('record/decision.json'); del r['cosignature']; save('record/decision.json',r)"

sign_local='import base64,hashlib,importlib.util,json
def _mod(name,path):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
vr=_mod("vr","verifier/verify_receipt.py")
vo=_mod("vo","verifier/verify_offline.py")
def _enc(pt): return (pt[1]|((pt[0]&1)<<255)).to_bytes(32,"little")
def make_dev_fixture(kind, include_digest=True, digest_override=None):
    seed=bytes(range(32)); h=hashlib.sha512(seed).digest()
    a=int.from_bytes(h[:32],"little"); a&=(1<<254)-8; a|=1<<254; prefix=h[32:]
    pub=_enc(vr._scalarmult(vr.B,a))
    with open("record/arguments.json") as f: args=json.load(f)
    ah=vo.act_hash("payments.refund_send",args)
    dd=vo.display_digest(args)
    md={"act_hash":ah,"act_hash_alg":"sha384+canonical_payload.v3","act_type":"payments.refund_send",
        "hands":"one-person (G-301)","key_id":"requisition_lab_dev_ed25519_v0",
        "n6_profile":"not_followed","profile":"lab","signer":"dev"}
    if kind=="requisition.lab.decision.v0":
        md["verdict"]="allow"
        member="display_projection_digest"
    else:
        member="display_digest"
    if include_digest:
        md[member]=dd if digest_override is None else digest_override
    payload_obj={"chain_scope":"requisition-lab:account:test","metadata":md,
                 "occurred_at":"2026-11-16T20:30:09Z","payload_hash":None,"previous_hash":None,
                 "receipt_type":kind,"schema_version":"agent_receipt.v1","sequence":1,
                 "status":"recorded","subject_id":"test-subject","subject_type":"requisition.lab.nonce_claim"}
    payload=vo.encode(payload_obj).decode("utf-8")
    msg=payload.encode("utf-8")
    r=int.from_bytes(hashlib.sha512(prefix+msg).digest(),"little")%vr.Q
    R=_enc(vr._scalarmult(vr.B,r))
    k=int.from_bytes(hashlib.sha512(R+pub+msg).digest(),"little")%vr.Q
    sig=R+((r+k*a)%vr.Q).to_bytes(32,"little")
    env={"signature":base64.b64encode(sig).decode(),"key_id":"requisition_lab_dev_ed25519_v0",
         "signed_payload":payload,"receipt_hash":hashlib.sha256(msg).hexdigest()}
    keys={"schema":"requisition_lab_key_file.v1","entries":[{
        "algorithm":"ed25519","key_id":"requisition_lab_dev_ed25519_v0","profile":"lab",
        "public_key":base64.b64encode(pub).decode(),"public_key_fingerprint":hashlib.sha256(pub).hexdigest(),
        "signer":"dev","status":"active","status_changed_at":"2026-11-09T00:00:00Z",
        "valid_from":"2026-11-09T00:00:00Z","valid_to":None}]}
    with open("local-record.json","w") as f: json.dump(env,f)
    with open("local-keys.json","w") as f: json.dump(keys,f)
'

run_offline_case() {  # $1 = name, $2 = expected outcome (passed|failed), $3 = expected substring (may be empty), $4 = extra verify_offline flag (may be empty), $5 = python setup
  dir="$work/$1"
  mkdir "$dir" && cp -R "$here/record" "$here/verifier" "$dir/" || exit 2
  (cd "$dir" && python3 -I -c "$5") || exit 2
  if [ -n "$4" ]; then
    python3 -I "$dir/verifier/verify_offline.py" \
      --arguments "$dir/record/arguments.json" --act-type payments.refund_send \
      --record "$dir/local-record.json" --registry "$dir/local-keys.json" \
      --lab-verify "$dir/verifier/lab-verify" "$4" > "$dir/output.txt" 2>&1
  else
    python3 -I "$dir/verifier/verify_offline.py" \
      --arguments "$dir/record/arguments.json" --act-type payments.refund_send \
      --record "$dir/local-record.json" --registry "$dir/local-keys.json" \
      --lab-verify "$dir/verifier/lab-verify" > "$dir/output.txt" 2>&1
  fi
  rc=$?
  if [ "$rc" -eq 0 ]; then got=passed; else got=failed; fi
  matched=1
  if [ -n "$3" ] && ! grep -F -q -- "$3" "$dir/output.txt"; then matched=0; fi
  if [ "$got" = "$2" ] && [ "$matched" -eq 1 ]; then echo "ok          $1 -> verification ${got}, as expected"
  else echo "UNEXPECTED  $1 -> verification ${got} (rc=$rc, expected $2${3:+, match '$3'})"; bad=1; fi
}

run_offline_case "locally signed decision with display_projection_digest" passed "display_projection_digest: equal" "" "$sign_local
make_dev_fixture('requisition.lab.decision.v0', include_digest=True)"
run_offline_case "locally signed decision missing display_projection_digest" failed "display_projection_digest: ABSENT" "" "$sign_local
make_dev_fixture('requisition.lab.decision.v0', include_digest=False)"
run_offline_case "locally signed statement missing display_digest" failed "display_digest: ABSENT" "" "$sign_local
make_dev_fixture('requisition.lab.statement.v0', include_digest=False)"
run_offline_case "locally signed decision missing display_projection_digest with opt-out flag" passed "allowed by --allow-missing-display-digest" "--allow-missing-display-digest" "$sign_local
make_dev_fixture('requisition.lab.decision.v0', include_digest=False)"
run_offline_case "locally signed decision with mismatched display_projection_digest and opt-out flag" failed "display_projection_digest: MISMATCH" "--allow-missing-display-digest" "$sign_local
make_dev_fixture('requisition.lab.decision.v0', include_digest=True, digest_override='0'*64)"

if [ "$bad" -eq 0 ]; then echo "RESULT: PASS (the untouched copy verifies; every tampered copy is refused)"; else echo "RESULT: FAIL"; fi
exit "$bad"
