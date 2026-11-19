# Offline test notes

Tested the public verifier in this checkout. The documented suite passes. The cryptographic checks that were tried (bit flips, swapped signatures, a forged identity-key signature, a changed amount, a non-normalized reason) fail closed. The gaps are about what a pass is allowed to mean: the one command does not require a statement plus a linked allow decision, it does not enforce two approvers, and it does not look at the expiry fields the records already carry.

Nothing in this file changes the verifier. Throwaway keys and mutated copies stayed in a temp directory and were not committed.

## How tested

Environment, 2026-11-19:

- Linux x86_64, Python 3.12.3 (one of the two versions the README names as tested). Locale `en_US.UTF-8`.
- OpenSSL 3.0.13 was used only to mint a throwaway Ed25519 key for policy checks. It was not used on the published signatures, and no AWS, KMS, or other signing service was called.
- Go 1.22.2, Node v22.23.4, and Java 21.0.13 are installed. Elixir and `mix` are not. `strace` is not installed, so the README's `strace -e trace=network` claim was not repeated with `strace`.
- Scripts were read before they were run. `verify.sh`, `tamper-test.sh`, `checkpoint-test.sh`, and `interop/run-all.sh` do not open a network connection. `run-all.sh` skips a verifier whose tool is missing and does not download it.

Network check: `verify.sh` and `checkpoint-test.sh` were run with `LD_PRELOAD` set to a small library that logs every libc `socket()` and makes `connect()` fail. Both stderr logs were empty (0 bytes). `verify.sh` still matched `expected-output.txt` and exited 0. `checkpoint-test.sh` still exited 0. That is evidence those two processes did not call `socket()`. It is not a system-call trace of every child.

### Documented suite

| Command | Exit | Result |
|---|---|---|
| `sh verify.sh` | 0 | Last line `RESULT: PASS (both records verify)`. `diff -q expected-output.txt` against that stdout reported the files identical. |
| `sha256sum -c SHA256SUMS` | 0 | 116 files `OK`, 0 `FAILED`. `SHA256SUMS` itself is not a line in that file (117 tracked files). |
| `sh tamper-test.sh` | 0 | all 9 cases `ok` (untouched copy passes, eight tampered copies refused). Last line `RESULT: PASS (the untouched copy verifies; every tampered copy is refused)`. |
| `sh checkpoint-test.sh` | 0 | all 32 cases `ok`. Last line `RESULT: PASS (32 cases: 6 pass, 26 refused by name, each as expected)`. |
| `python3 -B -I tools/check-licence.py` | 0 | `licence and pins: PASS` |
| `python3 -B interop/build-cases.py --check` | 0 | `interop/cases.tsv equals the cases derived from record/ and interop/vectors/` |
| `interop/run-all.sh` | 0 | `mldsa-py 1.0.1 (sha256 0e8885d01ed76919, Python 3.12.3): 260 cases, 0 disagree with the expected result []`. The other eight verifiers printed `SKIPPED` (their libraries are not installed). `verifiers run: 1, with a disagreement or an error: 0`. |

Go harness, not part of the pass above. From `interop/verifiers/go-crypto-mldsa`, with `GOPROXY=off` and `GOTOOLCHAIN=local` so Go would not download a toolchain:

```
go: go.mod requires go >= 1.27 (running go 1.22.2; GOTOOLCHAIN=local)
```

Exit 1. The harness README already says to point `GO_BIN` at a checked Go 1.27.4 tarball. That tarball was not downloaded here, so the Go result was not reproduced. Elixir `mix test` was not run because `elixir` and `mix` are absent.

### What was refused correctly

These were copies under `/tmp`. The published tree was not modified.

- Amount changed by one minor unit, one bit flipped in either signature of either record, one character changed in the decision payload, Ed25519 public key replaced, identity-point public key with a forged signature, ML-DSA co-signature removed: `tamper-test.sh`, exit 0, each tampered copy refused.
- Ed25519 signatures swapped between `record/statement.json` and `record/decision.json`: `sh verify.sh` exit 1, `lab-verify exit 1, verdict_code signature_invalid`, `RESULT: FAIL`.
- The two `cosignature` objects swapped: exit 1, `co-signature: does NOT cover the record's own bytes`, `RESULT: FAIL`.
- `args.reason` set to `duplicate charge` plus U+0301: exit 1, `act_hash: MISMATCH` and `display_digest: MISMATCH`, `RESULT: FAIL`. No Unicode normalization is applied, which is the safe direction.
- Duplicate JSON member in `arguments.json`: exit 1, `binding: UNREADABLE (duplicate member)`, no traceback.
- `decision.json` replaced by `{`, empty `statement.json`, a leading UTF-8 BOM, `amount_minor` written as `1250.0`, and an 80-deep array: each exit 1 with `binding: UNREADABLE (...)` and `verdict: FAIL`. No traceback.
- `--act-type` set to `payménts` under `LC_ALL=C` and under `LC_ALL=C.UTF-8`: both exit 1 with `act_type: MISMATCH` and `verdict: FAIL`. No locale crash on this Python.
- Argument key order reversed (same values): `sh verify.sh` exit 0. The canonical encoder sorts keys, so this is a pass, not a hole.
- `hands` set to `two-account, two-passkey (G-301)` with the same sanctioner twice: exit 3, `verdict_code: lab_hands_unsupported`. The stronger label does refuse a duplicate. See the next section for the label the published records actually use.
- The same throwaway record with `--require-pq` and no ML-DSA signature: exit 4, `post-quantum REQUIRED (--require-pq): NOT MET`. `verify.sh`'s flag still fails closed when the post-quantum signature is missing.

The throwaway records below were signed with a local Ed25519 key (public key SHA-256 `e35b9e19f9c6449fbc867a6ff145eb8722003fdd18ce6ad50c63c8ce90001500`), placed alone in a temp key file as `signer: kms` with a lab KMS key id. They are not the published AWS KMS keys, and they are not evidence that a published signature can be forged. They show which checks the program applies after a signature it can verify.

## Bugs

### 1. `verify.sh` passes a bundle that has no decision

**Why it matters.** The script's header says it verifies the statement and the decision. The last line and exit 0 are what someone will automate. Replacing the decision with a second copy of the statement removes the `allow` and still prints `RESULT: PASS`. Swapping the two files does the same. The README already says each record is judged on its own (`README.md`, "One record is judged at a time"). This is the one command not checking that the two paths are those two roles.

**Evidence.** Temp copy of `record/`, `verifier/`, and `verify.sh`. Then `cp record/statement.json record/decision.json` and `sh verify.sh`:

```
EXIT: 0
signed verdict: none (a requisition.lab.statement.v0, not a decision)
RESULT: PASS (both records verify)
```

That `signed verdict: none` line is printed for both paths. The same exit 0 and `RESULT: PASS` happen when both files are `decision.json`, and when the two files are exchanged (`statement.json` then prints `signed verdict: allow` and `decision.json` prints `signed verdict: none`).

`verify.sh` lines 9-18 only remember whether `python3` exited 0. `envelope_of` in `verifier/verify_offline.py` (the loop at lines 555-557) accepts whichever of `decision`, `statement`, or `record` is present. Nothing then checks that one file is `requisition.lab.statement.v0`, the other is `requisition.lab.decision.v0`, that the decision's `statement_id` equals the statement's `receipt_hash`, or that the decision's `previous_hash` does too.

On the published files those links do hold. They are not what the command checks:

```
statement.receipt_hash be1414f11f885ab2de74fb8a0f37c7d923f7e8f9b5438d1fdc8d81c352db164a
decision.statement_id  be1414f11f885ab2de74fb8a0f37c7d923f7e8f9b5438d1fdc8d81c352db164a
decision.previous_hash be1414f11f885ab2de74fb8a0f37c7d923f7e8f9b5438d1fdc8d81c352db164a
```

**Effort.** Small. After both invocations, require the two receipt types, `verdict` `allow` on the decision, and `statement_id` plus `previous_hash` equal to the statement's `receipt_hash`.

**Priority.** High.

### 2. Two approvers are not checked, and the published decision names none

**Why it matters.** The README's account of the run says two separate accounts approved, neither of them the requester's. A pass of `verify.sh` does not establish that. Both published records are signed `hands: one-person (G-301)`. For that value, `check_hands` returns before it looks at sanctioners. The decision does not carry `sanctioners` at all, and `verify.sh` still exits 0.

**Evidence.** Published bytes:

```
statement.hands one-person (G-301)
statement.sanctioners ['d4cbec5b-cba2-44ae-b9b4-94795a00735f', '517c6d9d-26d6-4d96-9633-5b88998eea6a']
statement.principal rqp_fb3ce799775da309383baec33f3c8e7f
decision.hands one-person (G-301)
decision has sanctioners False
decision.verdict allow
```

`sh verify.sh` on those files exits 0 (see the suite above). The success output never prints the sanctioners.

`verifier/lab-verify` lines 185-188 define `HANDS_VALUES[0]` as `one-person (G-301)`. Lines 760-762:

```
if hands == HANDS_VALUES[0]:
    return
```

The distinctness check below that (lines 763-767) runs only for the other label.

A locally signed decision with `hands` `one-person (G-301)`, `sanctioners` `["same-person", "same-person"]`, `principal` `same-person`, `exp` / `not_after` / `exec_not_after` all `2000-01-01T00:00:00Z`, and `statement_id` `not-the-real-statement`, run as:

```
python3 -I verifier/verify_offline.py --arguments arguments.json --act-type payments.refund_send \
  --record one-person-duplicate-sanctioners.json --registry registry.json \
  --lab-verify verifier/lab-verify --accept-signer kms
```

Exit 0, `signed verdict: allow`, `verdict: PASS`. The same file with `--require-pq` exits 4, so this is not a bypass of `verify.sh`'s post-quantum flag. It is the hands check the published records exercise, because they use the `one-person` label.

The stronger label works. The same shape with `two-account, two-passkey (G-301)` and a duplicated sanctioner exits 3 with `lab_hands_unsupported`. Two distinct sanctioners, one of them equal to `principal`, exit 0, and the output says `it shows two accounts, NOT that two people held them`. That sentence is accurate and is also the gap: the requester can be one of the two accounts, and the program still passes.

**Effort.** Medium. Decide the rule (both records carry the same two sanctioners, distinct, and disjoint from `principal` / `caller_id`), and apply it even when `hands` is `one-person`. The published decision would need a new signature if the producer starts including sanctioners there. The checker change itself is local.

**Priority.** High.

### 3. A missing display digest is still a pass

**Why it matters.** README check 1 says the verifier recomputes the digest of what the approvers were shown and compares it with the signed digest. If that member is absent, the comparison is skipped and the record can still pass. The published records include the member, so this run's `verify.sh` is fine. A later record can drop it.

**Evidence.** `verifier/verify_offline.py` lines 688-691 append the digest to the checks only when `digest_member in md`. Otherwise they print that it is not signed and leave `ok` unchanged.

Locally signed decision with no `display_projection_digest`, same command shape as bug 2, without `--require-pq`:

```
EXIT: 0
display_projection_digest: not signed in this record (the act_hash above binds every argument)
verdict: PASS
```

The act hash was equal. The display digest was not checked.

**Effort.** Small. If the member is absent, fail the binding.

**Priority.** Medium.

### 4. The KMS ARN check is a suffix match, and the pass line attributes it to the key file

**Why it matters.** The success line says the key file pins an ARN. The key file entries for the published KMS keys have no `kms_key_arn` field (the ARN is only inside the free-text `note` and inside the signed bytes). The structured check is: the string starts with `arn:`, its service component is `kms`, and it ends with `:key/` plus the resource id taken from `key_id`. An alias-shaped string that merely ends that way is accepted and then printed as if the key file had pinned it.

**Evidence.** `verifier/lab-verify` `check_kms_key`, lines 623-628. `verifier/verify_offline.py` lines 918-941 put `signed_md["kms_key_arn"]` into the sentence "the key file pins as AWS KMS keys".

Locally signed decision whose `kms_key_arn` is `arn:aws:kms:eu-west-1:999999999999:alias/not-a-key:key/00112233-4455-6677-8899-aabbccddeeff` (the key id's resource is that UUID), same command shape, without `--require-pq`:

```
EXIT: 0
DEGRADED (lab): signed by a lab key the key file given pins as AWS KMS key arn:aws:kms:eu-west-1:999999999999:alias/not-a-key:key/00112233-4455-6677-8899-aabbccddeeff
verdict: PASS -- ... the key file pins as AWS KMS keys arn:aws:kms:eu-west-1:999999999999:alias/not-a-key:key/00112233-4455-6677-8899-aabbccddeeff
```

This does not forge a published signature. Whoever holds the private key can choose the account, the region, and extra path segments. The published records use ordinary `arn:aws:kms:us-east-2:847072440326:key/...` values, and those still verify.

**Effort.** Small. Require `arn:aws:kms:<region>:<account>:key/<resource>` with no extra components, and print an ARN as pinned only when the key file has that field and it matches.

**Priority.** Medium.

## Enhancements

### Check `exp`, `not_after`, and `exec_not_after`

**Why it matters.** The decision's execution window is about a minute (`occurred_at` `2026-11-13T15:56:48Z`, `exec_not_after` `2026-11-13T15:57:48Z`, `not_after` `2026-11-13T15:58:48Z`). The statement's `exp` is `2026-11-13T16:01:38Z`. `sh verify.sh` on 2026-11-19 still exits 0. A refund approval that was only good for a minute verifies forever. The README already says the verifier does not compare signed times with the current time, so this is a request to add the check, not a claim that the limit was hidden.

**Evidence.** The field values above, and `sh verify.sh` exit 0 on 2026-11-19 (`date -u` was `2026-11-19T23:38:47Z` during this run). The throwaway record in bug 2 also passed with those three fields set to `2000-01-01T00:00:00Z`.

**Effort.** Small for a flag such as `--now` (default: the system clock, with an explicit `--historical` for these records). The README's limit paragraph would need a matching sentence.

**Priority.** High as a feature, because the fields are already inside the signature. Not a silent bug relative to the current README.

### Make exit 0 mean the decision was `allow`

**Why it matters.** `lab-verify` prints `the exit code does not tell an allow from a deny`, and `verify.sh` turns any Python exit 0 into `RESULT: PASS`. A signed `deny` is a pass.

**Evidence.** Locally signed decision with `verdict` `deny`, no sanctioners, `hands` `one-person (G-301)`, command as in bug 2, without `--require-pq`:

```
EXIT: 0
signed verdict: deny
signed verdict: deny (the record's own; the exit code does not tell an allow from a deny)
verdict: PASS
```

**Effort.** Small on `verify.sh`: require the decision's signed verdict to be `allow` (or whatever set of verdicts should count as approval). The inner program can keep its current exit for people who want the signature-only answer.

**Priority.** High for the one command. The inner behavior is already documented in its own output.

### Ship a log checkpoint for the 13 November records, and run it from `verify.sh`

**Why it matters.** Check 4 is the only check that says the record is in the evaluation log under a witnessed checkpoint. `verify.sh` does not run it, and this repository has no checkpoint for these two records. The 32 passing and failing vectors use a different development key, not the AWS KMS keys named in `record/public-keys.json`. A pass today shows the two signatures and the argument binding. It does not show inclusion in the log.

**Evidence.** `README.md` line 92 states both facts. `sh checkpoint-test.sh` exits 0 on the 32 lab vectors (6 pass, 26 refused by name). Those vectors are not the 13 November statement and decision.

**Effort.** Medium, and only the evaluation environment can produce the real checkpoint, the inclusion proof, and the witness cosignatures. The verifier side is the flags that already exist.

**Priority.** High as a feature. The absence is already written down. It is not described as scheduled.

### Re-derive `hands`, or stop signing `one-person` for a two-account approval

**Why it matters.** Bug 2 is the checker half. The producer half is that these records were signed with the label that skips the check, while the statement happens to contain two distinct sanctioner ids. A reader of the JSON sees two ids. The verifier is required, by its own comment, never to upgrade the label (`verifier/lab-verify` lines 753-757).

**Evidence.** The same lines as bug 2, plus the published `hands` value.

**Effort.** Depends on the producer. The checker side is bug 2.

**Priority.** High, together with bug 2.

### Say, in the root README, that `elixir/` is not a second copy of `verify.sh`

**Why it matters.** `elixir/README.md` is accurate: Ed25519, key window, optional log checkpoint, no other package. It does not check the act-hash binding, the ML-DSA co-signature, or `hands`. The root file list can be read as "the Elixir receipt verifier" for this repository's job. `mix test` could not be run here.

**Evidence.** `elixir/README.md` opening paragraph. `command -v elixir` and `command -v mix` print nothing. `elixir/mix.exs` `source_url` is `https://github.com/ScriptKittyOS/Requisition-Offline-Verifier`.

**Effort.** Small for the README sentence. Parity with `verify.sh` is a larger port.

**Priority.** Medium for the sentence. Low for a full port until the Python checks above are settled, so the two implementations do not freeze different rules.

### One canonical form for control characters

**Why it matters.** `verifier/verify_offline.py` contains two encoders. Verification uses only v3 (`derivation_label`, lines 645-647, always returns `sha384+canonical_payload.v3`). v3 escapes U+000B as `\u000B` (uppercase, line 193). v4 escapes it as `\u000b` (lowercase, line 264, the RFC 8785 form). A second implementation that "corrects" the case will disagree on any argument that contains a control character. The published arguments are printable ASCII, so this run is unaffected. This fails closed (a mismatch), it does not accept a forged hash.

**Evidence.** Calling `encode` and `encode_v4` on `{"c": "\u000b"}` produced `{"c":"\u000B"}` and `{"c":"\u000b"}`.

**Effort.** Small. One sentence next to the v3 encoder, or stop shipping the unused v4 copy if it stays withdrawn.

**Priority.** Low.

## Doc fixes

### `CHECKPOINTS.md` is not runnable from this tree

**Why it matters.** The command block in `CHECKPOINTS.md` invokes `bin/verify_offline.py` and tells the reader to look at `bench/holytrinity-v2/verifier/`. `verifier/CHECKPOINTS.md` and `elixir/CHECKPOINTS.md` say the vectors live in `lab/checkpoint-vectors/`. None of those paths exist here. `PROVENANCE.md` maps them. A banner at the top of each copied document would save a false start. `sh checkpoint-test.sh` is the command that actually runs.

**Evidence.**

```
bin/verify_offline.py exists: False
bin/lab-verify exists: False
lab/checkpoint-vectors/manifest.json exists: False
```

`sh checkpoint-test.sh` exit 0, as in the suite table.

**Effort.** Small.

**Priority.** Low. The map exists. The copied command block is still wrong for this tree.

### Interop results other than mldsa-py were not reproduced here

**Why it matters.** Not a false claim in the docs. The Go README pins Go 1.27.4, names `GOTOOLCHAIN=local`, and gives a SHA-256 for the tarball. This machine has Go 1.22.2, and the local-toolchain run failed as quoted above. The other harnesses were `SKIPPED` by `interop/run-all.sh`. The one that could run, mldsa-py, agreed on all 260 cases. Elixir's documented versions (1.18.4, 1.19.2, 1.20.4) were not installed, so `mix test` and `mix hex.build` were not repeated.

**Evidence.** The `run-all.sh` line and the Go error in "How tested".

**Effort.** None required in the docs if the pinned tarball stays the reproduction path. A container or a note that Go 1.22 cannot compile `crypto/mldsa` would help the next person on an older Go.

**Priority.** Low.

## What the repo already says, so it is not asked for as if it were forgotten

These are stated limits or decisions, not a hidden failure of this run. The feature section asks to close a few of them. They should not be filed as newly discovered bugs.

- A pass does not prove the action ran, that the keys are a trust root, or that the private keys are inside AWS KMS. `DEGRADED (lab)` and exit 5 from `lab-verify` are deliberate. `verify.sh` turns that into `RESULT: PASS` only when the other checks hold. README, "What a pass proves, and what it does not", and "About `DEGRADED (lab)`".
- Signed times are not compared with the wall clock. README, same section. The expiry feature above is a request to add that, with the limit already written.
- One record is judged at a time. README, same section. Bug 1 is narrower: the one command's two paths are not checked to be a statement and a linked decision.
- `verify.sh` does not run the log check, and this tree has no checkpoint for the 13 November records. `README.md` line 92. The checkpoint feature above asks for that artifact.
- A checkpoint is not shown to be the newest, witness identity is not checked, ML-DSA-44 witness cosignatures are refused by name, and a record whose own signature is ML-DSA-87 is not checkpoint-checked. `verifier/CHECKPOINTS.md`, "Not checked".
- The held-state file has no signature of its own. README and `CHECKPOINTS.md`. Not re-tested beyond the 32 vectors, which already include an older held tree and a split view.
- `canonical_payload.v4` is in `verifier/verify_offline.py` and is not used to verify a record. `PROVENANCE.md`, and `derivation_label` lines 645-647. The v4 label is described as withdrawn.
- Extra top-level fields the signature does not cover are ignored on purpose. A temp copy of `statement.json` with `approved_by` `alice` and `verdict` `allow` added inside the statement envelope still made `sh verify.sh` exit 0 and print `signed verdict: none` for that file (the signed verdict is unchanged) and `RESULT: PASS`. `elixir/VERDICTS.md`, "One stricter rule considered and not adopted."
- Anchoring `occurred_at` outside the signer is named future work. `elixir/VERDICTS.md`.
- `requisition-aws` and `requisition-ts` are not published yet and are not required to run this verifier. README, "Install".
- `elixir/` is described as added for the next release. `PROVENANCE.md`.
- The inner verifier's exit does not distinguish `allow` from `deny`. That sentence is printed on every passing decision in `expected-output.txt`. The enhancement above is to make `verify.sh` stricter than that, not to claim the sentence is missing.

## Top 5 to hand over

1. **Require a statement and a linked `allow` decision in `verify.sh`.** Copying `statement.json` over `decision.json` still exits 0 and prints `RESULT: PASS (both records verify)`, with `signed verdict: none` on both paths.
2. **Check two distinct approvers on both records.** The published decision has no `sanctioners` member, both records are signed `one-person (G-301)`, and `verifier/lab-verify` lines 760-762 return immediately for that label. `sh verify.sh` exits 0. A same-person-twice record exits 0 when the post-quantum flag is not what rejects it.
3. **Honor `exp`, `not_after`, and `exec_not_after`.** `sh verify.sh` exits 0 on 2026-11-19. The decision's `exec_not_after` is `2026-11-13T15:57:48Z`. The README already says the clock is not consulted. This is a request to add the check.
4. **Publish a witnessed log checkpoint for these two records and run it from `verify.sh`.** `README.md` line 92: `verify.sh` does not run check 4, and this tree has no checkpoint for the 13 November records. `checkpoint-test.sh` covers a different lab key.
5. **Parse the KMS ARN strictly, and do not call it pinned by the key file unless the key file has that field.** A signed ARN of `arn:aws:kms:eu-west-1:999999999999:alias/not-a-key:key/<resource>` exits 0 and is printed as pinned. `check_kms_key` only requires an `arn:` prefix, service `kms`, and a `:key/<resource>` suffix (`verifier/lab-verify` lines 623-628).
