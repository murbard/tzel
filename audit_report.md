# TzEL v2: Security Audit Report

Static analysis of the protocol specification, full codebase (Rust core, Cairo circuits, OCaml reference, wallet, ledger service, dependencies), and test suite. No code was executed; all findings are from source inspection. The Tezos rollup kernel is out of scope.

Findings are tagged **[spec]**, **[code]**, or **[test]** by origin.

---

## Part I -- Specification

Audit of `specs/spec.md` against itself and the implementation.

### S1. WOTS+ secret key derivation: two conflicting definitions [spec]

The Key Hierarchy diagram (line 38) says:
```
seed_i = H(H(TAG_AUTH_KEY, ask_j), i_felt)
```
The Auth Key Tree section (line 80) says:
```
sk_root_i = H(TAG_XMSS_SK, ask_j, i_felt)
```

Nested 2-input with `TAG_AUTH_KEY` vs flat 3-input with `TAG_XMSS_SK`. The implementation matches the Auth Key Tree section. The Key Hierarchy diagram is stale. An implementer following the diagram will derive wrong keys.

### S2. XMSS hash personalization: table contradicts section [spec]

The domain separation table (line 447) claims WOTS+ chain hash uses `wotsSP__` and auth tree Merkle nodes use `mrklSP__`. The Auth Key Tree section (lines 101-102) says H_chain and H_node use **unpersonalized** BLAKE2s with ADRS-based domain separation. The implementation confirms unpersonalized -- `xmss_chain_step()` and `xmss_node_hash()` call `blake2s_parts()` without personalization. A `hash1_wots` function with `wotsSP__` exists but is **not used** in the actual XMSS chain computation.

This is the most dangerous inconsistency for a clean-room implementer. Following the table produces a different, incompatible XMSS tree.

### S3. Missing tag constants [spec]

`TAG_XMSS_SK` and `TAG_XMSS_PS` are used (lines 76, 80) but their string values (`"xmss-sk"`, `"xmss-ps"`) are never defined -- not inline, not in the Domain Tag Constants table. `TAG_XMSS_CHAIN`, `TAG_XMSS_LTREE`, `TAG_XMSS_TREE` are defined inline (lines 103-105) but also absent from the table. Meanwhile `TAG_AUTH_KEY` (`"auth-key"`) IS in the table but belongs to the stale derivation in S1.

### S4. Unshield no-change zero list omits `pub_seed_change` [spec]

Line 269 lists fields zeroed for prover malleability elimination: `v_change`, `d_j_change`, `rseed_change`, `auth_root_change`, `nk_tag_change`, `memo_ct_hash_change`. The field `pub_seed_change` is missing from the spec's list. The implementation correctly zeroes it (`unshield.cairo:75`).

### S5. Sighash fold algorithm unspecified [spec]

The spec lists inputs to `fold()` but never defines the folding algorithm. The implementation is a sequential left-fold: `state = H_sigh(state, next_input)`. A single hash of concatenated inputs would produce different results.

### S6. Delegated proving leaks per-address nullifier capability [spec]

The prover receives `nk_spend_j` per input. `security.md:20` acknowledges same-address linking but understates the scope. With `nk_spend_j` and public on-chain data (all commitments and positions are public), the prover can compute candidate nullifiers for every `(cm, pos)` pair, check each against the on-chain nullifier set, and determine which commitments belong to address `j` and whether they've been spent. This is closer to full-view capability for one address than mere linking, and it persists permanently.

### S7. No sighash expiry [spec]

Acknowledged in spec. Combined with delegated proving: a malicious prover can withhold a completed proof indefinitely and submit it at an adverse time. The user's only defense is racing to spend the same inputs in a different transaction, requiring a full re-prove.

### S8. WOTS+ key reuse catastrophic and on-chain unenforceable [spec]

`security.md:34-37` correctly flags this. The key index is hidden inside the STARK for unlinkability, so the chain cannot detect double-use. A stale backup, multi-device race, or crash between signing and persistence can cause silent key reuse, enabling signature forgery by anyone who observes both proofs (including the delegated prover).

### S9. Shield has no `auth_domain` [spec]

Shield public outputs are `[v_pub, cm_new, sender_id, memo_ct_hash]` with no `auth_domain`. If two deployments share an account namespace, a shield proof is valid on both. External sender-binding mitigates this in practice, but the proof object itself is portable. Transfer and unshield include `auth_domain`.

### S10. Minor spec observations [spec]

- **Input count N is public** (nullifier count visible). Acknowledged in `security.md`.
- **Viewing ciphertext correctness not proven in-circuit** (`security.md:27`). A malicious sender can encrypt garbage.
- **Zero-value notes**: nothing prevents `v_pub = 0` shields, enabling commitment tree spam.
- **Variable N communicated implicitly**: the verifier infers N as `(total_outputs - 6)`. The spec should state the parsing rule.

---

## Part II -- Implementation

Deep static analysis of Rust, Cairo, OCaml, and dependencies.

### Critical

#### C1. OCaml commitment hash encodes value differently than Rust [code]

**OCaml** (`ocaml/protocol/hash.ml:97-103`): blits `v` as a full 32-byte felt252 into bytes [32..64].

**Rust** (`core/src/lib.rs:187-194`): writes `v` as an 8-byte LE u64 into bytes [32..40]; bytes [40..64] are implicitly zero from `[0u8; 128]` init.

Both produce the same buffer for valid u64 values (the felt's high 24 bytes are zero). This is fragile rather than currently broken. Any future change to value width, or an OCaml path that constructs a felt with non-zero high bytes, would silently break interop. The Rust code's implicit zero gap should be documented, and the OCaml code should use explicit 8-byte encoding to match the Rust layout.

#### C2. Wallet stores master_sk unencrypted on disk [code]

**File**: `apps/wallet/src/main.rs:489-505`

The wallet file is plaintext JSON containing `master_sk` as a hex string. No password derivation, encryption, or OS keychain integration. A file read yields complete spending authority.

No `zeroize` crate usage was found anywhere. Temporary secret derivatives (`ask_j`, `nk_spend`, WOTS signatures) are stack/heap allocated without explicit zeroization on drop.

### High

#### H1. WOTS+ key reuse compounded by backup fragility [code]

Three compounding risks:

1. **On-chain enforcement impossible** (S8 above): `key_idx` hidden inside the STARK.
2. **Wallet state is the sole defense**: the wallet (`main.rs:690-713`) advances the BDS index and persists it atomically before proving via fsync + atomic rename (`main.rs:828-831`). Well-implemented.
3. **Backup restore breaks the invariant**: restoring a wallet file rolls back the WOTS key index. No backup-age detection, no monotonic counter persisted externally, no warning on restore.

### Medium

#### M1. ChaCha20-Poly1305 uses fixed zero nonce [code]

**File**: `core/src/lib.rs:872,917`

Every note encryption uses `Nonce::from_slice(&[0u8; 12])`. Safe in production (fresh ML-KEM shared secret per note = fresh key), but the deterministic encryption path (`encrypt_note_deterministic`, line 883) reuses (key, nonce=0) if the same ephemeral is supplied twice, yielding XOR of plaintexts. A derived nonce (e.g., `H(key)[..12]`) would eliminate this at zero cost.

#### M2. Detection tag comparison is not constant-time [code]

**File**: `core/src/lib.rs:936`

```rust
computed == enc.tag  // short-circuit u16 equality
```

Detection is privacy-sensitive. An observer measuring a detection server's response time could narrow down tag matches. Use `subtle::ConstantTimeEq`.

#### M3. Historical root set never pruned [code]

**File**: `core/src/lib.rs:1407-1424`

The ledger's `valid_roots: HashSet<F>` grows without bound. No expiry window. Storage concern and minor attack surface: a proof referencing a very old root remains valid forever.

#### M4. ml-kem dependency is a release candidate [code]

`ml-kem = "0.3.0-rc.2"` in four in-scope Cargo.toml files (core, wallet, demo, tzel services; also present in the out-of-scope rollup kernel). Consistent with the project's development status, but should be upgraded when 0.3.0 stable ships.

### Low / Informational

#### L1. Cairo BLAKE2s uses pre-computed personalized IVs [code]

**File**: `cairo/src/blake_hash.cairo:49-123`

The generic hash IV differs from RFC 7693's standard BLAKE2s IV. This is intentional (parameter-block XOR pre-baked). No inline derivation or comment proves correctness. Recommend adding a test that derives the IVs from first principles and asserts equality.

#### L2. Commitment buffer has implicit 24-byte zero gap [code]

**File**: `core/src/lib.rs:187-194`

`commit()` writes `v` as 8 bytes into a 128-byte zero-initialized buffer. Bytes [40..64] are implicitly zero. Correct but fragile. A comment would clarify intent.

#### L3. Nullifier uses same personalization for both hash layers [code]

**File**: `core/src/lib.rs:196-207`

Both `H_nf(cm, pos)` and `H_nf(nk_spend, cm_pos)` use `nulfSP__`. Both are 64-byte inputs. Domain separation relies on structural input difference, not distinct personalizations. Safe but unusual.

#### L4. No rate limiting on ledger HTTP API [code]

Demo/reference ledger has no rate limiting, authentication, or CORS policy. Operational infrastructure concern.

#### L5. Wallet note cleanup not atomic with submission [code]

**File**: `apps/wallet/src/main.rs:2691-2697`

Crash between submission and wallet cleanup leaves stale notes. UX issue (stale balance until next `scan`), not fund-loss.

#### L6. Dependency hygiene [code]

Cryptographic dependencies (blake2s_simd, chacha20poly1305, ml-kem) use semver ranges (e.g., `"1.0"`, `"0.10"`), allowing patch updates. Proving-stack dependencies (stwo, cairo-vm, proving-utils) are pinned to exact git revisions or `=` versions. No `unsafe` in cryptographic code paths (only in Tezos kernel FFI). No hardcoded secrets, .env files, or test mnemonics. No build.rs files.

---

## Part III -- Test Coverage

Static analysis of all tests across Rust, Cairo, and OCaml.

### Inventory

| Component | Tests | Property | Integration |
|-----------|-------|----------|-------------|
| `core/src/lib.rs` | 15 | 3 | -- |
| `core/src/canonical_wire.rs` | 6 | -- | -- |
| `services/tzel/src/lib.rs` | 77 | -- | -- |
| `services/tzel/src/protocol_vectors.rs` | 2 | -- | -- |
| `services/tzel/src/interop_scenario.rs` | 2 | -- | -- |
| `services/tzel/tests/` | 3 active, 3 ignored | -- | 6 |
| `apps/wallet/src/main.rs` | 41 | 1 | -- |
| `apps/ledger/src/main.rs` | 12 | -- | -- |
| `cairo/src/*.cairo` | **0** | **0** | -- |
| `ocaml/test/` | 175 | -- | 1 |
| **Fuzzing** | **0** | -- | -- |
| **Benchmarks** | **0** | -- | -- |

**Totals**: ~335 unit tests, 4 property tests, 8 integration tests, 0 fuzz targets.

### What is well-tested

**Consensus rules** (tzel service): 22 attack tests validate that the ledger rejects every category of proof-binding violation -- cm mismatch, memo substitution, root mismatch, auth_domain mismatch, v_pub inflation, recipient redirect, fake nullifier, double-spend, duplicate nullifiers, zero inputs, balance overflow, short preimage. Two atomicity tests verify ledger state is untouched after rejection.

**Regression suite**: 23 regression tests lock down past bugs: 251-bit truncation, WOTS+/sighash personalization separation, circuit type tags, auth-domain binding, memo-ct-hash coverage, sender validation, client-cm/enc requirements.

**Wallet WOTS+ index safety**: `test_transfer_persists_wots_state_before_proving` and `test_unshield_persists_wots_state_before_proving` simulate proof failure and assert the index was already persisted. `test_reserve_next_auth_rejects_exhausted_tree` asserts clean error at 2^AUTH_DEPTH.

**Note acceptance**: tests reject XOR-corrupted commitments and wrong owner tags despite successful AEAD decryption.

**Cross-implementation vectors**: `protocol_vectors.rs` generates deterministic vectors for BLAKE2s, key hierarchy, ML-KEM, ChaCha20, WOTS+, Merkle, nullifiers, sighash, and wire encoding. The OCaml `test_vectors.ml` independently recomputes all 16 vector groups and asserts byte-exact match.

### Gaps

#### T1. Cairo circuits have zero direct unit tests [test]

Every `.cairo` file has no test module. All circuit testing is indirect: the Rust integration tests generate real STARK proofs, but these are `#[ignore]`'d. The fast test suite never exercises the Cairo code.

**Missing tests per file:**

| File | Missing |
|------|---------|
| `blake_hash.cairo` | `felt_to_u32x8`/`u32x8_to_felt` roundtrip; IV constants verified from first principles; `sighash_to_wots_digits` boundary cases (all-zero, all-max, length=133) |
| `merkle.cairo` | `verify()` with valid and invalid paths; **position aliasing guard** (`path_indices >= 2^TREE_DEPTH`) -- critical security check, never tested; same for `verify_auth()` with `key_idx >= 2^AUTH_DEPTH` |
| `xmss_common.cairo` | `xmss_chain_step` with known I/O; `xmss_recover_pk` with valid and corrupted signatures; `pk_to_leaf` with odd input count |
| `transfer.cairo` | Invalid WOTS+ signature (never tested anywhere); invalid Merkle path; balance mismatch; duplicate nullifiers; N=0, N=1, N=16, N=17 |
| `unshield.cairo` | No-change path: non-zero `v_change`/`d_j_change`/etc. should each fail; balance mismatch; invalid auth path |

#### T2. No property-based tests for core cryptographic invariants [test]

Only 4 proptest functions exist. The following invariants have no property test:

| Invariant | Why it matters |
|-----------|---------------|
| **Commitment hiding**: different `rseed` -> different `cm` | Privacy: predictable cm lets observers match notes to addresses |
| **Commitment binding**: different `(d_j, v, owner_tag)` -> different `cm` | Soundness: shared commitments make spending ambiguous |
| **Nullifier depends on nk_spend**: different `nk_spend` -> different `nf` | Soundness: without this, any key holder can double-spend |
| **Nullifier depends on cm**: different `cm` -> different `nf` | Soundness: without this, nullifier isn't note-specific |
| **WOTS+ checksum prevents forgery**: increasing a message digit decreases the checksum, requiring a smaller checksum digit the attacker can't produce | The checksum is the forgery barrier |
| **Value conservation**: `sum(v_in) == v_out_1 + v_out_2` for random valid witnesses | The fundamental ledger invariant; tested only with fixed amounts |
| **Wire encoding roundtrip**: `decode(encode(x)) == x` for random `x` | Tested with fixtures only |

#### T3. No fuzzing harnesses [test]

Zero fuzz targets. High-value targets:

- `decode_tze::<PaymentAddress>(arbitrary_bytes)` and `decode_tze::<EncryptedNote>(arbitrary_bytes)`
- `parse_single_task_output_preimage(arbitrary_felts)` -- integer overflow in length fields
- `EncryptedNote::validate()` with arbitrary field sizes
- `felt_to_u64` / `felt_to_usize` with adversarial 32-byte inputs

#### T4. Sighash field sensitivity not exhaustively tested [test]

`test_transfer_and_unshield_sighash_are_bound_to_public_fields` (core lib.rs:2217) tests `auth_domain`, `nullifiers`, `v_pub`, and `recipient` sensitivity. A separate test, `test_mutant_sighash_known_answer` (tzel lib.rs:1796), additionally covers `cm_1`/`cm_2` swap and `v_pub` variation. Between the two tests, the following fields are still **not** tested for sensitivity:

- `root` (transfer or unshield)
- `memo_ct_hash_1`, `memo_ct_hash_2` (transfer)
- `cm_change`, `memo_ct_hash_change` (unshield)
- Nullifier ordering (does `[nf_a, nf_b]` differ from `[nf_b, nf_a]`?)

If any of these were accidentally dropped from the fold, the corresponding public output could be swapped without invalidating the WOTS+ signature.

#### T5. WOTS+ sign/verify exercised at only two key indices [test]

`test_wots_signature_recovers_authenticated_leaf` (core lib.rs:2134) uses `key_idx=0`. `test_regression_wots_signature_binds_to_auth_leaf` (tzel lib.rs:1924) uses `key_idx=7`. No other index is tested with a full sign/verify/leaf-recovery cycle. `test_regression_wots_key_index_produces_different_keys` verifies indices produce different keys but only signs at index 0. OCaml tests also exercise only `key_idx=0`. Two indices is better than one, but an ADRS packing bug affecting only high indices (e.g., byte-order error in `key_idx >= 256`) would still be invisible.

#### T6. Wallet missing multi-input and change-output tests [test]

No wallet-level unit test constructs a multi-input transfer (N >= 2). The ledger-level test `test_apply_unshield_stark_path_with_change_updates_balance_and_note` (core lib.rs:2380) does exercise unshield with change at the state-machine level, but no wallet test constructs the full witness for this path. Specific gaps:

- **N=2+ inputs** (consolidation): witness layout for multiple `nk_spend`, `auth_root`, `wots_sig`, `cm_path`, `auth_path` arrays. Off-by-one in flat-array indexing would silently produce an invalid proof.
- **Unshield with/without change**: change address derivation, commitment computation, `has_change` witness flag.
- **Multi-address spending**: inputs from different addresses. Untested whether notes from mixed addresses produce correct witnesses.
- **Change address lifecycle**: `next_address()` creates a new address; `addr_counter`, BDS state, and WOTS index must all be persisted. No test checks this sequence.
- **Balance edge cases**: spending all notes, zero-value notes, `u64::MAX` value notes.

#### T7. Wallet backup/restore has no safety test [test]

No test simulates: save wallet, advance WOTS index, restore from backup, attempt transaction. This is the scenario that causes catastrophic WOTS+ key reuse (H1 above).

#### T8. OCaml commitment encoding not cross-checked [test]

Both implementations produce the same commitment for u64 values, but no test explicitly verifies byte-exact equality across Rust and OCaml for the same `(d_j, v, rcm, owner_tag)`. A direct cross-check with `v = u64::MAX` is absent.

#### T9. Core crypto functions tested only indirectly [test]

| Function | Line | Status |
|----------|------|--------|
| `derive_nk_spend(nk, d_j)` | 172 | Indirect via note recovery |
| `derive_nk_tag(nk_spend)` | 179 | Indirect via note recovery |
| `owner_tag(auth_root, pub_seed, nk_tag)` | 183 | Indirect via note recovery |
| `commit(d_j, v, rcm, otag)` | 187 | Indirect via note recovery + shield |
| `advance_auth_path()` | 693 | **Dead code** (never called) |
| `build_auth_tree()` | 662 | Only via fixtures |
| `auth_tree_path()` | 668 | Only via fixtures |
| `blake2s_parts()` | 126 | Never directly |
| `hash1_wots()` | 402 | Only in regression test for IV |

#### T10. Ledger TrustMeBro paths untested in unit tests [test]

`apply_shield`, `apply_transfer`, `apply_unshield` each have a TrustMeBro path where the ledger generates commitments from request fields. The unit tests always construct fake STARK proofs with explicit output preimages. TrustMeBro is only tested via the integration test `test_e2e_trust_me_bro` (black-box, HTTP).

#### T11. Atomicity not verified for most rejection paths [test]

Only 2 of ~20 rejection tests check that ledger state is unchanged after rejection. The rest assert the error message but don't check `tree.leaves`, `valid_roots`, `nullifiers`, `memos`, and balances are untouched.

#### T12. Integration tests for real STARK proofs are ignored [test]

`test_shield_proof_roundtrip`, `test_transfer_proof_roundtrip`, `test_unshield_proof_roundtrip` are `#[ignore]`. These are the only tests exercising the full Cairo circuit -> reprover -> ledger verification path. If they never run in CI, circuit and reprover regressions go undetected.

---

## Part IV -- What looks solid

### Consensus rules [code]

All eight contract-level checks from the spec are implemented and tested:

| Rule | Location | Tests |
|------|----------|-------|
| Root validation | `lib.rs:1620,1710` | `test_transfer_invalid_root_rejected` |
| Auth-domain validation | `lib.rs:1654,1740` | `test_regression_sighash_auth_domain_changes_digest` |
| Executable binding | `tzel/src/lib.rs:227-248` | Implicit in all STARK tests |
| Nullifier uniqueness | `lib.rs:1623-1634,1713-1724` | `test_transfer_double_spend_rejected`, `test_attack_transfer_fake_nullifier_rejected` |
| Commitment binding | `lib.rs:1554,1666` | `test_attack_transfer_cm_mismatch_rejected` |
| Memo integrity | `lib.rs:1562,1674-1678` | `test_attack_transfer_memo_substitution_rejected`, `test_regression_shield_memo_hash_validated` |
| Shield sender binding | `lib.rs:1557` | `test_regression_shield_sender_validated` |
| Change output handling | `lib.rs:1776-1784` | `test_ledger_unshield_rejects_change_note_without_cm` |

### Cairo circuits [code]

- Public output ordering matches spec for all three circuits.
- Value arithmetic uses u128 accumulators over u64 inputs; balance equations enforced exactly.
- Nullifiers are position-dependent, pairwise-distinct, and verified against public outputs.
- WOTS+ digit decomposition (128 message + 5 checksum, base-4) is correct; chain direction correct.
- Merkle path verification includes the critical `assert(idx == 0)` bounds check preventing position aliasing.
- No-change unshield path zeroes all 7 witness fields (the spec omits `pub_seed_change` but the circuit doesn't).
- Sighash fold ordering and type tags (0x01 transfer, 0x02 unshield) match spec.

### WOTS+ / XMSS [code]

- Parameters correct: w=4, 133 chains (128 msg + 5 checksum), chain length 3.
- ADRS packing: no field overflow, felt252 truncation applied.
- LTree handles odd-length levels correctly.
- Felt252 truncation (`out[31] &= 0x07`) consistently applied across all hash outputs.

### Wallet key-index safety [code]

- `reserve_next_auth()` advances BDS state in memory (`main.rs:712-713`).
- `persist_wallet_and_make_proof()` writes the wallet to disk via atomic rename + fsync _before_ proof generation (`main.rs:828-831`).
- Exhaustion returns a clean error (`main.rs:702-707`).
- Tests confirm index persistence survives proof-generation failure.

### Note acceptance [code]

The wallet recomputes commitments from decrypted data before accepting notes (`main.rs:618`), exactly as the spec requires. Tested against tampered commitments and wrong owner tags.

### Serialization [code]

TDE wire encoding in Rust and OCaml uses fixed-size fields with exact byte counts matching the spec. Decode rejects trailing bytes. EncryptedNote validation enforces exact sizes.

### State management [code]

The ledger uses `Arc<Mutex<Ledger>>` for all state mutations. No TOCTOU races. Balance operations use `checked_add` / `checked_sub`. Nullifier insertion is atomic with validation.

### Cryptographic design [spec]

- Nullifier construction with position binding (faerie gold prevention).
- Owner tag fusing auth_root + pub_seed + nk_tag into commitments.
- Capability hierarchy (detection < incoming view < full view < spend).
- Sighash binding to transaction type, auth_domain, all inputs and outputs.
- WOTS+ checksum prevents single-signature forgery.
- ML-KEM KEM-DEM construction with fresh shared secrets per encapsulation.

---

## Part V -- Suggested test additions

### P0

**Cairo circuit unit tests.** Add a test module to each `.cairo` file:

```
blake_hash.cairo:
  - test_felt_u32x8_roundtrip_zero
  - test_felt_u32x8_roundtrip_max
  - test_wots_digits_all_zero_sighash
  - test_wots_digits_all_max_sighash
  - test_wots_digits_length_133

merkle.cairo:
  - test_verify_valid_path
  - test_verify_wrong_sibling_fails
  - test_verify_position_aliasing_rejected
  - test_verify_auth_position_aliasing_rejected

transfer.cairo:
  - test_verify_rejects_balance_mismatch
  - test_verify_rejects_duplicate_nullifier
  - test_verify_n_1_minimum / n_16_maximum / n_0_rejected

unshield.cairo:
  - test_verify_no_change_zeroes_all_fields
  - test_verify_no_change_rejects_nonzero_v_change
  - test_verify_rejects_balance_mismatch
```

**Property tests for cryptographic invariants.** Add proptest functions for: commitment hiding (rseed variation), commitment binding (input variation), nullifier dependence on all three inputs (nk_spend, cm, pos), WOTS+ checksum forgery resistance, value conservation, wire encoding roundtrip.

### P1

- **Sighash exhaustive field sensitivity**: vary each input independently, assert output changes. Include nullifier ordering.
- **WOTS+ at high key_idx**: existing tests cover indices 0 and 7. Add sign/verify/leaf-recovery at `key_idx=256` (first index requiring two ADRS bytes) and `key_idx=65535` (maximum).
- **Multi-input wallet transaction**: construct N=2 transfer witness from two notes (ideally different addresses), assert flat-array layout.
- **Fuzzing harnesses**: `decode_tze`, `parse_single_task_output_preimage`, `EncryptedNote::validate()`.

### P2

- **Wallet backup/restore safety**: save, advance WOTS, restore, attempt transaction.
- **OCaml cross-check**: byte-exact commitment equality for `v = u64::MAX`.
- **Atomicity macro**: snapshot ledger state before rejection, assert all fields unchanged after. Apply to all rejection tests.
- **Run ignored integration tests in CI**: nightly job for `test_shield_proof_roundtrip`, `test_transfer_proof_roundtrip`, `test_unshield_proof_roundtrip`.
- **Ledger TrustMeBro paths**: unit tests for shield/transfer/unshield without output preimages.

### P3

- OCaml: WOTS+ vectors at `key_idx=256` and `key_idx=65535` (complement Rust coverage at 0, 7); depth-8 Merkle path verification.
- Wallet: `select_notes` with zero-value and `u64::MAX` notes; concurrent lock recovery.
- Core: `encrypt_note` randomized roundtrip; `detect()` returns false for wrong `dk_d`; `decrypt_memo()` returns None for wrong `dk_v`.
- EncryptedNote: `tag=0`, `tag=1023`, empty/oversized fields.
- Merkle: single leaf, large tree (hundreds of leaves), zero-valued leaves.

---

## Files examined

| Component | Key files | Lines (approx) |
|-----------|-----------|-----------------|
| Core crypto | `core/src/lib.rs`, `core/src/canonical_wire.rs` | 2,900 |
| Cairo circuits | `cairo/src/{shield,transfer,unshield,run_*,blake_hash,merkle,xmss_common}.cairo` | 1,200 |
| Ledger service | `services/tzel/src/lib.rs`, `apps/ledger/src/main.rs` | 3,100 |
| Wallet | `apps/wallet/src/main.rs` | 2,900 |
| OCaml reference | `ocaml/protocol/*.ml`, `ocaml/services/*.ml`, `ocaml/test/*.ml` | 2,500 |
| Test vectors | `services/tzel/src/{protocol_vectors,interop_scenario}.rs` | 1,100 |
| Config | All `Cargo.toml`, `Scarb.toml`, `Cargo.lock` | -- |
