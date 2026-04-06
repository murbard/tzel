# StarkPrivacy v2: Restructured Key Hierarchy

## Context

v1 works: four circuits (shield/unshield/join/split), two-level recursive STARK proofs at ~290 KB, delegated proving via nsk/ask split, 96-bit security. But the key hierarchy entangles nullifier material with address material (`pk_i = H(nsk_i)`), making scanning O(notes), preventing address reuse, and forcing per-note key indices everywhere.

v2 separates the spending branch (nullifiers, authorization) from the incoming branch (addresses, viewing, detection). This enables multi-address scanning, reusable addresses, clean viewing key delegation, and a proper detect ⊂ view capability hierarchy.

## Target Key Hierarchy

```
master_sk
├── spend_seed = H("spend", master_sk)
│   ├── nk       = H("nk",  spend_seed)      — account nullifier secret (ONE per account)
│   ├── ask_base = H("ask", spend_seed)       — base spend auth secret
│   └── ovk      = H("ovk", spend_seed)       — outgoing viewing key (sender can recover sent notes)
│
└── incoming_seed = H("incoming", master_sk)
    ├── dsk       = H("dsk", incoming_seed)   — diversifier derivation key
    ├── view_seed = H("view", incoming_seed)  — per-address ML-KEM viewing keys
    └── det_seed  = H("detect", view_seed)    — detection keys (derived FROM view → detect ⊂ view)

Per address index j:
    d_j    = H("div", dsk, j)                 — diversifier (public, unlinkable across j)
    ek_v_j = ML-KEM.KeyGen(H("mlkem-view", view_seed, j))    — memo encryption pubkey
    ek_d_j = ML-KEM.KeyGen(H("mlkem-detect", det_seed, j))   — detection pubkey

    address_j = (d_j, ek_v_j, ek_d_j)         — what you give to a sender

Per note (sent to address j):
    rseed  = random                            — per-note randomness
    rcm    = H("rcm", rseed)                   — commitment randomness
    rho    = H("rho", rseed)                   — nullifier nonce

Capabilities:
    detection_key(j)   = dk_d_j                                — flag candidates for address j
    incoming_view_key  = (dsk, view_seed)                       — decrypt all memos, all addresses
    full_viewing_key   = (nk, dsk, view_seed, ovk)              — above + compute nullifiers + outgoing
    spending_key       = full_viewing_key + ask_base             — full control
```

## Note Structure (v2)

```
Note = {
    d_j   : felt252       — diversifier (identifies the address)
    v     : u64            — amount
    rseed : felt252        — per-note randomness (derives rcm, rho)
}

cm  = H_commit(d_j, v, rcm)          — commitment (binds to address + value + randomness)
nf  = H_nullifier(nk, cm)            — nullifier (binds to account nk + this specific commitment)
```

Key changes from v1:
- Commitment does NOT contain pk or any spending material — only the diversified address
- Nullifier is `H(nk, cm)` not `H(nsk_i, rho)` — account-level nk, binds to cm itself
- One `nk` for the whole account, not per-note `nsk_i`
- `rseed` is per-note randomness; `rho` and `rcm` derive from it

## Circuit Changes

### Shield (v2)

Public outputs: `[v_pub, cm_new, ak, sender]`
Private inputs: `d_j, rseed`
Constraints:
1. `rcm = H("rcm", rseed)`
2. `cm_new = H_commit(d_j, v_pub, rcm)`

Note: shield doesn't touch nk (no note being spent).

### Unshield (v2)

Public outputs: `[root, nf, v_pub, ak, recipient]`
Private inputs: `nk, d_j, rseed, Merkle path`
Constraints:
1. `rcm = H("rcm", rseed)`
2. `cm = H_commit(d_j, v_pub, rcm)`
3. `cm` in Merkle tree under `root`
4. `nf = H_nullifier(nk, cm)`

Note: the circuit takes `nk` (account-level) not `nsk_i` (per-note). The prover needs `nk` for proving. For delegated proving, `nk` could be given to the prover (it's view-level material, not spend-level), OR the user precomputes `nf` locally and passes it as a public input with the circuit verifying it.

### Transfer (v2)

Public outputs: `[root, nf_a, nf_b, cm_1, cm_2, ak_a, ak_b]`
Private inputs: `nk, d_j_a, rseed_a, path_a, d_j_b, rseed_b, path_b, d_j_1, rseed_1, d_j_2, rseed_2`
Constraints:
1. For both inputs: recompute cm from (d_j, v, rcm), verify Merkle membership, compute nf = H(nk, cm)
2. nf_a != nf_b
3. For both outputs: recompute cm from (d_j, v, rcm)
4. v_a + v_b = v_1 + v_2

### Delegated Proving (v2)

The prover receives: `nk, d_j, rseed, v, Merkle path` per input note.

Concern: `nk` is account-level. If the prover gets `nk`, they can compute nullifiers for ALL the user's notes (not just this one). This is view-level access.

Options:
- **Accept it.** The prover already sees the transaction content. Knowing nk additionally lets them compute nullifiers, but they still can't spend (no ask) or decrypt other memos (no dk_v). The extra leak is: they can check whether a specific commitment has been spent, which is public info anyway (NF_set is public).
- **Precompute nf.** The user computes `nf = H(nk, cm)` locally (one hash, trivial) and passes it as a public input. The circuit takes nf as given rather than computing it. Then the prover doesn't need nk. But the circuit must still verify nf is correctly derived — which requires nk inside the circuit.
- **Prove nf derivation in a separate mini-proof.** Too complex for v2.

Recommendation: give the prover `nk`. The additional information they learn (ability to check if notes are spent) is already public. Document this as a known property.

## On-Chain Note Data (v2)

```
cm              —    32 bytes   commitment
ct_d            — 1,088 bytes   ML-KEM detection ciphertext
tag             —     2 bytes   detection tag (k bits, protocol constant)
ct_v            — 1,088 bytes   ML-KEM memo ciphertext
encrypted_memo  —    88 bytes   ChaCha20-Poly1305(v || rseed)
                ────────────────
                 ~2.3 KB per note
```

The encrypted memo now contains `(v, rseed)` instead of `(v, rho, r)`. The recipient derives `rho = H("rho", rseed)` and `rcm = H("rcm", rseed)` from rseed.

## Migration Steps

### Step 1: Update spec

Rewrite spec.md to describe the v2 hierarchy. Document:
- Key hierarchy with spend/incoming branches
- Note structure with d_j, rseed, cm, nf
- Circuit constraints for each transaction type
- Capability levels: detect < incoming_view < full_view < spend
- Delegated proving model (prover gets nk, can't spend)
- ak sender-timing leak as known v1 tradeoff, blinded lattice signatures as future v3

### Step 2: Update blake_hash.cairo

- Remove `derive_pk` (no more `pk = H(nsk)`)
- Add `derive_rcm(rseed)`, `derive_rho(rseed)` convenience functions
- Update `commit()` signature: `commit(d_j, v, rcm)` instead of `commit(pk, ak, v, rho, r)`
- Update `nullifier()` signature: `nullifier(nk, cm)` instead of `nullifier(nsk, rho)`
- Keep all personalized IVs (merkle, nullifier, owner, commit)
- Drop `owner_key(pk, ak)` — no longer needed

### Step 3: Update circuits

- `shield.cairo`: takes `(d_j, rseed)` as private, computes `cm = H(d_j, v, rcm)`, outputs `[v_pub, cm, ak, sender]`
- `unshield.cairo`: takes `(nk, d_j, rseed, path)` as private, computes `cm` and `nf = H(nk, cm)`, outputs `[root, nf, v_pub, ak, recipient]`
- `transfer.cairo`: takes `nk` once (account-level), per-input `(d_j, rseed, path)`, per-output `(d_j, rseed)`, same balance/nullifier constraints
- Remove `merkle.cairo` changes: none needed (Merkle verification is leaf-agnostic)

### Step 4: Update common.cairo

- Define `Address { d_j, ek_v_j, ek_d_j }` (for the demo; ek fields not used in circuits)
- Define `Note { nk, d_j, v, rseed, cm, index }`
- Derive addresses from `incoming_seed` + index
- Derive notes with `rseed` randomness
- Account-level `nk` shared across all notes

### Step 5: Update step executables

- All four steps use the new note/address structure
- `nk` is passed once per account, not per-note `nsk_i`

### Step 6: Update demo (Rust)

- Wallet holds `master_sk`, derives spend_seed/incoming_seed
- Addresses are `(d_j, ek_v_j, ek_d_j)` with ML-KEM keys (use `pqcrypto-mlkem` or `ml-kem` crate)
- Notes use rseed-based derivation
- Nullifier = H(nk, cm)
- Cross-implementation test vectors regenerated
- Add ML-KEM memo encryption/decryption
- Add detection with fixed-k tags

### Step 7: Update reprover

- Rebuild with new circuit executables
- Re-benchmark
- Proof size should be similar (~290 KB) since circuit complexity is comparable

### Step 8: Security audit

- Verify nullifier unlinkability with new H(nk, cm) construction
- Verify commitment doesn't leak spending material
- Verify detect ⊂ view capability chain
- Verify delegated proving safety (prover has nk but not ask)
- Verify ML-KEM ANO-CCA for address unlinkability
- Cross-implementation test with Cairo

## What Does NOT Change

- BLAKE2s as the hash function (with personalized IVs)
- Merkle tree structure (depth 48, same verification)
- Two-level recursive STARK proofs (Stwo + circuit reprover)
- Balance conservation (u128 arithmetic)
- Range checks (u64 typing)
- Delegated proving architecture (prover can't sign without ask)
- 96-bit STARK security level
- bench.sh / reprover infrastructure

## Known v2 Limitations (deferred to v3)

- **ak sender-timing leak**: sender knows ak_i, sees it on-chain when note is spent. Requires blinded lattice signatures to fix.
- **Detection is honest-sender**: malicious sender can bypass detection by submitting bogus ct_d. Recipient falls back to dk_v scanning.
- **Prover learns nk**: delegated prover can compute any nullifier (but this is public-equivalent info since NF_set is public).
- **ML-KEM ANO-CCA**: we rely on Kyber's key anonymity property (proven separately from IND-CCA2). Should cite the specific paper.
- **Detection statistics**: k-bit precision provides 2^(-k) false positive rate. Actual privacy depends on network throughput and user activity. No universal "k is enough" claim.
