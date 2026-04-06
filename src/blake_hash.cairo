/// BLAKE2s-256 hash primitives for StarkPrivacy v2.
///
/// # Key hierarchy (v2 — Penumbra-inspired, post-quantum)
///
/// ```text
///   master_sk
///   ├── spend_seed = H("spend", master_sk)
///   │   ├── nk       = H("nk",  spend_seed)    — account nullifier key (ONE per account)
///   │   ├── ask_base = H("ask", spend_seed)     — base authorization secret
///   │   └── ovk      = H("ovk", spend_seed)     — outgoing viewing key
///   │
///   └── incoming_seed = H("incoming", master_sk)
///       ├── dsk       = H("dsk", incoming_seed) — diversifier derivation key
///       ├── view_seed = H("view", incoming_seed)— per-address ML-KEM viewing keys
///       └── det_seed  = H("detect", view_seed)  — detection keys (detect ⊂ view)
/// ```
///
/// Spending material (nk, ask) and address material (d_j, ek_v, ek_d) live
/// in separate branches. The commitment binds to the diversified address,
/// NOT to spending keys. The nullifier binds to the account-level nk.
///
/// # Note structure
///
///   cm = H_commit(d_j, v, rcm, ak)     — commitment (address + value + randomness)
///   nf = H_null(nk, cm)               — nullifier (account key + commitment)
///   rcm = H("rcm", rseed)             — commitment randomness from per-note seed
///
/// # Domain separation via BLAKE2s personalization
///
/// Each hash use has a unique IV via the BLAKE2s personalization field:
///   - Generic (no personal): key derivation, derive_rcm, derive_rho
///   - "mrklSP__": Merkle internal nodes
///   - "nulfSP__": nullifiers
///   - "cmmtSP__": note commitments

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxTrait;

// ── Arithmetic helpers ───────────────────────────────────────────────
const MASK32: u128 = 0xFFFFFFFF;
const POW32: u128 = 0x100000000;
const POW64: u128 = 0x10000000000000000;
const POW96: u128 = 0x1000000000000000000000000;

// ── Personalized BLAKE2s IVs ─────────────────────────────────────────
//
// h[i] = IV[i] ^ P[i], where P[0] = 0x01010020 (digest=32, unkeyed,
// sequential) and P[6..7] carry the personalization string.

/// Generic IV — no personalization. Used for key derivation.
fn blake2s_iv() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ])
}

/// Merkle-node IV — personalization "mrklSP__".
fn blake2s_iv_merkle() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x73E8ABC6, 0x04BF9D4A,
    ])
}

/// Nullifier IV — personalization "nulfSP__".
fn blake2s_iv_nullifier() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x79EFACC5, 0x04BF9D4A,
    ])
}

/// Commitment IV — personalization "cmmtSP__".
fn blake2s_iv_commit() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x6BEEB4C8, 0x04BF9D4A,
    ])
}

// ── Encoding helpers ─────────────────────────────────────────────────

/// Encode felt252 as 8 little-endian u32 words.
fn felt_to_u32x8(val: felt252) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let v: u256 = val.into();
    let lo = v.low;
    let hi = v.high;
    (
        (lo & MASK32).try_into().unwrap(),
        ((lo / POW32) & MASK32).try_into().unwrap(),
        ((lo / POW64) & MASK32).try_into().unwrap(),
        ((lo / POW96) & MASK32).try_into().unwrap(),
        (hi & MASK32).try_into().unwrap(),
        ((hi / POW32) & MASK32).try_into().unwrap(),
        ((hi / POW64) & MASK32).try_into().unwrap(),
        ((hi / POW96) & MASK32).try_into().unwrap(),
    )
}

/// Decode 8 u32 words to felt252, truncating to 251 bits (mask 0x07FFFFFF on word 7).
fn u32x8_to_felt(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32, h5: u32, h6: u32, h7: u32) -> felt252 {
    let low: u128 = h0.into() + h1.into() * POW32 + h2.into() * POW64 + h3.into() * POW96;
    let h7_masked: u128 = h7.into() & 0x07FFFFFF;
    let high: u128 = h4.into() + h5.into() * POW32 + h6.into() * POW64 + h7_masked * POW96;
    let out = u256 { low, high };
    out.try_into().unwrap()
}

// ── Core hash functions ──────────────────────────────────────────────

/// H(a) — single-element hash (32 bytes, generic IV).
/// Used for key derivation steps.
pub fn hash1(a: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let result = blake2s_finalize(blake2s_iv(), 32, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b) — two-element hash (64 bytes) with caller-specified IV.
fn hash2_with_iv(iv: Box<[u32; 8]>, a: felt252, b: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let result = blake2s_finalize(iv, 64, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b) — generic two-element hash (64 bytes, no personalization).
/// Used for key derivation intermediate steps only.
pub fn hash2_generic(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv(), a, b)
}

/// H_merkle(a, b) — Merkle tree internal node hash ("mrklSP__" IV).
pub fn hash2(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_merkle(), a, b)
}

/// H_commit(a, b, c, d) — 128-byte hash with commitment IV ("cmmtSP__").
fn hash4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let (c0, c1, c2, c3, c4, c5, c6, c7) = felt_to_u32x8(c);
    let (d0, d1, d2, d3, d4, d5, d6, d7) = felt_to_u32x8(d);

    let block1 = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let state = blake2s_compress(blake2s_iv_commit(), 64, block1);

    let block2 = BoxTrait::new([c0, c1, c2, c3, c4, c5, c6, c7, d0, d1, d2, d3, d4, d5, d6, d7]);
    let result = blake2s_finalize(state, 128, block2);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

// ── Protocol functions ───────────────────────────────────────────────

/// Derive commitment randomness from per-note seed: rcm = H(H("rcm"), rseed).
/// Domain-separated by the "rcm" tag in the first hash.
pub fn derive_rcm(rseed: felt252) -> felt252 {
    hash2_generic(hash1(0x72636D), rseed) // 0x72636D = "rcm"
}

/// Derive nullifier nonce from per-note seed: rho = H(H("rho"), rseed).
/// Used for outgoing view key recovery; NOT used in the nullifier itself
/// (v2 nullifiers are H(nk, cm), not H(nk, rho)).
pub fn derive_rho(rseed: felt252) -> felt252 {
    hash2_generic(hash1(0x72686F), rseed) // 0x72686F = "rho"
}

/// Note commitment: cm = H_commit(d_j, v, rcm, ak).
///
/// Binds to the diversified address (d_j), value, commitment randomness,
/// AND the authorization verifying key (ak). Binding ak into the commitment
/// prevents a delegated prover from substituting their own authorization
/// key — doing so would change cm, breaking the Merkle proof.
///
/// ak is a public key (not a secret), so including it here doesn't
/// compromise the spending/address separation.
pub fn commit(d_j: felt252, v: u64, rcm: felt252, ak: felt252) -> felt252 {
    hash4(d_j, v.into(), rcm, ak)
}

/// Nullifier: nf = H_null(nk, cm).
///
/// Binds the account-level nullifier key to this specific commitment.
/// Only the owner (who knows nk) can compute the nullifier. Since nk
/// is account-level (not per-note), the full viewing key holder can
/// also compute nullifiers to track spent/unspent status.
pub fn nullifier(nk: felt252, cm: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_nullifier(), nk, cm)
}
