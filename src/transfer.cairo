/// Transfer circuit: 2-in-2-out JoinSplit (v2).
///
/// # Public outputs
///   - `root`   — Merkle root
///   - `nf_a`   — nullifier of input A
///   - `nf_b`   — nullifier of input B
///   - `cm_1`   — output commitment 1
///   - `cm_2`   — output commitment 2
///   - `ak_a`   — auth key for input A (contract verifies signature)
///   - `ak_b`   — auth key for input B
///
/// # Key change from v1
///
/// nk is account-level (one per account), not per-note. The nullifier is
/// H(nk, cm) — binding the account key to the specific commitment. The
/// commitment binds to the diversified address d_j, not to spending keys.
///
/// For delegated proving: the prover receives nk (view-level material,
/// equivalent to public info since NF_set is on-chain). They cannot
/// spend without ask.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    // --- public ---
    root: felt252,
    nf_a: felt252,
    nf_b: felt252,
    cm_1: felt252,
    cm_2: felt252,
    // --- input A ---
    nk_a: felt252,
    ak_a: felt252,
    d_j_a: felt252,
    v_a: u64,
    rseed_a: felt252,
    siblings_a: Span<felt252>,
    path_indices_a: u64,
    // --- input B ---
    nk_b: felt252,
    ak_b: felt252,
    d_j_b: felt252,
    v_b: u64,
    rseed_b: felt252,
    siblings_b: Span<felt252>,
    path_indices_b: u64,
    // --- output 1 ---
    d_j_1: felt252,
    v_1: u64,
    rseed_1: felt252,
    ak_1: felt252,
    // --- output 2 ---
    d_j_2: felt252,
    v_2: u64,
    rseed_2: felt252,
    ak_2: felt252,
) -> Array<felt252> {
    // ── Input A: recompute cm, verify Merkle, check nullifier ────────
    let rcm_a = hash::derive_rcm(rseed_a);
    let cm_a = hash::commit(d_j_a, v_a, rcm_a, ak_a);
    merkle::verify(cm_a, root, siblings_a, path_indices_a);
    assert(hash::nullifier(nk_a, cm_a) == nf_a, 'transfer: bad nf_a');

    // ── Input B ──────────────────────────────────────────────────────
    let rcm_b = hash::derive_rcm(rseed_b);
    let cm_b = hash::commit(d_j_b, v_b, rcm_b, ak_b);
    merkle::verify(cm_b, root, siblings_b, path_indices_b);
    assert(hash::nullifier(nk_b, cm_b) == nf_b, 'transfer: bad nf_b');

    // ── Same-note double-spend prevention ────────────────────────────
    assert(nf_a != nf_b, 'transfer: duplicate nullifier');

    // ── Output commitments ───────────────────────────────────────────
    let rcm_1 = hash::derive_rcm(rseed_1);
    assert(hash::commit(d_j_1, v_1, rcm_1, ak_1) == cm_1, 'transfer: bad cm_1');
    let rcm_2 = hash::derive_rcm(rseed_2);
    assert(hash::commit(d_j_2, v_2, rcm_2, ak_2) == cm_2, 'transfer: bad cm_2');

    // ── Balance conservation (u128 prevents overflow) ────────────────
    let sum_in: u128 = v_a.into() + v_b.into();
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    array![root, nf_a, nf_b, cm_1, cm_2, ak_a, ak_b]
}
