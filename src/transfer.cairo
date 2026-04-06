/// Transfer circuit: N→2 JoinSplit (1 ≤ N ≤ 16).
///
/// # Public outputs
///   [root, nf_0..nf_{N-1}, cm_1, cm_2, auth_leaf_0..auth_leaf_{N-1},
///    memo_ct_hash_1, memo_ct_hash_2]
///
/// # Constraints per input
///   nk_tag_i = H_nktg(nk_spend_i)
///   owner_tag_i = H_owner(auth_root_i, nk_tag_i)
///   cm_i = H_commit(d_j_i, v_i, rcm_i, owner_tag_i)
///   cm_i in commitment tree under root
///   nf_i = H_nf(nk_spend_i, cm_i, pos_i)
///   auth_leaf_i in auth tree under auth_root_i
///
/// # Constraints on outputs
///   owner_tag = H_owner(auth_root, nk_tag)
///   cm = H_commit(d_j, v, rcm, owner_tag)
///
/// # Balance
///   sum(v_inputs) = v_1 + v_2

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

const MAX_INPUTS: u32 = 16;

pub fn verify(
    // --- public ---
    root: felt252,
    nf_list: Span<felt252>,
    cm_1: felt252,
    cm_2: felt252,
    // --- per-input parallel arrays ---
    nk_spend_list: Span<felt252>,
    auth_root_list: Span<felt252>,        // per-input auth tree root
    auth_leaf_hash_list: Span<felt252>,   // H(pk_i) — one-time key hash
    auth_siblings_flat: Span<felt252>,    // auth tree Merkle paths (flattened)
    auth_index_list: Span<u64>,           // index within auth tree
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    cm_siblings_flat: Span<felt252>,      // commitment tree Merkle paths
    cm_path_indices_list: Span<u64>,      // commitment tree positions (also nf pos)
    // --- output 1 ---
    d_j_1: felt252, v_1: u64, rseed_1: felt252, auth_root_1: felt252, nk_tag_1: felt252, memo_ct_hash_1: felt252,
    // --- output 2 ---
    d_j_2: felt252, v_2: u64, rseed_2: felt252, auth_root_2: felt252, nk_tag_2: felt252, memo_ct_hash_2: felt252,
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'transfer: need >= 1 input');
    assert(n <= MAX_INPUTS, 'transfer: too many inputs');
    assert(nk_spend_list.len() == n, 'transfer: nk_spend len');
    assert(auth_root_list.len() == n, 'transfer: auth_root len');
    assert(auth_leaf_hash_list.len() == n, 'transfer: auth_leaf len');
    assert(auth_index_list.len() == n, 'transfer: auth_idx len');
    assert(auth_siblings_flat.len() == n * merkle::AUTH_DEPTH, 'transfer: auth_sibs len');
    assert(d_j_in_list.len() == n, 'transfer: d_j len');
    assert(v_in_list.len() == n, 'transfer: v len');
    assert(rseed_in_list.len() == n, 'transfer: rseed len');
    assert(cm_path_indices_list.len() == n, 'transfer: path len');
    assert(cm_siblings_flat.len() == n * merkle::TREE_DEPTH, 'transfer: cm_sibs len');

    // ── Verify each input ────────────────────────────────────────────
    let mut sum_in: u128 = 0;
    let mut i: u32 = 0;
    while i < n {
        let nk_spend = *nk_spend_list.at(i);
        let auth_root = *auth_root_list.at(i);
        let auth_leaf_hash = *auth_leaf_hash_list.at(i);
        let auth_idx = *auth_index_list.at(i);
        let d_j = *d_j_in_list.at(i);
        let v: u64 = *v_in_list.at(i);
        let rseed = *rseed_in_list.at(i);
        let cm_path_idx = *cm_path_indices_list.at(i);

        // Verify nk_tag derives from nk_spend (binding check).
        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(auth_root, nk_tag);

        // Recompute commitment.
        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, otag);

        // Commitment tree membership.
        let cm_sib_start = i * merkle::TREE_DEPTH;
        let cm_siblings = cm_siblings_flat.slice(cm_sib_start, merkle::TREE_DEPTH);
        merkle::verify(cm, root, cm_siblings, cm_path_idx);

        // Auth tree membership — proves this one-time key belongs to the spender.
        let auth_sib_start = i * merkle::AUTH_DEPTH;
        let auth_siblings = auth_siblings_flat.slice(auth_sib_start, merkle::AUTH_DEPTH);
        merkle::verify_auth(auth_leaf_hash, auth_root, auth_siblings, auth_idx);

        // Position-dependent nullifier.
        let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
        assert(nf == *nf_list.at(i), 'transfer: bad nf');

        sum_in += v.into();
        i += 1;
    };

    // ── Pairwise nullifier distinctness ──────────────────────────────
    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'transfer: dup nullifier');
            b += 1;
        };
        a += 1;
    };

    // ── Verify output commitments ────────────────────────────────────
    let rcm_1 = hash::derive_rcm(rseed_1);
    let otag_1 = hash::owner_tag(auth_root_1, nk_tag_1);
    assert(hash::commit(d_j_1, v_1, rcm_1, otag_1) == cm_1, 'transfer: bad cm_1');

    let rcm_2 = hash::derive_rcm(rseed_2);
    let otag_2 = hash::owner_tag(auth_root_2, nk_tag_2);
    assert(hash::commit(d_j_2, v_2, rcm_2, otag_2) == cm_2, 'transfer: bad cm_2');

    // ── Balance conservation ─────────────────────────────────────────
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    // ── Public outputs ───────────────────────────────────────────────
    let mut outputs: Array<felt252> = array![root];
    let mut j: u32 = 0;
    while j < n { outputs.append(*nf_list.at(j)); j += 1; };
    outputs.append(cm_1);
    outputs.append(cm_2);
    // Output auth_leaf_hash per input (for contract-side signature verification)
    let mut j: u32 = 0;
    while j < n { outputs.append(*auth_leaf_hash_list.at(j)); j += 1; };
    outputs.append(memo_ct_hash_1);
    outputs.append(memo_ct_hash_2);
    outputs
}
