/// Unshield circuit: N→withdrawal + optional change (1 ≤ N ≤ 16).
///
/// # Public outputs
///   [root, nf_0..nf_{N-1}, v_pub, auth_leaf_0..auth_leaf_{N-1},
///    recipient, cm_change, memo_ct_hash_change]
///
/// # Constraints (per input)
///   nk_tag_i = H_nktg(nk_spend_i)
///   owner_tag_i = H_owner(auth_root_i, nk_tag_i)
///   cm_i = H_commit(d_j_i, v_i, rcm_i, owner_tag_i)
///   Merkle membership in commitment tree
///   nf_i = H_nf(nk_spend_i, cm_i, pos_i)
///   auth_leaf_i in auth tree under auth_root_i
///
/// # Change output
///   If has_change: cm_change = H_commit(d_j_c, v_change, rcm_c, H_owner(auth_root_c, nk_tag_c))
///   If !has_change: all change witness data = 0
///
/// # Balance: sum(v_inputs) = v_pub + v_change

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

const MAX_INPUTS: u32 = 16;

pub fn verify(
    // --- public ---
    root: felt252,
    nf_list: Span<felt252>,
    v_pub: u64,
    recipient: felt252,
    // --- per-input parallel arrays ---
    nk_spend_list: Span<felt252>,
    auth_root_list: Span<felt252>,
    auth_leaf_hash_list: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    auth_index_list: Span<u64>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    cm_siblings_flat: Span<felt252>,
    cm_path_indices_list: Span<u64>,
    // --- optional change output ---
    has_change: bool,
    d_j_change: felt252,
    v_change: u64,
    rseed_change: felt252,
    auth_root_change: felt252,
    nk_tag_change: felt252,
    memo_ct_hash_change: felt252,
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'unshield: need >= 1 input');
    assert(n <= MAX_INPUTS, 'unshield: too many inputs');
    assert(nk_spend_list.len() == n, 'unshield: nk_spend len');
    assert(auth_root_list.len() == n, 'unshield: auth_root len');
    assert(auth_leaf_hash_list.len() == n, 'unshield: auth_leaf len');
    assert(auth_index_list.len() == n, 'unshield: auth_idx len');
    assert(auth_siblings_flat.len() == n * merkle::AUTH_DEPTH, 'unshield: auth_sibs len');
    assert(d_j_in_list.len() == n, 'unshield: d_j len');
    assert(v_in_list.len() == n, 'unshield: v len');
    assert(rseed_in_list.len() == n, 'unshield: rseed len');
    assert(cm_path_indices_list.len() == n, 'unshield: path len');
    assert(cm_siblings_flat.len() == n * merkle::TREE_DEPTH, 'unshield: cm_sibs len');

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

        // Verify binding: nk_tag derives from nk_spend.
        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(auth_root, nk_tag);

        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, otag);

        // Commitment tree membership.
        let cm_sib_start = i * merkle::TREE_DEPTH;
        let cm_siblings = cm_siblings_flat.slice(cm_sib_start, merkle::TREE_DEPTH);
        merkle::verify(cm, root, cm_siblings, cm_path_idx);

        // Auth tree membership.
        let auth_sib_start = i * merkle::AUTH_DEPTH;
        let auth_siblings = auth_siblings_flat.slice(auth_sib_start, merkle::AUTH_DEPTH);
        merkle::verify_auth(auth_leaf_hash, auth_root, auth_siblings, auth_idx);

        // Position-dependent nullifier.
        let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
        assert(nf == *nf_list.at(i), 'unshield: bad nf');

        sum_in += v.into();
        i += 1;
    };

    // ── Pairwise nullifier distinctness ──────────────────────────────
    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'unshield: dup nf');
            b += 1;
        };
        a += 1;
    };

    // ── Change output (optional) ─────────────────────────────────────
    let cm_change = if has_change {
        let rcm_c = hash::derive_rcm(rseed_change);
        let otag_c = hash::owner_tag(auth_root_change, nk_tag_change);
        hash::commit(d_j_change, v_change, rcm_c, otag_c)
    } else {
        assert(v_change == 0, 'unshield: no change but v!=0');
        assert(memo_ct_hash_change == 0, 'unshield: mh!=0 but no change');
        assert(d_j_change == 0, 'unshield: d_j!=0 but no change');
        assert(rseed_change == 0, 'unshield: rseed!=0 no change');
        assert(auth_root_change == 0, 'unshield: ar!=0 but no change');
        assert(nk_tag_change == 0, 'unshield: nkt!=0 but no change');
        0
    };

    // ── Balance conservation ─────────────────────────────────────────
    let sum_out: u128 = v_pub.into() + v_change.into();
    assert(sum_in == sum_out, 'unshield: balance mismatch');

    // ── Public outputs ───────────────────────────────────────────────
    let mut outputs: Array<felt252> = array![root];
    let mut j: u32 = 0;
    while j < n { outputs.append(*nf_list.at(j)); j += 1; };
    outputs.append(v_pub.into());
    let mut j: u32 = 0;
    while j < n { outputs.append(*auth_leaf_hash_list.at(j)); j += 1; };
    outputs.append(recipient);
    outputs.append(cm_change);
    outputs.append(memo_ct_hash_change);
    outputs
}
