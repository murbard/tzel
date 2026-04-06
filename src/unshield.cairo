/// Unshield circuit: withdraw a private note to a public address.
///
/// # Public outputs
///   - `root`      — Merkle root of T
///   - `nf`        — nullifier (added to NF_set)
///   - `v_pub`     — withdrawn amount
///   - `ak`        — authorization key (contract verifies signature)
///   - `recipient` — destination address (prevents front-running)
///
/// # Private inputs
///   - `nk`            — account nullifier key
///   - `d_j`           — diversified address
///   - `rseed`         — per-note randomness
///   - `siblings`      — Merkle authentication path
///   - `path_indices`  — leaf position bitmask
///
/// # Constraints
///   1. rcm = derive_rcm(rseed)
///   2. cm  = H_commit(d_j, v_pub, rcm, ak)
///   3. cm is in T under root
///   4. nf  = H_null(nk, cm)

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    root: felt252,
    nf: felt252,
    v_pub: u64,
    ak: felt252,
    recipient: felt252,
    nk: felt252,
    d_j: felt252,
    rseed: felt252,
    siblings: Span<felt252>,
    path_indices: u64,
) -> Array<felt252> {
    // Recompute commitment from note data.
    let rcm = hash::derive_rcm(rseed);
    let cm = hash::commit(d_j, v_pub, rcm, ak);

    // Verify Merkle membership.
    merkle::verify(cm, root, siblings, path_indices);

    // Verify nullifier: nf = H(nk, cm). Account-level nk, not per-note.
    assert(hash::nullifier(nk, cm) == nf, 'unshield: bad nullifier');

    array![root, nf, v_pub.into(), ak, recipient]
}
