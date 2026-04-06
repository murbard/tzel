/// Shield circuit: deposit public tokens into a private note.
///
/// # Public outputs
///   - `v_pub`  — deposited amount
///   - `cm_new` — new note commitment (appended to T)
///   - `ak`     — authorization verifying key (contract verifies spend signature)
///   - `sender` — depositor's address (prevents front-running)
///
/// # Private inputs
///   - `d_j`   — diversified address index (identifies the recipient address)
///   - `rseed` — per-note randomness
///
/// # Constraint
///   rcm = derive_rcm(rseed)
///   cm_new = H_commit(d_j, v_pub, rcm, ak)

use starkprivacy::blake_hash as hash;

pub fn verify(
    v_pub: u64,
    cm_new: felt252,
    ak: felt252,
    sender: felt252,
    d_j: felt252,
    rseed: felt252,
) -> Array<felt252> {
    let rcm = hash::derive_rcm(rseed);
    assert(hash::commit(d_j, v_pub, rcm, ak) == cm_new, 'shield: bad commitment');

    array![v_pub.into(), cm_new, ak, sender]
}
