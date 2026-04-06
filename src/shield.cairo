/// Shield circuit: deposit public tokens into a private note.
///
/// # Public outputs
///   - `v_pub`        — deposited amount
///   - `cm_new`       — new note commitment (appended to T)
///   - `ak`           — authorization verifying key
///   - `sender`       — depositor's address (prevents front-running)
///   - `memo_ct_hash` — hash of the encrypted memo ciphertext (prevents relay tampering)
///
/// # Constraint
///   cm_new = H_commit(d_j, v_pub, rcm, ak)
///
/// `memo_ct_hash` is computed client-side as H(ciphertext) and passed in
/// as a public input. The circuit does not touch the memo — it just commits
/// to the hash so the on-chain contract can verify the posted calldata matches.

use starkprivacy::blake_hash as hash;

pub fn verify(
    v_pub: u64,
    cm_new: felt252,
    ak: felt252,
    sender: felt252,
    memo_ct_hash: felt252,
    d_j: felt252,
    rseed: felt252,
) -> Array<felt252> {
    let rcm = hash::derive_rcm(rseed);
    assert(hash::commit(d_j, v_pub, rcm, ak) == cm_new, 'shield: bad commitment');

    array![v_pub.into(), cm_new, ak, sender, memo_ct_hash]
}
