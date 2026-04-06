/// Test executable: Shield 1000 to Alice at address 0.
///
/// Proves cm = H_commit(d_j, v_pub, rcm, ak) — the commitment
/// contains the actual deposited amount. Without this proof,
/// an attacker could deposit 1 but commit to v=100.
///
/// The memo_ct_hash is a placeholder (0xDEAD) — in production this
/// would be H(ciphertext) computed client-side before proving.
///
/// Tree state: [] → [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let (_, ak) = common::derive_ask(common::alice_account().ask_base, 0);
    let sender: felt252 = 0xA11CE_ADD8;
    let memo_ct_hash: felt252 = 0xDEAD; // placeholder
    shield::verify(a.v, a.cm, ak, sender, memo_ct_hash, a.d_j, a.rseed)
}
