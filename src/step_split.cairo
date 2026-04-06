/// Step 4: Split C(1500) + Z(0) → D(800, alice) + E(700, bob).
/// Tree: [cm_a, cm_b, cm_z, cm_c, cm_w]
///
/// C belongs to Bob, Z belongs to Dummy — different accounts, different nk.
/// The v2 transfer circuit takes per-input nk, supporting cross-account inputs.

use starkprivacy::{common, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();
    let d = common::note_d();
    let e = common::note_e();

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm, c.cm, w.cm];
    let (sib_c, idx_c, root) = tree::auth_path(leaves.span(), 3, zh.span());
    let (sib_z, idx_z, _) = tree::auth_path(leaves.span(), 2, zh.span());

    let (_, ak_c) = common::derive_ask(common::bob_account().ask_base, 0);
    let (_, ak_z) = common::derive_ask(common::dummy_account().ask_base, 0);

    transfer::verify(
        root, c.nf, z.nf, d.cm, e.cm,
        // input C (Bob's nk)
        c.nk, ak_c, c.d_j, c.v, c.rseed, sib_c.span(), idx_c,
        // input Z (Dummy's nk — different account!)
        z.nk, ak_z, z.d_j, z.v, z.rseed, sib_z.span(), idx_z,
        // output D (Alice), output E (Bob)
        d.d_j, d.v, d.rseed, d.ak,
        e.d_j, e.v, e.rseed, e.ak,
    )
}
