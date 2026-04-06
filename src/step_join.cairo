/// Step 3: Join A(1000) + B(500) → C(1500, bob) + W(0, dummy).
/// Also shields dummy note Z. Tree: [cm_a, cm_b, cm_z]

use starkprivacy::{common, shield, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();

    // Shield dummy note Z for later use in split.
    let (_, ak_z) = common::derive_ask(common::dummy_account().ask_base, 0);
    let sender: felt252 = 0xA11CE_ADD8;
    shield::verify(z.v, z.cm, ak_z, sender, z.d_j, z.rseed);

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm];
    let (sib_a, idx_a, root) = tree::auth_path(leaves.span(), 0, zh.span());
    let (sib_b, idx_b, _) = tree::auth_path(leaves.span(), 1, zh.span());

    // Both inputs are Alice's → same nk.
    let (_, ak_a) = common::derive_ask(common::alice_account().ask_base, 0);
    let (_, ak_b) = common::derive_ask(common::alice_account().ask_base, 1);

    transfer::verify(
        root, a.nf, b.nf, c.cm, w.cm,
        // input A (Alice)
        a.nk, ak_a, a.d_j, a.v, a.rseed, sib_a.span(), idx_a,
        // input B (Alice)
        b.nk, ak_b, b.d_j, b.v, b.rseed, sib_b.span(), idx_b,
        // output C (Bob), output W (Dummy)
        c.d_j, c.v, c.rseed, c.ak,
        w.d_j, w.v, w.rseed, w.ak,
    )
}
