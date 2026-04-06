/// Test executable: Split C(1500) → D(800, alice) + E(700, bob).
///
/// Demonstrates N=1 transfer: single input split into two outputs.
/// No dummy notes needed — the N→2 circuit supports N=1 natively.
///
/// Tree state: [cm_a, cm_b, cm_z, cm_c, cm_w] → adds [cm_d, cm_e]

use starkprivacy::{common, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    // Reconstruct all prior notes to build the tree at this state.
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();
    let d = common::note_d();
    let e = common::note_e();

    // Build tree with 5 leaves and get auth path for C (index 3).
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm, c.cm, w.cm];
    let (sib_c, idx_c, root) = tree::auth_path(leaves.span(), 3, zh.span());

    let (_, ak_c) = common::derive_ask(common::bob_account().ask_base, 0);

    // N=1: single-element arrays. No dummy note needed!
    transfer::verify(
        root,
        array![c.nf].span(),
        d.cm, e.cm,
        // per-input (N=1)
        array![c.nk].span(),
        array![ak_c].span(),
        array![c.d_j].span(),
        array![c.v].span(),
        array![c.rseed].span(),
        sib_c.span(),
        array![idx_c].span(),
        // output D (Alice) + output E (Bob)
        d.d_j, d.v, d.rseed, d.ak, 0,
        e.d_j, e.v, e.rseed, e.ak, 0,
    )
}
