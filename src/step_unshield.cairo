/// Test executable: Unshield note A — withdraw 1000 to a recipient.
///
/// Demonstrates N=1 unshield with no change output.
/// The circuit proves Merkle membership, nullifier correctness,
/// and outputs the withdrawal amount + recipient address.
///
/// Tree state: [cm_a] (from step_shield)

use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let (_, ak) = common::derive_ask(common::alice_account().ask_base, 0);
    let recipient: felt252 = 0xCAFE;

    // Build Merkle tree with a single leaf and get auth path.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    // N=1: single-element arrays for all per-input data.
    // No change output (has_change=false, all change fields=0).
    unshield::verify(
        root,
        array![a.nf].span(),
        a.v,
        recipient,
        // per-input arrays (N=1)
        array![a.nk].span(),
        array![ak].span(),
        array![a.d_j].span(),
        array![a.v].span(),
        array![a.rseed].span(),
        siblings.span(),
        array![idx].span(),
        // no change output
        false, 0, 0, 0, 0, 0,
    )
}
