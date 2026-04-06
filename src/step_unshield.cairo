/// Step 2: Unshield note A — withdraw 1000 to a recipient.
/// Tree: [cm_a]

use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let (_, ak) = common::derive_ask(common::alice_account().ask_base, 0);
    let recipient: felt252 = 0xCAFE;

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    unshield::verify(root, a.nf, a.v, ak, recipient, a.nk, a.d_j, a.rseed, siblings.span(), idx)
}
