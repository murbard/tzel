/// Step 1: Shield 1000 to Alice at address 0.
/// Tree: [] → [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let (_, ak) = common::derive_ask(common::alice_account().ask_base, 0);
    let sender: felt252 = 0xA11CE_ADD8;
    shield::verify(a.v, a.cm, ak, sender, a.d_j, a.rseed)
}
