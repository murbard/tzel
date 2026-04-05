/// Step 1: Shield 1000 to Alice.
/// Tree: [] → [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let sender: felt252 = 0xA11CE_ADD8; // Alice's public address
    shield::verify(a.v, a.cm, sender, a.pk, a.rho, a.r)
}
