/// Shared test data for step executables (v2 key hierarchy).
///
/// # v2 key hierarchy
///
/// ```text
///   master_sk
///   ├── spend_seed → nk (account nullifier key), ask_base, ovk
///   └── incoming_seed → dsk (diversifier key), view_seed, det_seed
/// ```
///
/// - nk is ONE per account (not per-note like v1's nsk_i)
/// - Addresses are diversified: d_j = H("div", dsk, j)
/// - Commitment: cm = H_commit(d_j, v, rcm, ak)
/// - Nullifier: nf = H_null(nk, cm)
///
/// WARNING: Test keys are hardcoded and publicly known.

use starkprivacy::blake_hash as hash;

// ── Account ──────────────────────────────────────────────────────────

/// An account's spending-side keys (derived from master_sk).
#[derive(Drop, Copy)]
pub struct Account {
    pub nk: felt252,          // account nullifier key
    pub ask_base: felt252,    // base authorization secret
    pub incoming_seed: felt252, // root for address derivation
}

/// Derive an account from a master secret key.
pub fn derive_account(master_sk: felt252) -> Account {
    let spend_seed = hash::hash2_generic(0x7370656E64, master_sk);   // "spend"
    let nk = hash::hash2_generic(0x6E6B, spend_seed);               // "nk"
    let ask_base = hash::hash2_generic(0x61736B, spend_seed);       // "ask"
    let incoming_seed = hash::hash2_generic(0x696E636F6D696E67, master_sk); // "incoming"
    Account { nk, ask_base, incoming_seed }
}

/// Derive per-address authorization keys: ask_j = H(ask_base, j), ak_j = H(ask_j).
pub fn derive_ask(ask_base: felt252, j: felt252) -> (felt252, felt252) {
    let ask_j = hash::hash2_generic(ask_base, j);
    let ak_j = hash::hash1(ask_j);
    (ask_j, ak_j)
}

// ── Address ──────────────────────────────────────────────────────────

/// Derive a diversified address index. In the full protocol, the address
/// also includes ML-KEM public keys (ek_v, ek_d), but those are
/// application-layer and not used in circuits.
pub fn derive_address(incoming_seed: felt252, j: felt252) -> felt252 {
    let dsk = hash::hash2_generic(0x64736B, incoming_seed); // "dsk"
    hash::hash2_generic(dsk, j) // d_j = H(dsk, j)
}

// ── Note ─────────────────────────────────────────────────────────────

/// A note with all its data (spending and address material).
#[derive(Drop, Copy)]
pub struct Note {
    pub nk: felt252,     // account nullifier key
    pub ak: felt252,     // authorization verifying key (bound into commitment)
    pub d_j: felt252,    // diversified address
    pub v: u64,          // amount
    pub rseed: felt252,  // per-note randomness
    pub cm: felt252,     // commitment = H_commit(d_j, v, rcm, ak)
    pub nf: felt252,     // nullifier = H_null(nk, cm)
}

/// Build a note. ak is bound into the commitment to prevent prover substitution.
pub fn make_note(nk: felt252, ak: felt252, d_j: felt252, v: u64, rseed: felt252) -> Note {
    let rcm = hash::derive_rcm(rseed);
    let cm = hash::commit(d_j, v, rcm, ak);
    let nf = hash::nullifier(nk, cm);
    Note { nk, ak, d_j, v, rseed, cm, nf }
}

// ── Test accounts and notes ──────────────────────────────────────────

const MASTER_ALICE: felt252 = 0xA11CE;
const MASTER_BOB: felt252 = 0xB0B;
const MASTER_DUMMY: felt252 = 0xDEAD;

/// Alice's account (nk, ask_base, incoming_seed).
pub fn alice_account() -> Account { derive_account(MASTER_ALICE) }
pub fn bob_account() -> Account { derive_account(MASTER_BOB) }
pub fn dummy_account() -> Account { derive_account(MASTER_DUMMY) }

/// Alice's address at index 0.
pub fn alice_addr_0() -> felt252 { derive_address(alice_account().incoming_seed, 0) }
pub fn alice_addr_1() -> felt252 { derive_address(alice_account().incoming_seed, 1) }
pub fn alice_addr_2() -> felt252 { derive_address(alice_account().incoming_seed, 2) }
pub fn bob_addr_0() -> felt252 { derive_address(bob_account().incoming_seed, 0) }
pub fn bob_addr_1() -> felt252 { derive_address(bob_account().incoming_seed, 1) }
pub fn dummy_addr_0() -> felt252 { derive_address(dummy_account().incoming_seed, 0) }
pub fn dummy_addr_1() -> felt252 { derive_address(dummy_account().incoming_seed, 1) }

// Test scenario:
//   Step 1 (shield):   1000 → note A at alice_addr_0
//   Step 2 (unshield): withdraw note A
//   Step 3 (join):     A(1000) + B(500) → C(1500, bob) + W(0, dummy)
//                      also shields dummy note Z
//   Step 4 (split):    C(1500) + Z(0) → D(800, alice) + E(700, bob)

// Helper to get ak for a given account and address index.
fn alice_ak(j: felt252) -> felt252 { let (_, ak) = derive_ask(alice_account().ask_base, j); ak }
fn bob_ak(j: felt252) -> felt252 { let (_, ak) = derive_ask(bob_account().ask_base, j); ak }
fn dummy_ak(j: felt252) -> felt252 { let (_, ak) = derive_ask(dummy_account().ask_base, j); ak }

pub fn note_a() -> Note { make_note(alice_account().nk, alice_ak(0), alice_addr_0(), 1000, 0x1001) }
pub fn note_b() -> Note { make_note(alice_account().nk, alice_ak(1), alice_addr_1(), 500, 0x1002) }
pub fn note_z() -> Note { make_note(dummy_account().nk, dummy_ak(0), dummy_addr_0(), 0, 0x1003) }
pub fn note_c() -> Note { make_note(bob_account().nk, bob_ak(0), bob_addr_0(), 1500, 0x1004) }
pub fn note_w() -> Note { make_note(dummy_account().nk, dummy_ak(1), dummy_addr_1(), 0, 0x1005) }
pub fn note_d() -> Note { make_note(alice_account().nk, alice_ak(2), alice_addr_2(), 800, 0x1006) }
pub fn note_e() -> Note { make_note(bob_account().nk, bob_ak(1), bob_addr_1(), 700, 0x1007) }
