/// Shared test data for step executables (v2 key hierarchy with auth key tree).
///
/// # Key hierarchy
///
///   master_sk
///   ├── spend_seed → nk (account nullifier root), ask_base, ovk
///   │   ├── nk_spend_j = H_nksp(nk, d_j) — per-address secret nullifier key
///   │   │   └── nk_tag_j = H_nktg(nk_spend_j) — per-address public binding tag
///   │   └── ask_j = H(ask_base, j)
///   │       └── auth_leaf_i = H(H("auth-key", ask_j, i)) — one-time key hash
///   │       └── auth_root_j = MerkleRoot(auth_leaf_0, ..., auth_leaf_{K-1})
///   └── incoming_seed → dsk → d_j (diversified address)
///
/// Commitment: cm = H_commit(d_j, v, rcm, H_owner(auth_root_j, nk_tag_j))
/// Nullifier:  nf = H_nf(nk_spend_j, cm, pos)  — position-dependent
///
/// WARNING: Test keys are hardcoded and publicly known.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

// ── Account ──────────────────────────────────────────────────────────

#[derive(Drop, Copy)]
pub struct Account {
    pub nk: felt252,            // account nullifier root
    pub ask_base: felt252,      // authorization derivation root
    pub incoming_seed: felt252,  // root for address derivation
}

pub fn derive_account(master_sk: felt252) -> Account {
    let spend_seed = hash::hash2_generic(0x7370656E64, master_sk);   // "spend"
    let nk = hash::hash2_generic(0x6E6B, spend_seed);               // "nk"
    let ask_base = hash::hash2_generic(0x61736B, spend_seed);       // "ask"
    let incoming_seed = hash::hash2_generic(0x696E636F6D696E67, master_sk); // "incoming"
    Account { nk, ask_base, incoming_seed }
}

/// Per-address authorization secret.
pub fn derive_ask(ask_base: felt252, j: felt252) -> felt252 {
    hash::hash2_generic(ask_base, j)
}

// ── Address ──────────────────────────────────────────────────────────

/// Derive diversifier d_j.
pub fn derive_address(incoming_seed: felt252, j: felt252) -> felt252 {
    let dsk = hash::hash2_generic(0x64736B, incoming_seed); // "dsk"
    hash::hash2_generic(dsk, j)
}

/// Derive per-address nullifier keys from account nk and diversifier d_j.
pub fn derive_nk_keys(nk: felt252, d_j: felt252) -> (felt252, felt252) {
    let nk_spend = hash::derive_nk_spend(nk, d_j);
    let nk_tag = hash::derive_nk_tag(nk_spend);
    (nk_spend, nk_tag)
}

// ── Auth Key Tree ────────────────────────────────────────────────────

/// Derive the auth leaf hash for one-time key index i.
/// This is test witness data for the step executables.
/// The circuit takes auth_leaf_hash as an opaque input and only verifies
/// Merkle membership — it never computes the leaf itself.
/// The Rust wallet derives leaves as H(ML-DSA.KeyGen(seed_i).pk);
/// here we use a deterministic hash because Cairo has no ML-DSA library.
pub fn auth_leaf(ask_j: felt252, i: felt252) -> felt252 {
    let seed_i = hash::hash2_generic(
        hash::hash2_generic(0x617574682D6B6579, ask_j), // H("auth-key", ask_j)
        i,
    );
    hash::hash1(seed_i) // H(seed_i) stands in for H(pk_i)
}

/// Build the auth tree for address j and return (auth_root, leaves).
/// K = 2^AUTH_DEPTH leaves.
pub fn build_auth_tree(ask_j: felt252) -> (felt252, Array<felt252>) {
    let _k: u32 = 1;
    let mut leaves: Array<felt252> = array![];
    let mut i: u32 = 0;
    let total: u64 = pow2(merkle::AUTH_DEPTH);
    while i < total.try_into().unwrap() {
        leaves.append(auth_leaf(ask_j, i.into()));
        i += 1;
    };
    let root = compute_auth_root(leaves.span());
    (root, leaves)
}

fn pow2(n: u32) -> u64 {
    let mut r: u64 = 1;
    let mut i: u32 = 0;
    while i < n { r = r * 2; i += 1; };
    r
}

/// Compute Merkle root from leaves, padding with zero hashes.
fn compute_auth_root(leaves: Span<felt252>) -> felt252 {
    let mut zh: Array<felt252> = array![0];
    let mut i: u32 = 0;
    while i < merkle::AUTH_DEPTH {
        let prev = *zh.at(i);
        zh.append(hash::hash2(prev, prev));
        i += 1;
    };
    compute_level(leaves, 0, zh.span(), merkle::AUTH_DEPTH)
}

fn compute_level(level: Span<felt252>, depth: u32, zh: Span<felt252>, max_depth: u32) -> felt252 {
    if depth == max_depth {
        return if level.len() == 0 { *zh.at(max_depth) } else { *level.at(0) };
    }
    let mut next: Array<felt252> = array![];
    let mut i: u32 = 0;
    loop {
        let left = if i < level.len() { *level.at(i) } else { *zh.at(depth) };
        let right = if i + 1 < level.len() { *level.at(i + 1) } else { *zh.at(depth) };
        next.append(hash::hash2(left, right));
        i += 2;
        if i >= level.len() { break; }
    };
    compute_level(next.span(), depth + 1, zh, max_depth)
}

/// Get auth path (siblings) for leaf at given index.
pub fn auth_path(leaves: Span<felt252>, index: u32) -> Array<felt252> {
    let mut zh: Array<felt252> = array![0];
    let mut i: u32 = 0;
    while i < merkle::AUTH_DEPTH {
        let prev = *zh.at(i);
        zh.append(hash::hash2(prev, prev));
        i += 1;
    };
    let mut siblings: Array<felt252> = array![];
    let mut level: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < leaves.len() { level.append(*leaves.at(i)); i += 1; };

    let mut idx = index;
    let mut d: u32 = 0;
    while d < merkle::AUTH_DEPTH {
        let sib_idx = idx ^ 1;
        let sib = if sib_idx < level.len() { *level.at(sib_idx) } else { *zh.at(d) };
        siblings.append(sib);
        let mut next: Array<felt252> = array![];
        let mut i: u32 = 0;
        loop {
            let left = if i < level.len() { *level.at(i) } else { *zh.at(d) };
            let right = if i + 1 < level.len() { *level.at(i + 1) } else { *zh.at(d) };
            next.append(hash::hash2(left, right));
            i += 2;
            if i >= level.len() { break; }
        };
        level = next;
        idx = idx / 2;
        d += 1;
    };
    siblings
}

// ── Note ─────────────────────────────────────────────────────────────

#[derive(Drop, Copy)]
pub struct Note {
    pub nk_spend: felt252,
    pub nk_tag: felt252,
    pub auth_root: felt252,      // auth key tree root (replaces ak in owner_tag)
    pub auth_leaf_hash: felt252,  // H(pk_i) for the one-time key
    pub auth_key_idx: u32,        // index within auth tree
    pub d_j: felt252,
    pub v: u64,
    pub rseed: felt252,
    pub cm: felt252,
}

/// Auth data needed for spending: the auth tree leaves and the ask_j.
#[derive(Drop)]
pub struct AuthData {
    pub ask_j: felt252,
    pub auth_root: felt252,
    pub auth_leaves: Array<felt252>,
}

/// Build a note with auth tree data.
pub fn make_note(
    nk: felt252, auth_data: @AuthData, d_j: felt252, v: u64, rseed: felt252, key_idx: u32,
) -> Note {
    let (nk_spend, nk_tag) = derive_nk_keys(nk, d_j);
    let auth_root = auth_data.auth_root.clone();
    let auth_leaf_hash = auth_data.auth_leaves.at(key_idx).clone();
    let rcm = hash::derive_rcm(rseed);
    let otag = hash::owner_tag(auth_root, nk_tag);
    let cm = hash::commit(d_j, v, rcm, otag);
    Note { nk_spend, nk_tag, auth_root, auth_leaf_hash, auth_key_idx: key_idx, d_j, v, rseed, cm }
}

// ── Test accounts and notes ──────────────────────────────────────────

const MASTER_ALICE: felt252 = 0xA11CE;
const MASTER_BOB: felt252 = 0xB0B;
const MASTER_DUMMY: felt252 = 0xDEAD;

pub fn alice_account() -> Account { derive_account(MASTER_ALICE) }
pub fn bob_account() -> Account { derive_account(MASTER_BOB) }
pub fn dummy_account() -> Account { derive_account(MASTER_DUMMY) }

pub fn alice_addr_0() -> felt252 { derive_address(alice_account().incoming_seed, 0) }
pub fn alice_addr_1() -> felt252 { derive_address(alice_account().incoming_seed, 1) }
pub fn alice_addr_2() -> felt252 { derive_address(alice_account().incoming_seed, 2) }
pub fn bob_addr_0() -> felt252 { derive_address(bob_account().incoming_seed, 0) }
pub fn bob_addr_1() -> felt252 { derive_address(bob_account().incoming_seed, 1) }
pub fn dummy_addr_0() -> felt252 { derive_address(dummy_account().incoming_seed, 0) }
pub fn dummy_addr_1() -> felt252 { derive_address(dummy_account().incoming_seed, 1) }

pub fn alice_auth(j: felt252) -> AuthData {
    let ask_j = derive_ask(alice_account().ask_base, j);
    let (auth_root, auth_leaves) = build_auth_tree(ask_j);
    AuthData { ask_j, auth_root, auth_leaves }
}

pub fn bob_auth(j: felt252) -> AuthData {
    let ask_j = derive_ask(bob_account().ask_base, j);
    let (auth_root, auth_leaves) = build_auth_tree(ask_j);
    AuthData { ask_j, auth_root, auth_leaves }
}

pub fn dummy_auth(j: felt252) -> AuthData {
    let ask_j = derive_ask(dummy_account().ask_base, j);
    let (auth_root, auth_leaves) = build_auth_tree(ask_j);
    AuthData { ask_j, auth_root, auth_leaves }
}

// Test notes — each uses key_idx=0 for the one-time auth key.
pub fn note_a() -> (Note, AuthData) {
    let ad = alice_auth(0);
    (make_note(alice_account().nk, @ad, alice_addr_0(), 1000, 0x1001, 0), ad)
}
pub fn note_b() -> (Note, AuthData) {
    let ad = alice_auth(1);
    (make_note(alice_account().nk, @ad, alice_addr_1(), 500, 0x1002, 0), ad)
}
pub fn note_z() -> (Note, AuthData) {
    let ad = dummy_auth(0);
    (make_note(dummy_account().nk, @ad, dummy_addr_0(), 0, 0x1003, 0), ad)
}
pub fn note_c() -> (Note, AuthData) {
    let ad = bob_auth(0);
    (make_note(bob_account().nk, @ad, bob_addr_0(), 1500, 0x1004, 0), ad)
}
pub fn note_w() -> (Note, AuthData) {
    let ad = dummy_auth(1);
    (make_note(dummy_account().nk, @ad, dummy_addr_1(), 0, 0x1005, 0), ad)
}
pub fn note_d() -> (Note, AuthData) {
    let ad = alice_auth(2);
    (make_note(alice_account().nk, @ad, alice_addr_2(), 800, 0x1006, 0), ad)
}
pub fn note_e() -> (Note, AuthData) {
    let ad = bob_auth(1);
    (make_note(bob_account().nk, @ad, bob_addr_1(), 700, 0x1007, 0), ad)
}
