//! StarkPrivacy shared library — crypto, types, Merkle tree, API types.

use blake2s_simd::Params;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ml_kem::kem::{Encapsulate, TryDecapsulate};
use ml_kem::ml_kem_768;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════════════
// Core types
// ═══════════════════════════════════════════════════════════════════════

pub type F = [u8; 32];
pub const ZERO: F = [0u8; 32];
pub const DETECT_K: usize = 10;
pub const MEMO_SIZE: usize = 1024;
pub const DEPTH: usize = 16;

// ═══════════════════════════════════════════════════════════════════════
// Serde helpers — hex encoding for F and Vec<u8>
// ═══════════════════════════════════════════════════════════════════════

pub mod hex_f {
    use super::F;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(f: &F, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(f))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<F, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut f = [0u8; 32];
        f.copy_from_slice(&bytes);
        Ok(f)
    }
}

pub mod hex_f_vec {
    use super::F;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<F>, s: S) -> Result<S::Ok, S::Error> {
        let hexes: Vec<String> = v.iter().map(|f| hex::encode(f)).collect();
        hexes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<F>, D::Error> {
        let hexes: Vec<String> = Vec::deserialize(d)?;
        hexes
            .iter()
            .map(|s| {
                let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes"));
                }
                let mut f = [0u8; 32];
                f.copy_from_slice(&bytes);
                Ok(f)
            })
            .collect()
    }
}

pub mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// BLAKE2s hashing — personalized, 251-bit truncated
// ═══════════════════════════════════════════════════════════════════════

fn blake2s(personal: &[u8; 8], data: &[u8]) -> F {
    let digest = Params::new().hash_length(32).personal(personal).hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

fn blake2s_generic(data: &[u8]) -> F {
    let digest = Params::new().hash_length(32).hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

pub fn hash(data: &[u8]) -> F {
    blake2s_generic(data)
}

pub fn hash_two(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash(&buf)
}

pub fn hash_merkle(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    blake2s(b"mrklSP__", &buf)
}

fn hash_commit_raw(data: &[u8]) -> F {
    blake2s(b"cmmtSP__", data)
}

pub fn derive_rcm(rseed: &F) -> F {
    let mut tag = ZERO;
    tag[0] = 0x6D;
    tag[1] = 0x63;
    tag[2] = 0x72;
    hash_two(&hash(&tag), rseed)
}

pub fn derive_nk_spend(nk: &F, d_j: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(nk);
    buf[32..].copy_from_slice(d_j);
    blake2s(b"nkspSP__", &buf)
}

pub fn derive_nk_tag(nk_spend: &F) -> F {
    blake2s(b"nktgSP__", nk_spend)
}

pub fn owner_tag(ak: &F, nk_tag: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(ak);
    buf[32..].copy_from_slice(nk_tag);
    blake2s(b"ownrSP__", &buf)
}

pub fn commit(d_j: &F, v: u64, rcm: &F, otag: &F) -> F {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(d_j);
    buf[32..40].copy_from_slice(&v.to_le_bytes());
    buf[64..96].copy_from_slice(rcm);
    buf[96..128].copy_from_slice(otag);
    hash_commit_raw(&buf)
}

pub fn nullifier(nk_spend: &F, cm: &F, pos: u64) -> F {
    let mut buf1 = [0u8; 64];
    buf1[..32].copy_from_slice(cm);
    let mut pos_f = ZERO;
    pos_f[..8].copy_from_slice(&pos.to_le_bytes());
    buf1[32..].copy_from_slice(&pos_f);
    let cm_pos = blake2s(b"nulfSP__", &buf1);
    let mut buf2 = [0u8; 64];
    buf2[..32].copy_from_slice(nk_spend);
    buf2[32..].copy_from_slice(&cm_pos);
    blake2s(b"nulfSP__", &buf2)
}

pub fn memo_ct_hash(enc: &EncryptedNote) -> F {
    let mut buf = Vec::with_capacity(enc.ct_v.len() + enc.encrypted_data.len());
    buf.extend_from_slice(&enc.ct_v);
    buf.extend_from_slice(&enc.encrypted_data);
    blake2s(b"memoSP__", &buf)
}

pub fn short(f: &F) -> String {
    hex::encode(&f[..4])
}

// ═══════════════════════════════════════════════════════════════════════
// Key derivation
// ═══════════════════════════════════════════════════════════════════════

fn felt_tag(s: &[u8]) -> F {
    let mut val = 0u128;
    for &b in s {
        val = (val << 8) | b as u128;
    }
    let mut f = ZERO;
    let le = val.to_le_bytes();
    f[..16].copy_from_slice(&le);
    f
}

#[derive(Clone)]
pub struct Account {
    pub nk: F,
    pub ask_base: F,
    pub incoming_seed: F,
}

pub fn derive_account(master_sk: &F) -> Account {
    let spend_seed = hash_two(&felt_tag(b"spend"), master_sk);
    Account {
        nk: hash_two(&felt_tag(b"nk"), &spend_seed),
        ask_base: hash_two(&felt_tag(b"ask"), &spend_seed),
        incoming_seed: hash_two(&felt_tag(b"incoming"), master_sk),
    }
}

pub fn derive_address(incoming_seed: &F, j: u32) -> F {
    let dsk = hash_two(&felt_tag(b"dsk"), incoming_seed);
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    hash_two(&dsk, &idx)
}

pub fn derive_ak(ask_base: &F, j: u32) -> F {
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    hash(&hash_two(ask_base, &idx))
}

// ═══════════════════════════════════════════════════════════════════════
// ML-KEM-768 encryption + detection
// ═══════════════════════════════════════════════════════════════════════

pub type Ek = ml_kem_768::EncapsulationKey;
pub type Dk = ml_kem_768::DecapsulationKey;

pub fn kem_keygen_from_seed(seed: &[u8; 64]) -> (Ek, Dk) {
    let seed_arr = ml_kem::array::Array::from(*seed);
    let dk = ml_kem_768::DecapsulationKey::from_seed(seed_arr);
    let ek = dk.encapsulation_key().clone();
    (ek, dk)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    #[serde(with = "hex_bytes")]
    pub ct_d: Vec<u8>,
    pub tag: u16,
    #[serde(with = "hex_bytes")]
    pub ct_v: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub encrypted_data: Vec<u8>,
}

pub fn encrypt_note(
    v: u64,
    rseed: &F,
    user_memo: Option<&[u8]>,
    ek_v: &Ek,
    ek_d: &Ek,
) -> EncryptedNote {
    let (ct_d, ss_d): (ml_kem_768::Ciphertext, _) = ek_d.encapsulate();
    let tag_hash = hash(ss_d.as_slice());
    let tag = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);

    let mut plaintext = Vec::with_capacity(8 + 32 + MEMO_SIZE);
    plaintext.extend_from_slice(&v.to_le_bytes());
    plaintext.extend_from_slice(rseed);
    let mut memo_padded = vec![0u8; MEMO_SIZE];
    match user_memo {
        Some(m) => {
            let len = m.len().min(MEMO_SIZE);
            memo_padded[..len].copy_from_slice(&m[..len]);
        }
        None => {
            memo_padded[0] = 0xF6;
        }
    }
    plaintext.extend_from_slice(&memo_padded);

    let (ct_v, ss_v): (ml_kem_768::Ciphertext, _) = ek_v.encapsulate();
    let key = hash(ss_v.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext.as_slice())
        .unwrap();

    EncryptedNote {
        ct_d: ct_d.to_vec(),
        tag,
        ct_v: ct_v.to_vec(),
        encrypted_data,
    }
}

pub fn detect(enc: &EncryptedNote, dk_d: &Dk) -> bool {
    let Ok(ct) = ml_kem_768::Ciphertext::try_from(enc.ct_d.as_slice()) else {
        return false;
    };
    let ss = dk_d
        .try_decapsulate(&ct)
        .expect("ML-KEM decaps is infallible");
    let tag_hash = hash(ss.as_slice());
    let computed = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);
    computed == enc.tag
}

pub fn decrypt_memo(enc: &EncryptedNote, dk_v: &Dk) -> Option<(u64, F, Vec<u8>)> {
    let ct = ml_kem_768::Ciphertext::try_from(enc.ct_v.as_slice()).ok()?;
    let ss = dk_v.try_decapsulate(&ct).ok()?;
    let key = hash(ss.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let pt = cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), enc.encrypted_data.as_slice())
        .ok()?;
    if pt.len() != 8 + 32 + MEMO_SIZE {
        return None;
    }
    let v = u64::from_le_bytes(pt[..8].try_into().unwrap());
    let mut rseed = ZERO;
    rseed.copy_from_slice(&pt[8..40]);
    let user_memo = pt[40..].to_vec();
    Some((v, rseed, user_memo))
}

// ═══════════════════════════════════════════════════════════════════════
// Merkle tree
// ═══════════════════════════════════════════════════════════════════════

pub struct MerkleTree {
    pub leaves: Vec<F>,
    zero_hashes: Vec<F>,
}

impl MerkleTree {
    pub fn new() -> Self {
        let mut z = vec![ZERO];
        for i in 0..DEPTH {
            z.push(hash_merkle(&z[i], &z[i]));
        }
        Self {
            leaves: vec![],
            zero_hashes: z,
        }
    }

    pub fn append(&mut self, leaf: F) -> usize {
        let i = self.leaves.len();
        self.leaves.push(leaf);
        i
    }

    pub fn root(&self) -> F {
        self.compute_level(0, &self.leaves)
    }

    fn compute_level(&self, depth: usize, level: &[F]) -> F {
        if depth == DEPTH {
            return if level.is_empty() {
                self.zero_hashes[DEPTH]
            } else {
                level[0]
            };
        }
        let mut next = vec![];
        let mut i = 0;
        loop {
            let left = if i < level.len() {
                level[i]
            } else {
                self.zero_hashes[depth]
            };
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                self.zero_hashes[depth]
            };
            next.push(hash_merkle(&left, &right));
            i += 2;
            if i >= level.len() && !next.is_empty() {
                break;
            }
        }
        self.compute_level(depth + 1, &next)
    }

    pub fn auth_path(&self, index: usize) -> (Vec<F>, F) {
        let mut level = self.leaves.clone();
        let mut siblings = vec![];
        let mut idx = index;
        for d in 0..DEPTH {
            let sib_idx = idx ^ 1;
            siblings.push(if sib_idx < level.len() {
                level[sib_idx]
            } else {
                self.zero_hashes[d]
            });
            let mut next = vec![];
            let mut i = 0;
            loop {
                let left = if i < level.len() {
                    level[i]
                } else {
                    self.zero_hashes[d]
                };
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    self.zero_hashes[d]
                };
                next.push(hash_merkle(&left, &right));
                i += 2;
                if i >= level.len() {
                    break;
                }
            }
            level = next;
            idx /= 2;
        }
        (siblings, level[0])
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Note (wallet-side)
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    #[serde(with = "hex_f")]
    pub nk_spend: F,
    #[serde(with = "hex_f")]
    pub nk_tag: F,
    #[serde(with = "hex_f")]
    pub ak: F,
    #[serde(with = "hex_f")]
    pub d_j: F,
    pub v: u64,
    #[serde(with = "hex_f")]
    pub rseed: F,
    #[serde(with = "hex_f")]
    pub cm: F,
    pub index: usize,
}

// ═══════════════════════════════════════════════════════════════════════
// Proof enum
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Proof {
    TrustMeBro,
    Stark {
        #[serde(with = "hex_bytes")]
        data: Vec<u8>,
    },
}

// ═══════════════════════════════════════════════════════════════════════
// API types
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
pub struct FundReq {
    pub addr: String,
    pub amount: u64,
}

/// Payment address — everything a sender needs to create a note for the recipient.
#[derive(Clone, Serialize, Deserialize)]
pub struct PaymentAddress {
    #[serde(with = "hex_f")]
    pub d_j: F,
    #[serde(with = "hex_f")]
    pub ak: F,
    #[serde(with = "hex_f")]
    pub nk_tag: F,
    #[serde(with = "hex_bytes")]
    pub ek_v: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ek_d: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ShieldReq {
    pub sender: String,
    pub v: u64,
    pub address: PaymentAddress,
    pub memo: Option<String>,
    pub proof: Proof,
}

#[derive(Serialize, Deserialize)]
pub struct ShieldResp {
    #[serde(with = "hex_f")]
    pub cm: F,
    pub index: usize,
}

#[derive(Serialize, Deserialize)]
pub struct TransferReq {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    #[serde(with = "hex_f")]
    pub cm_1: F,
    #[serde(with = "hex_f")]
    pub cm_2: F,
    pub enc_1: EncryptedNote,
    pub enc_2: EncryptedNote,
    pub proof: Proof,
}

#[derive(Serialize, Deserialize)]
pub struct TransferResp {
    pub index_1: usize,
    pub index_2: usize,
}

#[derive(Serialize, Deserialize)]
pub struct UnshieldReq {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    pub v_pub: u64,
    pub recipient: String,
    #[serde(with = "hex_f")]
    pub cm_change: F,
    pub enc_change: Option<EncryptedNote>,
    pub proof: Proof,
}

#[derive(Serialize, Deserialize)]
pub struct UnshieldResp {
    pub change_index: Option<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct NoteMemo {
    pub index: usize,
    #[serde(with = "hex_f")]
    pub cm: F,
    pub enc: EncryptedNote,
}

#[derive(Serialize, Deserialize)]
pub struct NotesFeedResp {
    pub notes: Vec<NoteMemo>,
    pub next_cursor: usize,
}

#[derive(Serialize, Deserialize)]
pub struct TreeInfoResp {
    #[serde(with = "hex_f")]
    pub root: F,
    pub size: usize,
    pub depth: usize,
}

#[derive(Serialize, Deserialize)]
pub struct NullifiersResp {
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
}

#[derive(Serialize, Deserialize)]
pub struct BalanceResp {
    pub balances: HashMap<String, u64>,
}

// ═══════════════════════════════════════════════════════════════════════
// Ledger state
// ═══════════════════════════════════════════════════════════════════════

pub struct Ledger {
    pub tree: MerkleTree,
    pub nullifiers: HashSet<F>,
    pub balances: HashMap<String, u64>,
    pub valid_roots: HashSet<F>,
    pub memos: Vec<(F, EncryptedNote)>,
}

impl Ledger {
    pub fn new() -> Self {
        let tree = MerkleTree::new();
        let mut roots = HashSet::new();
        roots.insert(tree.root());
        Self {
            tree,
            nullifiers: HashSet::new(),
            balances: HashMap::new(),
            valid_roots: roots,
            memos: vec![],
        }
    }

    fn snapshot_root(&mut self) {
        self.valid_roots.insert(self.tree.root());
    }

    fn post_note(&mut self, cm: F, enc: EncryptedNote) {
        self.memos.push((cm, enc));
    }

    pub fn fund(&mut self, addr: &str, amount: u64) {
        *self.balances.entry(addr.into()).or_default() += amount;
    }

    pub fn shield(&mut self, req: &ShieldReq) -> Result<ShieldResp, String> {
        let bal = self.balances.get(&req.sender).copied().unwrap_or(0);
        if bal < req.v {
            return Err("insufficient balance".into());
        }

        let ek_v = ml_kem_768::EncapsulationKey::new(
            req.address
                .ek_v
                .as_slice()
                .try_into()
                .map_err(|_| "bad ek_v length")?,
        )
        .map_err(|_| "invalid ek_v")?;
        let ek_d = ml_kem_768::EncapsulationKey::new(
            req.address
                .ek_d
                .as_slice()
                .try_into()
                .map_err(|_| "bad ek_d length")?,
        )
        .map_err(|_| "invalid ek_d")?;

        let mut rng = rand::rng();
        let rseed: F = rng.random();
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(&req.address.ak, &req.address.nk_tag);
        let cm = commit(&req.address.d_j, req.v, &rcm, &otag);

        *self.balances.get_mut(&req.sender).unwrap() -= req.v;
        let index = self.tree.append(cm);
        self.snapshot_root();

        let memo_bytes = req.memo.as_ref().map(|s| s.as_bytes());
        self.post_note(cm, encrypt_note(req.v, &rseed, memo_bytes, &ek_v, &ek_d));

        Ok(ShieldResp { cm, index })
    }

    pub fn transfer(&mut self, req: &TransferReq) -> Result<TransferResp, String> {
        let n = req.nullifiers.len();
        if n == 0 || n > 16 {
            return Err("bad nullifier count".into());
        }
        if !self.valid_roots.contains(&req.root) {
            return Err("invalid root".into());
        }
        for nf in &req.nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(format!("nullifier {} already spent", short(nf)));
            }
        }
        for i in 0..n {
            for j in i + 1..n {
                if req.nullifiers[i] == req.nullifiers[j] {
                    return Err("duplicate nullifier".into());
                }
            }
        }

        // In TrustMeBro mode we cannot verify balance conservation (values are private).
        // With a real Stark proof, the proof covers this.
        match &req.proof {
            Proof::TrustMeBro => {} // skip STARK verification
            Proof::Stark { .. } => {
                // TODO: verify STARK proof against transfer program hash
                return Err("STARK verification not yet implemented".into());
            }
        }

        let index_1 = self.tree.append(req.cm_1);
        let index_2 = self.tree.append(req.cm_2);
        for nf in &req.nullifiers {
            self.nullifiers.insert(*nf);
        }
        self.post_note(req.cm_1, req.enc_1.clone());
        self.post_note(req.cm_2, req.enc_2.clone());
        self.snapshot_root();

        Ok(TransferResp { index_1, index_2 })
    }

    pub fn unshield(&mut self, req: &UnshieldReq) -> Result<UnshieldResp, String> {
        let n = req.nullifiers.len();
        if n == 0 || n > 16 {
            return Err("bad nullifier count".into());
        }
        if !self.valid_roots.contains(&req.root) {
            return Err("invalid root".into());
        }
        for nf in &req.nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(format!("nullifier {} already spent", short(nf)));
            }
        }
        for i in 0..n {
            for j in i + 1..n {
                if req.nullifiers[i] == req.nullifiers[j] {
                    return Err("duplicate nullifier".into());
                }
            }
        }

        match &req.proof {
            Proof::TrustMeBro => {}
            Proof::Stark { .. } => {
                return Err("STARK verification not yet implemented".into());
            }
        }

        let change_index = if req.cm_change != ZERO {
            let enc = req
                .enc_change
                .as_ref()
                .ok_or("change cm without encrypted note")?;
            let idx = self.tree.append(req.cm_change);
            self.post_note(req.cm_change, enc.clone());
            Some(idx)
        } else {
            None
        };

        for nf in &req.nullifiers {
            self.nullifiers.insert(*nf);
        }
        *self.balances.entry(req.recipient.clone()).or_default() += req.v_pub;
        self.snapshot_root();

        Ok(UnshieldResp { change_index })
    }
}
