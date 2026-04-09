(* Key hierarchy for StarkPrivacy v2.
   Domain tags are fixed ASCII-packed felt constants (not hashed strings).

   master_sk
   ├── spend_seed = H(TAG_SPEND, master_sk)
   │   ├── nk         = H(TAG_NK,  spend_seed)
   │   │   └── nk_spend_j = H_nksp(nk, d_j)
   │   │       └── nk_tag_j  = H_nktg(nk_spend_j)
   │   ├── ask_base   = H(TAG_ASK, spend_seed)
   │   │   └── ask_j  = H(ask_base, j)
   │   │       └── seed_i = H(H(TAG_AUTH_KEY, ask_j), i_felt)
   │
   └── incoming_seed = H(TAG_INCOMING, master_sk)
       ├── dsk         = H(TAG_DSK, incoming_seed)
       │   └── d_j     = H(dsk, j)
       ├── view_root   = H(TAG_VIEW, incoming_seed)
       └── detect_root = H(TAG_DETECT, view_root)  *)

let auth_depth = 10
let auth_tree_size = 1 lsl auth_depth  (* 1024 *)

type account_keys = {
  nk : Felt.t;
  ask_base : Felt.t;
  dsk : Felt.t;
  incoming_seed : Felt.t;
  view_root : Felt.t;
  detect_root : Felt.t;
}

type address = {
  index : int;
  d_j : Felt.t;
  auth_root : Felt.t;
  nk_tag : Felt.t;
  nk_spend : Felt.t;
  ask_j : Felt.t;
  ek_v : Mlkem.encapsulation_key;
  dk_v : Mlkem.decapsulation_key;
  ek_d : Mlkem.encapsulation_key;
  dk_d : Mlkem.decapsulation_key;
}

type payment_address = {
  pa_d_j : Felt.t;
  pa_auth_root : Felt.t;
  pa_nk_tag : Felt.t;
  pa_ek_v : Mlkem.encapsulation_key;
  pa_ek_d : Mlkem.encapsulation_key;
}

let derive master_sk =
  let spend_seed = Hash.hash2 Hash.tag_spend master_sk in
  let incoming_seed = Hash.hash2 Hash.tag_incoming master_sk in
  let nk = Hash.hash2 Hash.tag_nk spend_seed in
  let ask_base = Hash.hash2 Hash.tag_ask spend_seed in
  let dsk = Hash.hash2 Hash.tag_dsk incoming_seed in
  let view_root = Hash.hash2 Hash.tag_view incoming_seed in
  let detect_root = Hash.hash2 Hash.tag_detect view_root in
  { nk; ask_base; dsk; incoming_seed; view_root; detect_root }

let derive_diversifier keys j =
  Hash.hash2 keys.dsk (Felt.of_int j)

let derive_ask keys j =
  Hash.hash2 keys.ask_base (Felt.of_int j)

let derive_nk_spend keys d_j =
  Hash.hash_nk_spend keys.nk d_j

let derive_nk_tag nk_spend =
  Hash.hash_nk_tag nk_spend

let derive_wots_seed ask_j i =
  let auth_key_inner = Hash.hash2 Hash.tag_auth_key ask_j in
  Hash.hash2 auth_key_inner (Felt.of_int i)

let build_auth_tree ask_j =
  let leaves = Array.init auth_tree_size (fun i ->
    let seed_i = derive_wots_seed ask_j i in
    let pk_i = Wots.keygen seed_i in
    Wots.fold_pk pk_i) in
  let leaf_list = Array.to_list leaves in
  let root = Merkle.root_of_leaves ~depth:auth_depth leaf_list in
  (root, leaves)

let derive_address keys j =
  let d_j = derive_diversifier keys j in
  let ask_j = derive_ask keys j in
  let nk_spend = derive_nk_spend keys d_j in
  let nk_tag = derive_nk_tag nk_spend in
  let (auth_root, _leaves) = build_auth_tree ask_j in
  let (ek_v, dk_v) = Mlkem.derive_view_keypair keys.view_root j in
  let (ek_d, dk_d) = Mlkem.derive_detect_keypair keys.detect_root j in
  { index = j; d_j; auth_root; nk_tag; nk_spend; ask_j;
    ek_v; dk_v; ek_d; dk_d }

let to_payment_address addr =
  { pa_d_j = addr.d_j;
    pa_auth_root = addr.auth_root;
    pa_nk_tag = addr.nk_tag;
    pa_ek_v = addr.ek_v;
    pa_ek_d = addr.ek_d }

let owner_tag addr =
  Hash.hash_owner addr.auth_root addr.nk_tag
