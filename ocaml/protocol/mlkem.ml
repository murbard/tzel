(* ML-KEM-768 (FIPS 203) via mlkem-native C FFI.
   Deterministic keygen from 64-byte seed matches the Rust reference
   implementation's DecapsulationKey::from_seed. *)

let ek_size = 1184
let dk_size = 2400
let ct_size = 1088
let ss_size = 32

type encapsulation_key = bytes
type decapsulation_key = bytes
type ciphertext = bytes
type shared_secret = bytes

(* C FFI bindings to mlkem-native *)
external c_keypair_derand : bytes -> bytes * bytes = "caml_mlkem768_keypair_derand"
external c_encaps : bytes -> bytes * bytes = "caml_mlkem768_encaps"
external c_encaps_derand : bytes -> bytes -> bytes * bytes = "caml_mlkem768_encaps_derand"
external c_decaps : bytes -> bytes -> bytes = "caml_mlkem768_decaps"

(* Deterministic key generation from 64-byte seed.
   seed = d(32) || z(32) per FIPS 203.
   Returns (encapsulation_key, decapsulation_key). *)
let keygen_det (seed_64 : bytes) : encapsulation_key * decapsulation_key =
  assert (Bytes.length seed_64 = 64);
  c_keypair_derand seed_64

(* Randomized encapsulation: produces (shared_secret, ciphertext). *)
let encaps (ek : encapsulation_key) : shared_secret * ciphertext =
  assert (Bytes.length ek = ek_size);
  c_encaps ek

(* Deterministic encapsulation with 32-byte coins. *)
let encaps_derand (ek : encapsulation_key) (coins : bytes) : shared_secret * ciphertext =
  assert (Bytes.length ek = ek_size);
  assert (Bytes.length coins = 32);
  c_encaps_derand ek coins

(* Decapsulation: recover shared secret from ciphertext + decapsulation key. *)
let decaps (dk : decapsulation_key) (ct : ciphertext) : shared_secret =
  assert (Bytes.length dk = dk_size);
  assert (Bytes.length ct = ct_size);
  c_decaps dk ct

(* ── Deterministic seed derivation per spec ── *)

(* ML-KEM view key seed derivation (spec steps 2-5):
   view_h1 = H(TAG_MLKEM_V, view_root)
   view_h2 = H(view_h1, j_felt)
   seed_v_j = view_h2 || H(TAG_MLKEM_V2, view_h2)  (64 bytes) *)
let derive_view_seed (view_root : Felt.t) (j : int) : bytes =
  let j_felt = Felt.of_int j in
  let view_h1 = Hash.hash2 Hash.tag_mlkem_v view_root in
  let view_h2 = Hash.hash2 view_h1 j_felt in
  let second_half = Hash.hash2 Hash.tag_mlkem_v2 view_h2 in
  let seed = Bytes.create 64 in
  Bytes.blit view_h2 0 seed 0 32;
  Bytes.blit second_half 0 seed 32 32;
  seed

(* ML-KEM detect key seed derivation (spec steps 6-9):
   detect_h1 = H(TAG_MLKEM_D, detect_root)
   detect_h2 = H(detect_h1, j_felt)
   seed_d_j = detect_h2 || H(TAG_MLKEM_D2, detect_h2)  (64 bytes) *)
let derive_detect_seed (detect_root : Felt.t) (j : int) : bytes =
  let j_felt = Felt.of_int j in
  let detect_h1 = Hash.hash2 Hash.tag_mlkem_d detect_root in
  let detect_h2 = Hash.hash2 detect_h1 j_felt in
  let second_half = Hash.hash2 Hash.tag_mlkem_d2 detect_h2 in
  let seed = Bytes.create 64 in
  Bytes.blit detect_h2 0 seed 0 32;
  Bytes.blit second_half 0 seed 32 32;
  seed

(* Derive view keypair for address j *)
let derive_view_keypair (view_root : Felt.t) (j : int) : encapsulation_key * decapsulation_key =
  keygen_det (derive_view_seed view_root j)

(* Derive detect keypair for address j *)
let derive_detect_keypair (detect_root : Felt.t) (j : int) : encapsulation_key * decapsulation_key =
  keygen_det (derive_detect_seed detect_root j)
