(* WOTS+ w=4 (Winternitz One-Time Signature)
   133 hash chains: 128 message + 5 checksum
   Chain length: w-1 = 3 (base-4 digits, values 0..3)
   Hash: BLAKE2s with wotsSP__ personalization
   PK fold: BLAKE2s with pkfdSP__ personalization *)

let w = 4             (* Winternitz parameter *)
let n_msg = 128       (* message chains: 256 bits / 2 bits per digit *)
let n_csum = 5        (* checksum chains *)
let n_chains = 133    (* total = n_msg + n_csum *)
let chain_max = w - 1 (* = 3 *)

(* Apply hash chain: hash i times from value *)
let chain_hash v steps =
  let r = ref v in
  for _ = 1 to steps do
    r := Hash.hash_wots !r
  done;
  !r

(* Derive the i-th secret key element from seed *)
let derive_sk seed i =
  Hash.hash2 seed (Felt.of_int i)

(* KeyGen: derive public key (133 chain endpoints) from seed *)
let keygen seed =
  Array.init n_chains (fun i ->
    let sk_i = derive_sk seed i in
    chain_hash sk_i chain_max)

(* Fold a public key (133 felts) into a single felt via sequential left-fold *)
let fold_pk pk =
  assert (Array.length pk = n_chains);
  let acc = ref pk.(0) in
  for i = 1 to n_chains - 1 do
    acc := Hash.hash_pkfold !acc pk.(i)
  done;
  !acc

(* Decompose a 256-bit hash into base-4 digits (128 message + 5 checksum) *)
let decompose_sighash (h : bytes) =
  (* Extract 128 base-4 message digits from the hash (2 bits each, LSB first) *)
  let msg_digits = Array.make n_msg 0 in
  for i = 0 to n_msg - 1 do
    let byte_idx = i / 4 in
    let bit_ofs = (i mod 4) * 2 in
    let byte_val = Bytes.get_uint8 h byte_idx in
    msg_digits.(i) <- (byte_val lsr bit_ofs) land 3
  done;
  (* Compute checksum: sum of (w-1 - digit) for each message digit *)
  let csum = Array.fold_left (fun acc d -> acc + (chain_max - d)) 0 msg_digits in
  (* Decompose checksum into base-4 digits *)
  let csum_digits = Array.make n_csum 0 in
  let c = ref csum in
  for i = 0 to n_csum - 1 do
    csum_digits.(i) <- !c mod w;
    c := !c / w
  done;
  (* Concatenate *)
  let all = Array.make n_chains 0 in
  Array.blit msg_digits 0 all 0 n_msg;
  Array.blit csum_digits 0 all n_msg n_csum;
  all

(* Sign: given seed and sighash, produce signature (133 chain values) *)
let sign seed sighash =
  let digits = decompose_sighash sighash in
  Array.init n_chains (fun i ->
    let sk_i = derive_sk seed i in
    chain_hash sk_i digits.(i))

(* Verify: given signature, sighash, and public key *)
let verify sig_vals sighash pk =
  let digits = decompose_sighash sighash in
  let ok = ref true in
  for i = 0 to n_chains - 1 do
    let remaining = chain_max - digits.(i) in
    let computed_pk_i = chain_hash sig_vals.(i) remaining in
    if not (Felt.equal computed_pk_i pk.(i)) then
      ok := false
  done;
  !ok
