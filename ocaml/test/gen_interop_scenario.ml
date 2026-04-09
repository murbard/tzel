let fixed_felt seed =
  let b = Bytes.init 32 (fun i -> Char.chr ((seed + i) land 0xFF)) in
  Bytes.set_uint8 b 31 (Bytes.get_uint8 b 31 land 0x07);
  b

let fixed_bytes seed =
  Bytes.init 32 (fun i -> Char.chr ((seed + i) land 0xFF))

let payment_address_wire_of_addr (addr : Tzel.Keys.address) =
  let pa = Tzel.Keys.to_payment_address addr in
  let wire : Tzel.Encoding.payment_address_wire = {
    d_j = pa.pa_d_j;
    auth_root = pa.pa_auth_root;
    nk_tag = pa.pa_nk_tag;
    ek_v = pa.pa_ek_v;
    ek_d = pa.pa_ek_d;
  } in
  wire

let deterministic_encrypted_note (addr : Tzel.Keys.address) ~v ~rseed ~memo ~detect_seed ~view_seed =
  let (ss_d, ct_d) = Tzel.Mlkem.encaps_derand addr.ek_d (fixed_bytes detect_seed) in
  let tag = Tzel.Detection.compute_tag ss_d in
  let (ss_v, ct_v) = Tzel.Mlkem.encaps_derand addr.ek_v (fixed_bytes view_seed) in
  let encrypted_data = Tzel.Detection.encrypt_memo ~ss_v ~v ~rseed ~memo in
  let enc : Tzel.Encoding.encrypted_note = { ct_d; tag; ct_v; encrypted_data } in
  let memo_ct_hash = Tzel.Encoding.compute_memo_ct_hash enc in
  (enc, memo_ct_hash)

let json_felt f = `String (Tzel.Felt.to_hex f)

let json_felt_list xs = `List (List.map json_felt xs)

let () =
  let auth_domain = Tzel.Hash.hash_bytes (Bytes.of_string "tzel-auth-domain-local-dev-v1") in
  let initial_alice_balance = 100 in

  let alice_keys = Tzel.Keys.derive (fixed_felt 0x11) in
  let bob_keys = Tzel.Keys.derive (fixed_felt 0x55) in

  let alice_addr0 = Tzel.Keys.derive_address alice_keys 0 in
  let alice_addr1 = Tzel.Keys.derive_address alice_keys 1 in
  let bob_addr0 = Tzel.Keys.derive_address bob_keys 0 in

  let shield_rseed = fixed_felt 0x21 in
  let shield_note = Tzel.Note.create alice_addr0 100L shield_rseed in
  let (shield_enc, shield_memo_ct_hash) =
    deterministic_encrypted_note alice_addr0
      ~v:100L
      ~rseed:shield_rseed
      ~memo:(Bytes.of_string "interop-shield")
      ~detect_seed:0x31
      ~view_seed:0x41
  in

  let tree = Tzel.Merkle.create_with_leaves ~depth:48 in
  ignore (Tzel.Merkle.append_with_leaves tree shield_note.cm);
  let root_after_shield = Tzel.Merkle.root_with_leaves tree in
  let shield_nf = Tzel.Note.nullifier alice_addr0.nk_spend shield_note.cm 0 in

  let transfer_rseed_1 = fixed_felt 0x22 in
  let transfer_rseed_2 = fixed_felt 0x23 in
  let transfer_note_1 = Tzel.Note.create alice_addr1 60L transfer_rseed_1 in
  let transfer_note_2 = Tzel.Note.create bob_addr0 40L transfer_rseed_2 in
  let (transfer_enc_1, transfer_memo_ct_hash_1) =
    deterministic_encrypted_note alice_addr1
      ~v:60L
      ~rseed:transfer_rseed_1
      ~memo:(Bytes.of_string "interop-change")
      ~detect_seed:0x32
      ~view_seed:0x42
  in
  let (transfer_enc_2, transfer_memo_ct_hash_2) =
    deterministic_encrypted_note bob_addr0
      ~v:40L
      ~rseed:transfer_rseed_2
      ~memo:(Bytes.of_string "interop-bob")
      ~detect_seed:0x33
      ~view_seed:0x43
  in

  ignore (Tzel.Merkle.append_with_leaves tree transfer_note_1.cm);
  ignore (Tzel.Merkle.append_with_leaves tree transfer_note_2.cm);
  let root_after_transfer = Tzel.Merkle.root_with_leaves tree in
  let bob_nf = Tzel.Note.nullifier bob_addr0.nk_spend transfer_note_2.cm 2 in

  let json =
    `Assoc [
      "auth_domain", json_felt auth_domain;
      "initial_alice_balance", `Int initial_alice_balance;
      "shield", `Assoc [
        "sender", `String "alice";
        "v", `Int 100;
        "address", Tzel.Encoding.payment_address_to_json (payment_address_wire_of_addr alice_addr0);
        "cm", json_felt shield_note.cm;
        "enc", Tzel.Encoding.encrypted_note_to_json shield_enc;
        "memo_ct_hash", json_felt shield_memo_ct_hash;
      ];
      "transfer", `Assoc [
        "root", json_felt root_after_shield;
        "nullifiers", json_felt_list [shield_nf];
        "cm_1", json_felt transfer_note_1.cm;
        "cm_2", json_felt transfer_note_2.cm;
        "enc_1", Tzel.Encoding.encrypted_note_to_json transfer_enc_1;
        "enc_2", Tzel.Encoding.encrypted_note_to_json transfer_enc_2;
        "memo_ct_hash_1", json_felt transfer_memo_ct_hash_1;
        "memo_ct_hash_2", json_felt transfer_memo_ct_hash_2;
      ];
      "unshield", `Assoc [
        "root", json_felt root_after_transfer;
        "nullifiers", json_felt_list [bob_nf];
        "v_pub", `Int 40;
        "recipient", `String "bob";
        "cm_change", json_felt Tzel.Felt.zero;
        "enc_change", `Null;
        "memo_ct_hash_change", json_felt Tzel.Felt.zero;
      ];
      "expected", `Assoc [
        "alice_public_balance", `Int 0;
        "bob_public_balance", `Int 40;
        "tree_size", `Int 3;
        "nullifier_count", `Int 2;
      ];
    ]
  in
  print_endline (Yojson.Basic.pretty_to_string json)
