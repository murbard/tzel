let bytes_of_hex s = Hex.to_bytes (`Hex s)
let felt_of_hex s = bytes_of_hex s

let json_string = function `String s -> s | _ -> failwith "expected string"
let json_int = function `Int n -> n | _ -> failwith "expected int"
let json_list = function `List l -> l | _ -> failwith "expected list"
let json_assoc = function `Assoc a -> a | _ -> failwith "expected assoc"
let json_field key j = List.assoc key (json_assoc j)

let withdrawal_list =
  Alcotest.(list (pair string int64))

let rec find_manifest_up dir remaining =
  let candidate = Filename.concat dir "Cargo.toml" in
  if Sys.file_exists candidate then Some candidate
  else if remaining = 0 then None
  else
    let parent = Filename.dirname dir in
    if parent = dir then None else find_manifest_up parent (remaining - 1)

let cargo_manifest_path () =
  let starts =
    [ Sys.getcwd ();
      Filename.dirname Sys.executable_name;
      Filename.concat (Filename.dirname Sys.executable_name) "..";
      Filename.concat (Filename.dirname Sys.executable_name) "../.."; ]
  in
  let starts =
    List.map (fun p -> try Unix.realpath p with _ -> p) starts
    |> List.sort_uniq String.compare
  in
  match List.find_map (fun dir -> find_manifest_up dir 8) starts with
  | Some path -> path
  | None -> failwith "could not locate repository Cargo.toml"

let read_command_output cmd args =
  let ic = Unix.open_process_args_in cmd args in
  let buf = Buffer.create 4096 in
  (try
     while true do
       Buffer.add_string buf (input_line ic);
       Buffer.add_char buf '\n'
     done
   with End_of_file -> ());
  match Unix.close_process_in ic with
  | Unix.WEXITED 0 -> Buffer.contents buf
  | _ -> failwith "command failed"

let rust_scenario_json () =
  let manifest = cargo_manifest_path () in
  read_command_output "cargo"
    [|
      "cargo"; "run"; "-q"; "--manifest-path"; manifest;
      "-p"; "tzel-services"; "--bin"; "gen-interop-scenario";
    |]

let test_rust_wallet_scenario_applies_on_ocaml_ledger () =
  let json = Yojson.Basic.from_string (rust_scenario_json ()) in
  let auth_domain = felt_of_hex (json_string (json_field "auth_domain" json)) in
  let initial_alice_balance = Int64.of_int (json_int (json_field "initial_alice_balance" json)) in
  let ledger = Tzel.Ledger.create ~auth_domain in
  Tzel.Ledger.set_balance ledger "alice" initial_alice_balance;

  let shield = json_field "shield" json in
  let shield_sender = json_string (json_field "sender" shield) in
  let shield_pub : Tzel.Transaction.shield_public = {
    v_pub = Int64.of_int (json_int (json_field "v" shield));
    cm_new = felt_of_hex (json_string (json_field "cm" shield));
    sender_id = Tzel.Hash.account_id shield_sender;
    memo_ct_hash = felt_of_hex (json_string (json_field "memo_ct_hash" shield));
  } in
  begin match Tzel.Ledger.apply_shield ledger ~sender_string:shield_sender ~pub:shield_pub
                ~memo_ct_hash:shield_pub.memo_ct_hash with
  | Ok () -> ()
  | Error e -> Alcotest.failf "shield failed: %s" e
  end;
  Tzel.Ledger.append_commitment ledger
    (felt_of_hex (json_string (json_field "producer_cm" shield)));
  Tzel.Ledger.set_balance ledger shield_sender
    (Int64.sub (Tzel.Ledger.get_balance ledger shield_sender)
       (Int64.add
          (Int64.of_int (json_int (json_field "fee" shield)))
          (Int64.of_int (json_int (json_field "producer_fee" shield)))));

  let transfer = json_field "transfer" json in
  let transfer_pub : Tzel.Transaction.transfer_public = {
    auth_domain;
    root = felt_of_hex (json_string (json_field "root" transfer));
    nullifiers = List.map (fun x -> felt_of_hex (json_string x))
      (json_list (json_field "nullifiers" transfer));
    cm_1 = felt_of_hex (json_string (json_field "cm_1" transfer));
    cm_2 = felt_of_hex (json_string (json_field "cm_2" transfer));
    memo_ct_hash_1 = felt_of_hex (json_string (json_field "memo_ct_hash_1" transfer));
    memo_ct_hash_2 = felt_of_hex (json_string (json_field "memo_ct_hash_2" transfer));
  } in
  begin match Tzel.Ledger.apply_transfer ledger transfer_pub
                ~memo_ct_hash_1:transfer_pub.memo_ct_hash_1
                ~memo_ct_hash_2:transfer_pub.memo_ct_hash_2 with
  | Ok () -> ()
  | Error e -> Alcotest.failf "transfer failed: %s" e
  end;
  Tzel.Ledger.append_commitment ledger
    (felt_of_hex (json_string (json_field "cm_3" transfer)));

  let unshield = json_field "unshield" json in
  let recipient = json_string (json_field "recipient" unshield) in
  let unshield_pub : Tzel.Transaction.unshield_public = {
    auth_domain;
    root = felt_of_hex (json_string (json_field "root" unshield));
    nullifiers = List.map (fun x -> felt_of_hex (json_string x))
      (json_list (json_field "nullifiers" unshield));
    v_pub = Int64.of_int (json_int (json_field "v_pub" unshield));
    recipient_id = Tzel.Hash.account_id recipient;
    cm_change = felt_of_hex (json_string (json_field "cm_change" unshield));
    memo_ct_hash_change = felt_of_hex (json_string (json_field "memo_ct_hash_change" unshield));
  } in
  begin match Tzel.Ledger.apply_unshield ledger ~recipient_string:recipient unshield_pub
                ~memo_ct_hash_change:unshield_pub.memo_ct_hash_change with
  | Ok () -> ()
  | Error e -> Alcotest.failf "unshield failed: %s" e
  end;
  Tzel.Ledger.append_commitment ledger
    (felt_of_hex (json_string (json_field "cm_fee" unshield)));

  let expected = json_field "expected" json in
  let expected_withdrawals =
    json_list (json_field "withdrawals" expected)
    |> List.map (fun entry ->
         let recipient = json_string (json_field "recipient" entry) in
         let amount = Int64.of_int (json_int (json_field "amount" entry)) in
         (recipient, amount))
  in
  Alcotest.(check withdrawal_list) "withdrawals"
    expected_withdrawals
    (Tzel.Ledger.withdrawals ledger);
  Alcotest.(check int) "tree size"
    (json_int (json_field "tree_size" expected))
    (Tzel.Ledger.tree_size ledger);
  Alcotest.(check int) "nullifier count"
    (json_int (json_field "nullifier_count" expected))
    (Hashtbl.length ledger.nullifier_set)

let () =
  Alcotest.run "tzel-interop" [
    ("interop", [
      Alcotest.test_case "rust wallet scenario applies on ocaml ledger" `Quick
        test_rust_wallet_scenario_applies_on_ocaml_ledger;
    ]);
  ]
