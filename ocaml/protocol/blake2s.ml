(* BLAKE2s-256 with personalization support via C FFI *)

external c_blake2s_hash : bytes -> bytes -> bytes = "caml_blake2s_hash"

let hash ?(personal = Bytes.empty) data =
  c_blake2s_hash data personal

let hash_string ?(personal = "") data =
  let p = if personal = "" then Bytes.empty else Bytes.of_string personal in
  hash ~personal:p (Bytes.of_string data)
