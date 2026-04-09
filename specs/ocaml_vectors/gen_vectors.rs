// Stub: implement a gen-test-vectors binary in the Rust reference repo
// following specs/ocaml_vectors/test_vector_spec.md exactly.
//
// The spec defines every input, every computation, and the JSON schema.
// Use the same code paths as the real protocol — do not reimplement crypto.
//
// Add to rust/cli/Cargo.toml:
//   [[bin]]
//   name = "gen-test-vectors"
//   path = "src/bin/gen_test_vectors.rs"
//
// Run:
//   cargo run --manifest-path rust/cli/Cargo.toml --bin gen-test-vectors -- --output specs/ocaml_vectors/protocol_v1.generated.json
//
// Then validate from the OCaml side:
//   cd ocaml && dune exec test/test_vectors.exe
