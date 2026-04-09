# OCaml Implementation

This directory contains the independent OCaml implementation of the protocol.

- `protocol/` contains the pure protocol modules.
- `services/` contains the higher-level ledger/prover service modules.

- Canonical protocol spec: `../specs/spec.md`
- Shared cross-implementation vectors: `../specs/ocaml_vectors/`
- Canonical wire vectors: `../specs/test_vectors/`

Typical commands:

```bash
cd ocaml
opam exec -- dune runtest
```

Notes:

- The vendored `mlkem-native` tree is intentionally trimmed to the sources, build rules, and the checked-in `test/build/libmlkem768.a` archive used by the FFI.
- If you need to rebuild that archive locally, run `make -C vendor/mlkem-native test/build/libmlkem768.a`.
