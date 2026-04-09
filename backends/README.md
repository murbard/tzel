# Backends

This directory contains adapter layers used by the thin shells in `apps/`.

- `rust/` wires the shells to the native Rust implementation.
- An `ocaml/` adapter can be added later without moving the shells or changing the
  user-facing app layout.

The goal is to keep application packaging separate from the language-specific
implementation libraries in `rust/` and `ocaml/`.
