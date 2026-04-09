# Apps

This directory contains the thin user-facing shells:

- `wallet/` for `sp-client`
- `ledger/` for `sp-ledger`
- `prover/` for `reprove`
- `demo/` for the standalone demo binary

The shells are intentionally kept outside `rust/` so they can stay separate
from any particular implementation language. Today they are wired through the
Rust backend adapter in `backends/rust/`.
