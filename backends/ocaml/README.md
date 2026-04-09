# OCaml Backend Adapter

This directory is reserved for the adapter that will let the thin shells in
`apps/` call the independent OCaml implementation.

The OCaml libraries themselves live under `ocaml/`; this layer is only for the
bridge code needed to present the same backend surface the shells already use.
