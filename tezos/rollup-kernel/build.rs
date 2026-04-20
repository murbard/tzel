// The kernel bakes admin material (config-admin public seed + the two WOTS
// leaf hashes for the verifier/bridge config keys) into the WASM at compile
// time via `option_env!()` in src/lib.rs.  These values authenticate admin
// `Configure*` messages — change them and the set of admin signatures the
// kernel will accept changes with them.
//
// Cargo's default fingerprint tracks source files, Cargo.toml, RUSTFLAGS,
// and features — but NOT the values of ad-hoc environment variables read
// through `option_env!()`.  So this sequence silently produces a broken
// artifact:
//
//   1. Operator regenerates admin material (new `ask`) and exports new
//      `TZEL_ROLLUP_*_HEX` values.
//   2. `cargo build` sees no source change → reuses the cached WASM from
//      the previous ask.
//   3. Kernel is deployed; it holds the OLD pub_seed/leaves.
//   4. Admin signs Configure messages with the NEW ask.
//   5. Kernel rejects every admin signature as invalid — no compile error,
//      no startup panic, just silent DoS on admin ops.  Only symptom is
//      `ConfigureVerifier` / `ConfigureBridge` messages being rejected in
//      the rollup inbox with a signature-verification failure.
//
// The directives below extend cargo's fingerprint to include these three
// env vars, so any change to them forces a rebuild and the newly-baked
// WASM matches the currently-exported admin material.
//
// Note: `TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX` is deliberately NOT tracked —
// the `ask` is a runtime signing input read by `octez_kernel_message`, not
// a compile-time kernel input.  Only the derived public material is baked.
fn main() {
    for var in [
        "TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX",
        "TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX",
        "TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX",
    ] {
        println!("cargo:rerun-if-env-changed={}", var);
    }
}
