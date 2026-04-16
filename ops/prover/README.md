# Prover Deployment

This directory contains the minimum deployment assets for a host that needs to
run TzEL proving locally or provide prebuilt proving artifacts for wallets.

Unlike `tzel-operator`, the prover is not a daemon. The deployed surface is:

- `reprove`
- the Cairo executable JSON files:
  - `run_shield.executable.json`
  - `run_transfer.executable.json`
  - `run_unshield.executable.json`

The simplest standard layout is:

- `/usr/local/bin/reprove`
- `/usr/local/bin/tzel-wallet`
- `/opt/tzel/cairo/target/dev/*.executable.json`

## Files

- `prover.env.example`
  - standard installed paths for prover-related binaries and executables
- `../../scripts/install_tzel_binaries.sh`
  - builds and installs `tzel-operator`, `tzel-wallet`, `sp-client`,
    `octez_kernel_message`, `verified_bridge_fixture_message`, `reprove`, and
    the Cairo executable JSON files
- `../../scripts/prover_preflight.sh`
  - verifies the installed prover layout and checks that `reprove` can compute
    program hashes for all three deployed circuits

## Setup

1. Build release artifacts as your normal user.
   - `./scripts/install_tzel_binaries.sh --build-only`
2. Install them into standard paths.
   - `sudo ./scripts/install_tzel_binaries.sh --skip-build --prefix /usr/local --executables-dir /opt/tzel/cairo/target/dev`
3. Copy the env template.
   - `sudo mkdir -p /etc/tzel`
   - `sudo cp ops/prover/prover.env.example /etc/tzel/prover.env`
   - edit `/etc/tzel/prover.env` if you use nonstandard paths
4. Run preflight.
   - `./scripts/prover_preflight.sh /etc/tzel/prover.env`

## Expected Installed Paths

- prover binary: `/usr/local/bin/reprove`
- wallet binary: `/usr/local/bin/tzel-wallet`
- Cairo executables: `/opt/tzel/cairo/target/dev`

## Smoke Checks

Compute the authenticated program hashes directly:

```bash
/usr/local/bin/reprove /opt/tzel/cairo/target/dev/run_shield.executable.json --program-hash
/usr/local/bin/reprove /opt/tzel/cairo/target/dev/run_transfer.executable.json --program-hash
/usr/local/bin/reprove /opt/tzel/cairo/target/dev/run_unshield.executable.json --program-hash
```

Wallet help should work without a workspace checkout:

```bash
/usr/local/bin/tzel-wallet --help
```
