# Shadownet Operator Box

This directory contains the minimum deployment assets for a public Shadownet
operator machine that runs:

- `octez-node`
- `octez-dal-node`
- `octez-smart-rollup-node`
- `tzel-operator`

## Why A Public Box Matters

Live testing from this VM showed the following failure mode:

- DAL commitments were published successfully
- the slots later became `unattested`
- the rollup node then revealed `0` bytes for the DAL pages

For real shielded traffic, the DAL node that publishes slots must be reachable
by the rest of the DAL network. In practice that means:

- set a real `TZEL_DAL_PUBLIC_ADDR`
- open the DAL P2P port in the firewall
- run this on a public machine, not a local VM behind a private NAT

## Files

- `shadownet.env.example`
  - single environment file shared by all services
- `systemd/*.service`
  - systemd unit templates for the four long-running processes
- `../prover/`
  - standard prover deployment paths plus preflight for `reprove` and the Cairo executables
- `../../scripts/install_tzel_binaries.sh`
  - installs `tzel-operator`, `tzel-wallet`, `sp-client`, `octez_kernel_message`,
    `verified_bridge_fixture_message`, `reprove`, and the Cairo executable JSON files
- `../../scripts/shadownet_operator_preflight.sh`
  - checks binaries, env vars, and local service RPCs

## Setup

1. Install Octez binaries.
   - `./scripts/install_octez_ubuntu.sh`
2. Build TzEL release artifacts as your normal user.
   - `./scripts/install_tzel_binaries.sh --build-only`
3. Install TzEL release artifacts.
   - `sudo ./scripts/install_tzel_binaries.sh --skip-build --prefix /usr/local --executables-dir /opt/tzel/cairo/target/dev`
4. Copy the env template.
   - `sudo mkdir -p /etc/tzel`
   - `sudo cp ops/shadownet/shadownet.env.example /etc/tzel/shadownet.env`
   - edit `/etc/tzel/shadownet.env`
5. Initialize local state and node identity.
   - `sudo ./scripts/init_shadownet_operator_box.sh /etc/tzel/shadownet.env`
6. Import the operator key once.
   - `sudo -u tzel octez-client -d /var/lib/tzel/octez-client import secret key tzelshadownet <SECRET_KEY>`
7. Copy the service units.
   - `sudo cp ops/shadownet/systemd/*.service /etc/systemd/system/`
8. Reload and start services.
   - `sudo systemctl daemon-reload`
   - `sudo systemctl enable --now octez-node octez-dal-node octez-rollup-node tzel-operator`
9. Run preflight.
   - `./scripts/shadownet_operator_preflight.sh /etc/tzel/shadownet.env`

## Expected Local RPCs

- L1 node RPC: `http://127.0.0.1:8732`
- DAL node RPC: `http://127.0.0.1:10732`
- rollup node RPC: `http://127.0.0.1:28944`
- operator HTTP: `http://127.0.0.1:8787`

## Firewall

At minimum, allow inbound TCP for:

- the DAL node P2P port from `TZEL_DAL_NET_ADDR`
- the Octez node P2P port from `TZEL_OCTEZ_NODE_NET_ADDR`

Keep the RPC endpoints bound to loopback unless you explicitly want remote
access.
