use std::env;

use hex::encode as hex_encode;
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{
    inbox::ExternalMessageFrame,
    smart_rollup::SmartRollupAddress,
};
use tzel_core::{
    kernel_wire::{
        encode_kernel_inbox_message, KernelBridgeConfig, KernelInboxMessage,
        KernelVerifierConfig,
    },
    ProgramHashes, F,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  octez_kernel_message configure-bridge <sr1...> <KT1...>\n  octez_kernel_message configure-verifier <sr1...> <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>"
    );
    std::process::exit(2);
}

fn parse_felt(hex: &str) -> F {
    let bytes = hex::decode(hex).expect("felt hex should decode");
    assert_eq!(bytes.len(), 32, "felt hex must be 32 bytes");
    let mut felt = [0u8; 32];
    felt.copy_from_slice(&bytes);
    felt
}

fn emit_targeted_message(rollup_address: &str, message: &KernelInboxMessage) {
    let address =
        SmartRollupAddress::from_b58check(rollup_address).expect("rollup address should be valid");
    let payload = encode_kernel_inbox_message(message).expect("kernel message should encode");
    let frame = ExternalMessageFrame::Targetted {
        address,
        contents: payload.as_slice(),
    };
    let mut framed = Vec::new();
    frame
        .bin_write(&mut framed)
        .expect("targeted frame should encode");
    println!("{}", hex_encode(framed));
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        usage();
    };

    match cmd.as_str() {
        "configure-bridge" => {
            let Some(rollup_address) = args.next() else {
                usage();
            };
            let Some(ticketer) = args.next() else {
                usage();
            };
            if args.next().is_some() {
                usage();
            }
            emit_targeted_message(
                &rollup_address,
                &KernelInboxMessage::ConfigureBridge(KernelBridgeConfig { ticketer }),
            );
        }
        "configure-verifier" => {
            let Some(rollup_address) = args.next() else {
                usage();
            };
            let Some(auth_domain) = args.next() else {
                usage();
            };
            let Some(shield) = args.next() else {
                usage();
            };
            let Some(transfer) = args.next() else {
                usage();
            };
            let Some(unshield) = args.next() else {
                usage();
            };
            if args.next().is_some() {
                usage();
            }
            emit_targeted_message(
                &rollup_address,
                &KernelInboxMessage::ConfigureVerifier(KernelVerifierConfig {
                    auth_domain: parse_felt(&auth_domain),
                    verified_program_hashes: ProgramHashes {
                        shield: parse_felt(&shield),
                        transfer: parse_felt(&transfer),
                        unshield: parse_felt(&unshield),
                    },
                }),
            );
        }
        _ => usage(),
    }
}
