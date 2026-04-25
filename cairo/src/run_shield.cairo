/// Parameterized shield executable — takes witness data as input.
///
/// Public outputs (in order):
///   [auth_domain, v_note, fee, producer_fee, cm_new, cm_producer,
///    deposit_id, memo_ct_hash, producer_memo_ct_hash]
///
/// Argument layout (flattened felt252 array):
///   [auth_domain, v_note, fee, producer_fee, cm_new, cm_producer,
///    deposit_id, memo_ct_hash, producer_memo_ct_hash,
///    auth_root, auth_pub_seed, nk_tag, d_j, rseed,
///    producer_auth_root, producer_auth_pub_seed, producer_nk_tag,
///    producer_d_j, producer_rseed]
///
/// The circuit recomputes `intent` over the public-output prefix and
/// asserts `deposit_id == intent`. There is no `deposit_secret` argument —
/// shield is intent-bound: the L1 deposit transaction is itself the
/// authorization.

use tzel::shield;

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    assert(args.len() == 19, 'shield: need 19 args');
    let auth_domain = *args.at(0);
    let v_note: u64 = (*args.at(1)).try_into().unwrap();
    let fee: u64 = (*args.at(2)).try_into().unwrap();
    let producer_fee: u64 = (*args.at(3)).try_into().unwrap();
    let cm_new = *args.at(4);
    let cm_producer = *args.at(5);
    let deposit_id = *args.at(6);
    let memo_ct_hash = *args.at(7);
    let producer_memo_ct_hash = *args.at(8);
    let auth_root = *args.at(9);
    let auth_pub_seed = *args.at(10);
    let nk_tag = *args.at(11);
    let d_j = *args.at(12);
    let rseed = *args.at(13);
    let producer_auth_root = *args.at(14);
    let producer_auth_pub_seed = *args.at(15);
    let producer_nk_tag = *args.at(16);
    let producer_d_j = *args.at(17);
    let producer_rseed = *args.at(18);
    shield::verify(
        auth_domain,
        v_note,
        fee,
        producer_fee,
        cm_new,
        cm_producer,
        deposit_id,
        memo_ct_hash,
        producer_memo_ct_hash,
        auth_root,
        auth_pub_seed,
        nk_tag,
        d_j,
        rseed,
        producer_auth_root,
        producer_auth_pub_seed,
        producer_nk_tag,
        producer_d_j,
        producer_rseed,
    )
}
