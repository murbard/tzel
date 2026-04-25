/// Shield circuit: deposit public tokens into a private note.
///
/// # Public outputs
///   [auth_domain, v_note, fee, producer_fee, cm_new, cm_producer, deposit_id,
///    memo_ct_hash, producer_memo_ct_hash]
///
/// # Constraints
///   owner_tag = H_owner(auth_root, auth_pub_seed, nk_tag)
///   rcm = H("rcm", rseed)
///   cm_new = H_commit(d_j, v_note, rcm, owner_tag)
///
///   intent = sighash_fold(0x03, auth_domain) -> v_note -> fee -> producer_fee
///                       -> cm_new -> cm_producer -> memo_ct_hash
///                       -> producer_memo_ct_hash
///   deposit_id == intent
///
/// `auth_root`, `auth_pub_seed`, `nk_tag`, `d_j`, `rseed` for the recipient note
/// (and the producer-fee equivalents) are private inputs from the L1 depositor's
/// witness. The recipient note is fully constructed client-side at L1-deposit
/// time; the L1 deposit transaction's address (`deposit:<hex(intent)>`) commits
/// to every detail of the shield. Anything an untrusted prover could rewrite
/// is folded into `intent`, so a malicious prover cannot redirect funds.

use tzel::blake_hash as hash;

pub fn verify(
    auth_domain: felt252,
    v_note: u64,
    fee: u64,
    producer_fee: u64,
    cm_new: felt252,
    cm_producer: felt252,
    deposit_id: felt252,
    memo_ct_hash: felt252,
    producer_memo_ct_hash: felt252,
    // private inputs (recipient note witness)
    auth_root: felt252,
    auth_pub_seed: felt252,
    nk_tag: felt252,
    d_j: felt252,
    rseed: felt252,
    // private inputs (producer-fee note witness)
    producer_auth_root: felt252,
    producer_auth_pub_seed: felt252,
    producer_nk_tag: felt252,
    producer_d_j: felt252,
    producer_rseed: felt252,
) -> Array<felt252> {
    let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    assert(hash::commit(d_j, v_note, rcm, otag) == cm_new, 'shield: bad commitment');
    let producer_otag =
        hash::owner_tag(producer_auth_root, producer_auth_pub_seed, producer_nk_tag);
    let producer_rcm = hash::derive_rcm(producer_rseed);
    assert(
        hash::commit(producer_d_j, producer_fee, producer_rcm, producer_otag) == cm_producer,
        'shield prod cm',
    );
    assert(producer_fee > 0_u64, 'shield prod fee');

    // intent = fold(0x03, auth_domain, v_note, fee, producer_fee, cm_new,
    //               cm_producer, memo_ct_hash, producer_memo_ct_hash)
    let mut intent = hash::sighash_fold(0x03, auth_domain);
    intent = hash::sighash_fold(intent, v_note.into());
    intent = hash::sighash_fold(intent, fee.into());
    intent = hash::sighash_fold(intent, producer_fee.into());
    intent = hash::sighash_fold(intent, cm_new);
    intent = hash::sighash_fold(intent, cm_producer);
    intent = hash::sighash_fold(intent, memo_ct_hash);
    intent = hash::sighash_fold(intent, producer_memo_ct_hash);
    assert(intent == deposit_id, 'shield: bad intent');

    array![
        auth_domain,
        v_note.into(),
        fee.into(),
        producer_fee.into(),
        cm_new,
        cm_producer,
        deposit_id,
        memo_ct_hash,
        producer_memo_ct_hash,
    ]
}

#[cfg(test)]
mod tests {
    use tzel::blake_hash as hash;
    use super::verify;

    #[derive(Copy, Drop)]
    struct ShieldFixture {
        auth_domain: felt252,
        v_note: u64,
        fee: u64,
        producer_fee: u64,
        cm_new: felt252,
        cm_producer: felt252,
        deposit_id: felt252,
        memo_ct_hash: felt252,
        producer_memo_ct_hash: felt252,
        auth_root: felt252,
        auth_pub_seed: felt252,
        nk_tag: felt252,
        d_j: felt252,
        rseed: felt252,
        producer_auth_root: felt252,
        producer_auth_pub_seed: felt252,
        producer_nk_tag: felt252,
        producer_d_j: felt252,
        producer_rseed: felt252,
    }

    fn build_intent(
        auth_domain: felt252,
        v_note: u64,
        fee: u64,
        producer_fee: u64,
        cm_new: felt252,
        cm_producer: felt252,
        memo_ct_hash: felt252,
        producer_memo_ct_hash: felt252,
    ) -> felt252 {
        let mut intent = hash::sighash_fold(0x03, auth_domain);
        intent = hash::sighash_fold(intent, v_note.into());
        intent = hash::sighash_fold(intent, fee.into());
        intent = hash::sighash_fold(intent, producer_fee.into());
        intent = hash::sighash_fold(intent, cm_new);
        intent = hash::sighash_fold(intent, cm_producer);
        intent = hash::sighash_fold(intent, memo_ct_hash);
        intent = hash::sighash_fold(intent, producer_memo_ct_hash);
        intent
    }

    fn build_fixture() -> ShieldFixture {
        let auth_domain = 0x1234;
        let v_note = 19_u64;
        let fee = 4_u64;
        let producer_fee = 3_u64;
        let memo_ct_hash = 0x2222;
        let producer_memo_ct_hash = 0x2323;
        let auth_root = 0x3333;
        let auth_pub_seed = 0x4444;
        let nk_tag = 0x5555;
        let d_j = 0x6666;
        let rseed = 0x7777;
        let producer_auth_root = 0x8888;
        let producer_auth_pub_seed = 0x9999;
        let producer_nk_tag = 0xAAAA;
        let producer_d_j = 0xBBBB;
        let producer_rseed = 0xCCCC;
        let rcm = hash::derive_rcm(rseed);
        let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
        let cm_new = hash::commit(d_j, v_note, rcm, otag);
        let producer_rcm = hash::derive_rcm(producer_rseed);
        let producer_otag =
            hash::owner_tag(producer_auth_root, producer_auth_pub_seed, producer_nk_tag);
        let cm_producer = hash::commit(producer_d_j, producer_fee, producer_rcm, producer_otag);
        let deposit_id = build_intent(
            auth_domain,
            v_note,
            fee,
            producer_fee,
            cm_new,
            cm_producer,
            memo_ct_hash,
            producer_memo_ct_hash,
        );

        ShieldFixture {
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
        }
    }

    #[test]
    fn test_shield_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
        assert(outputs.len() == 9, 'shield outputs len');
        assert(*outputs.at(0) == fixture.auth_domain, 'shield out auth_domain');
        assert(*outputs.at(1) == fixture.v_note.into(), 'shield out v');
        assert(*outputs.at(2) == fixture.fee.into(), 'shield out fee');
        assert(*outputs.at(3) == fixture.producer_fee.into(), 'shield out producer fee');
        assert(*outputs.at(4) == fixture.cm_new, 'shield out cm');
        assert(*outputs.at(5) == fixture.cm_producer, 'shield out producer cm');
        assert(*outputs.at(6) == fixture.deposit_id, 'shield out deposit');
        assert(*outputs.at(7) == fixture.memo_ct_hash, 'shield out memo');
        assert(*outputs.at(8) == fixture.producer_memo_ct_hash, 'shield out producer memo');
    }

    #[test]
    #[should_panic(expected: ('shield: bad intent',))]
    fn test_shield_rejects_wrong_deposit_id() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id + 1,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad intent',))]
    fn test_shield_rejects_swapped_auth_domain() {
        // Same notes, different auth_domain — intent diverges, deposit_id
        // recompute mismatches. Closes the cross-deployment replay vector.
        let fixture = build_fixture();
        verify(
            fixture.auth_domain + 1,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_commitment() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new + 1,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_owner_material() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed + 1,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_value() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note + 1_u64,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_auth_root() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root + 1,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_nk_tag() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag + 1,
            fixture.d_j,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_note_randomness() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed + 1,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_note_body() {
        let fixture = build_fixture();
        verify(
            fixture.auth_domain,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.deposit_id,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j + 1,
            fixture.rseed,
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
        );
    }
}
