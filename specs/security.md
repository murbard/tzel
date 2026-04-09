# StarkPrivacy v2: Security Notes

This document is informative, not normative. The canonical protocol rules and encodings are in `specs/spec.md`.

## Security Properties

- **Balance conservation:** values are u64, arithmetic is carried out in u128, and the circuits enforce exact input/output equality.
- **Double-spend resistance:** nullifiers are unique per spent note position, pairwise distinct within a transaction, and checked against a global on-chain nullifier set.
- **Nullifier binding:** `nk_spend -> nk_tag -> owner_tag -> cm` binds the commitment to the nullifier key material.
- **Spend authority:** the STARK proves both knowledge of `nk_spend` and a valid WOTS+ signature over the sighash. No external signature verification is required.
- **On-chain spend unlinkability:** auth leaves, public keys, and spend signatures do not appear in public outputs.
- **Commitment privacy:** commitments are hiding through `rcm`; nullifiers use separate domains and do not reveal commitments directly.
- **Post-quantum profile:** the design uses BLAKE2s, ML-KEM-768, a hash-based one-time signature, and STARK proofs. It does not rely on elliptic curves or lattice signatures.
- **Zero-knowledge:** the intended deployment profile is the recursive proof path with ZK blinding. Single-level proving is a debug mode, not the privacy target.

## Privacy and Leakage

- **Input count is public:** the number of published nullifiers reveals `N`.
- **Transaction shape and timing are public:** observers still learn transaction type, ordering, and whether there is a change note.
- **Delegated provers can link same-address spends:** the prover sees per-address values such as `nk_spend_j` and `auth_root_j`. If the same service proves multiple spends from the same address, it can link them.
- **Detection tags are only a filtering aid:** the false-positive rate `2^(-k)` is not, by itself, a meaningful privacy guarantee.
- **No outgoing viewing in the current protocol:** full-view capability means incoming viewing plus nullifier/spent-state tracking. There is no outgoing-view ciphertext in the current scheme.

## Honest-Sender and Ciphertext Caveats

- **Detection is honest-sender:** a malicious sender can post bogus `ct_d`, causing detection to fail. The recipient then has to rely on viewing-key scanning.
- **Viewing ciphertext correctness is not proven in-circuit:** the proof binds ciphertext bytes, not that `ct_v` / `encrypted_data` decrypt to the same `(v, rseed, memo)` used in the commitment.
- **Recipient address fields are not self-authenticating to the sender:** shield and transfer outputs can be created with malformed `auth_root` / `nk_tag`, producing unspendable notes. This is sender self-griefing, not theft.
- **Memo integrity is transport integrity, not semantic correctness:** `memo_ct_hash` prevents relayer mutation of posted note ciphertext fields, but does not prove that the sender encrypted the intended plaintext.

## Wallet and One-Time-Key Safety

- **WOTS+ key reuse is catastrophic:** reusing a one-time key across two transactions can expose enough chain preimages for forgery.
- **Addresses have finite signing capacity:** each address has `2^AUTH_DEPTH` one-time keys. Addresses must be rotated before exhaustion.
- **Wallet state is part of the security boundary:** stale backups, multi-device races, or failed submissions that roll back key allocation can cause one-time-key reuse.
- **Implementations must persist state durably before submission:** this includes per-address WOTS index advancement and any note/account state used to avoid key reuse.

## Deployment Notes

- **The reference CLI ledger is demo-only for public balances:** `sp-ledger` is a localhost/reference verifier for proof and state-transition checks, not a real authenticated public account service.
- **Public account identifiers must be specified exactly in deployments:** the reference ledger uses `H(UTF8(account_string))`, but any replacement must define the exact byte encoding and verifier rule.
- **Proof verification must remain bound to the intended executable and authorization domain:** otherwise a valid proof may be accepted in the wrong verifier context.

## Additional Cryptographic Assumptions and Review Burden

- **ML-KEM failure is primarily a privacy failure:** memo confidentiality, recipient privacy, and detection degrade if ML-KEM breaks; spend authority does not directly derive from ML-KEM.
- **The hash-based spend-authority construction is custom:** it is straightforward and WOTS-like, but it is not the exact standardized XMSS/WOTS+ instantiation, so it carries more direct review burden.
- **ML-KEM key anonymity should be treated as an explicit assumption:** the protocol benefits from recipient-key anonymity properties beyond plain IND-CCA2 confidentiality.
