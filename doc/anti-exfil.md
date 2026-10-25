# Interactive anti-exfil for Taproot key-path signatures

This implementation follows the draft BIP-EXFIL additive single-signer protocol.
It creates ordinary BIP340 signatures. It does not implement sign-to-contract,
MuSig2 anti-exfil, FROST anti-exfil, or Taproot script-path anti-exfil.
The `BIP-EXFIL/host` and `BIP-EXFIL/nonce` domain tags are placeholders that
will need replacing, together with the test vectors, when a BIP number is assigned.

## PSBT transport

Call the normal `sign_psbt` command twice. Each protected input uses proprietary
PSBT keys `fc 02 61 65 <subtype> <xonly-signing-pubkey>`, with the **tweaked output
key**, not the internal key:

| Subtype | Value |
| --- | --- |
| `00` | 32-byte host randomness commitment |
| `01` | 33-byte compressed original signer nonce |
| `02` | 32-byte host randomness, a big-endian scalar in `1..n-1` |

Round 1 contains subtype `00` only. It yields no signature. Its yielded result is
`CompactSize(0xfffffffd) || CompactSize(input_index) || nonce33 || signing_key32`.
The initial `CCMD_YIELD` byte is handled by the normal client-command interpreter.
Round 2 contains all three fields and returns the normal Taproot signature result.
The app checks the host reveal against its commitment and checks the supplied
nonce against the deterministically rederived nonce before signing. Before yielding
the signature, the independent SDK BIP340 verifier checks it to catch faults
that could otherwise leak signing keys.

Both rounds process and review the complete transaction independently. No secret
nonce or signing session is persisted between commands. The secret nonce is bound
to the actual signing key, transaction sighash, and host commitment, and uses a
different nonce derivation domain from ordinary BIP340 signing.

Only `SIGHASH_DEFAULT` and `SIGHASH_ALL` are accepted in this flow. Partial field
sets, malformed fields, an incorrect signing key, or script-path requests fail
closed. PSBTs without anti-exfil fields retain the existing signing behavior.

## Tests

`unit-tests/test_crypto.c` includes eight independent cross-implementation
vectors (including odd signing keys, both final nonce parities, and `rho=n-1`),
deterministic retries, wrong reveals and openings, altered messages, and invalid
host scalars. The HWI `--ledger-anti-exfil` device test exercises two-round signing
against the Speculos app, negative device requests, and broadcast/confirmation.

The host must keep the original request and nonce receipt between rounds. On a
retry it must retain the same randomness and require the same signer nonce;
automatically restarting with fresh randomness enables selective-abort leakage.
The protocol transcript must not be published or written to ordinary logs.
