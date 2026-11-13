# Test vectors

Third-party known-answer vectors used by `src/known_answer.rs`. They are data,
not code, and are not edited by hand. This directory is excluded from the
published crate. The synthetic Dart transcript lives in `vectors/` at the
repository root, because the crate's own tests need it.

| File | Source | Used for |
|---|---|---|
| `nist_mlkem768.json` | NIST ACVP-Server `gen-val` ML-KEM-768 (FIPS 203) | key generation, encapsulation, decapsulation, encapsulation-key checks |
| `nist_mldsa65.json` | NIST ACVP-Server ML-DSA-65 (FIPS 204), external/pure interface | key generation, signing, verification including invalid signatures |
| `wycheproof_classical.json` | Google Wycheproof (C2SP `testvectors_v1`): X25519, Ed25519, AES-256-GCM, HKDF-SHA256 | malformed and edge-case inputs, plus the valid answers |

These are the same files as `test/vectors/` in the Fireplace app. NIST's
vectors are public domain. Wycheproof is Apache-2.0. Sources:
<https://github.com/usnistgov/ACVP-Server> and
<https://github.com/C2SP/wycheproof>.
