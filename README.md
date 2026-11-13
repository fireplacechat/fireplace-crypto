# fireplace-crypto

The end-to-end encryption protocol of [Fireplace](https://github.com/fireplacechat/mobile), in Rust: identity and device keys, prekeys, the handshake, and the hybrid double ratchet (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). The Fireplace app and its iOS notification extension both use it.

Work in progress. It follows Fireplace's design decisions (0002, 0003 and 0035 in the app repository) and stays byte-compatible with the app's existing messages, keys and sessions.

`ml-kem` and `ml-dsa` say they have not been independently audited. `aes-gcm` was audited by NCC Group. This crate does not claim an audit. The comparison with libcrux is in `docs/dependencies.md`.

The C ABI is `include/fireplace_crypto.h`. Callers free every returned buffer with `fp_free`.

Licence: [AGPL-3.0](LICENSE).
