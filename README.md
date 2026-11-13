# fireplace-crypto

The end-to-end encryption protocol of [Fireplace](https://github.com/fireplacechat/mobile), in Rust: identity and device keys, prekeys, the handshake, and the hybrid double ratchet (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). The Fireplace app and its iOS notification extension both use it.

Work in progress. It follows Fireplace's design decisions (0002, 0003 and 0035 in the app repository) and stays byte-compatible with the app's existing messages, keys and sessions.

Licence: [AGPL-3.0](LICENSE).
