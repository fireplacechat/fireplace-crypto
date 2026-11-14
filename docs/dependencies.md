# Dependencies

Pinned in `Cargo.toml` and `Cargo.lock`. The toolchain is `1.98.1` in
`rust-toolchain.toml`. `cargo audit` (0.23.0) and `cargo deny` (0.20.2) run
in CI. cargo-deny is a CI tool only. It is not linked into the crate.

Nothing here is a network client. `getrandom` reads the operating system.
No `hazmat` feature is enabled. JSON and base64 are implemented in this
crate. There is no `serde`, `serde_json`, or `base64` dependency, and the
C header is written by hand.

Without the `groups` feature, `cargo audit` on this lockfile reports no
vulnerabilities that apply. With it, five advisories are reported and ignored,
for the reasons under *Open advisories*. `cargo deny check` accepts the licences
below.

## Open advisories

OpenMLS 0.9.2 and its companion crates (feature `groups`) bring a large tree.
`cargo audit` and `cargo deny` read `Cargo.lock`, which lists every crate any
feature of any dependency could use, built or not. The ignore lists are in
`.cargo/audit.toml` and `deny.toml`.

| Advisory | Crate | Why it does not apply | What removes it |
|---|---|---|---|
| RUSTSEC-2026-0329 | libcrux-hmac-drbg 0.0.1 | Not compiled: an optional dependency this crate does not enable | Any OpenMLS release that drops or updates it |
| RUSTSEC-2026-0330, -0331 | libcrux-kem 0.0.9 | Not compiled, for the same reason. The KEM this crate uses with MLS comes from the RustCrypto backend | The same |
| RUSTSEC-2026-0459 | libsqlite3-sys 0.35.0 | Not compiled: OpenMLS's SQLite storage is not used; the app stores the records | The same |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | **Compiled, not run.** See below | OpenMLS's backend moving to `elliptic-curve` 0.14 (crypto-bigint 0.7.6 or later) |
| RUSTSEC-2026-0173 | proc-macro-error2 2.0.1 | A build-time macro (through `hax-lib`); unmaintained, not a vulnerability | A replacement upstream |

CI proves the first four stay out of the build: `cargo tree -i` must find no
path to those crates with every feature this repository uses, on every target.

**crypto-bigint 0.5.5** has timing differences in operations meant to be constant
time. It is linked through `p256` (and `elliptic-curve` 0.13), which OpenMLS's
RustCrypto backend and basic credential include for the NIST P-256 suites. This
crate uses one suite, `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`: X25519
and ML-KEM-768 for key exchange, Ed25519 for signatures. It creates groups and key
packages with that suite only and refuses a Welcome for any other
(`src/group/mod.rs`), so no P-256 key is ever generated, used or accepted, and
the affected code is not reached with a secret. The fixed crypto-bigint (0.7.6)
needs `elliptic-curve` 0.14, which OpenMLS 0.9.2's crates do not accept, so it
cannot be selected from here. Revisit when a newer OpenMLS is released; that
release is also needed for the final cipher suite identifiers.

## Direct crates

| Crate | Version | Features | Licence |
|---|---|---|---|
| aes-gcm | 0.11.1 | aes, alloc, zeroize | Apache-2.0 OR MIT |
| ed25519-dalek | 3.0.0 | alloc, fast, zeroize | BSD-3-Clause |
| getrandom | 0.4.1 | std, sys_rng | MIT OR Apache-2.0 |
| hkdf | 0.12.4 | (none; default features off) | MIT OR Apache-2.0 |
| ml-dsa | 0.1.2 | alloc, rand_core, zeroize | Apache-2.0 OR MIT |
| ml-kem | 0.3.4 | alloc, zeroize | Apache-2.0 OR MIT |
| rand_core | 0.10.0 | default | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | (none; default features off) | MIT OR Apache-2.0 |
| subtle | 2.6.1 | (none; default features off) | BSD-3-Clause |
| x25519-dalek | 3.0.0 | precomputed-tables, static_secrets, zeroize | BSD-3-Clause |
| zeroize | 1.8.2 | derive | Apache-2.0 OR MIT |

`ml-kem` and `ml-dsa` enable their own `zeroize` feature. Depending on the
`zeroize` crate alone would not wipe their keys. `subtle` compares
equal-length secrets in constant time. It was already pulled in by other
crates; it is now a direct dependency, with its default features off.

## Advisories that matter here

- **ml-dsa** RUSTSEC-2025-0144 / CVE-2026-22705, a timing side channel in
  signing, is fixed in 0.1.2. This crate pins 0.1.2.
- **aes-gcm** RUSTSEC-2023-0096 is fixed in 0.10.3 and later. This crate pins
  0.11.1. The NCC Group audit covers aes-gcm. It does not cover this crate
  or the post-quantum crates.
- **ctutils** 0.4.8 (pulled in by aes-gcm and the post-quantum crates) is
  past RUSTSEC-2026-0385, which is fixed from 0.4.4.
- **ml-kem** and **ml-dsa** say they have never been independently audited.
  This crate does not claim an audit either.

`ed25519-dalek` 3 pulls `sha2` 0.11. The HKDF path uses `sha2` 0.10, because
`hkdf` 0.12 is built on `digest` 0.10. Both versions are in the lockfile.
`cargo deny` allows that. The normal dependency tree has no `pkcs8`, no
`wit-bindgen`, and no `wasmtime` crates.

## Why not libcrux

Decision 0035 approves the crates above. libcrux is not on that list, so
this crate does not use it.

libcrux publishes formally verified ML-KEM and ML-DSA. That verification has
not meant an absence of defects. Advisories on the libcrux crates include:

- libcrux-ml-dsa RUSTSEC-2026-0076, a panic while decoding a signature hint
  (fixed in 0.0.8).
- libcrux-ml-dsa RUSTSEC-2026-0077, the signer-response norm check during
  verification (fixed in 0.0.8).
- libcrux-ml-dsa RUSTSEC-2026-0125, AVX2 verification of an edge case
  (fixed in 0.0.9).
- libcrux-ml-dsa RUSTSEC-2026-0126, an informational note that the AVX2
  implementation did not fully reduce intermediate values (fixed in 0.0.9).
- libcrux-kem RUSTSEC-2026-0330, a panic in hybrid encapsulation from a
  short seed (fixed in 0.0.10).
- libcrux-kem RUSTSEC-2026-0331, a panic decoding a short hybrid key
  (fixed in 0.0.10).

The known-answer vectors in this repository were produced with the approved
crates and checked against the Dart code. Switching libraries would be a new
dependency, and it would need the owner's approval.
