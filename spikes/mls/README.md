# MLS measurement spike

Not shipped and not part of the `fireplace-crypto` library or its lockfile. It
measures what Fireplace's group chats (mobile decision 0050) would cost with
**OpenMLS 0.9.2** and **openmls_rust_crypto 0.6.0** (both MIT), as approved by the
owner for a spike on 2026-11-14.

```sh
cd spikes/mls
cargo run --release
```

## Setup

- The group grows the way the product would: one account (four devices) per Commit,
  committed by the first administrator device.
- Welcomes carry the ratchet tree, because they are stored as Firestore documents.
- Handshake messages are encrypted (`PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`).
- Credentials are padded to the size of the real account endorsement (UID, device id,
  Ed25519 + ML-DSA-65 signature, certificate hash), so sizes are not flattered.
- Each row's add figures are for the **last** account added, when the group was
  already nearly full.

## Results (Windows x86-64 laptop, release build, 2026-11-14)

Chosen suite: `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519` (draft-07 `0x0011`;
OpenMLS 0.9.2 still uses the provisional id `0x004e`).

| devices | key package | add commit | Welcome | add: create / apply / join | self-update | update: create / apply | remove account | remove apply | 100-char msg | 16,384-emoji msg | member state |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | 6.0 KiB | 22.0 KiB | 22.1 KiB | 3.2 / 0.0 / 0.9 ms | 9.7 KiB | 1.6 / 0.9 ms | n/a | n/a | 246 B | 64.1 KiB | 73.9 KiB |
| 16 | 6.0 KiB | 43.1 KiB | 82.7 KiB | 4.9 / 3.7 / 2.1 ms | 19.0 KiB | 2.8 / 2.1 ms | 19.2 KiB | 1.7 ms | 246 B | 64.1 KiB | 181.3 KiB |
| 64 | 6.0 KiB | 101.2 KiB | 312.3 KiB | 12.6 / 4.2 / 7.3 ms | 49.2 KiB | 7.6 / 4.0 ms | 77.3 KiB | 4.0 ms | 246 B | 64.1 KiB | 768.9 KiB |

Classical baseline `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, for comparison:

| devices | key package | add commit | Welcome | self-update | remove account | member state |
|---|---|---|---|---|---|---|
| 4 | 3.7 KiB | 11.5 KiB | 11.8 KiB | 4.0 KiB | n/a | 31.7 KiB |
| 16 | 3.7 KiB | 16.2 KiB | 55.0 KiB | 4.5 KiB | 1.5 KiB | 94.4 KiB |
| 64 | 3.7 KiB | 20.1 KiB | 226.7 KiB | 6.5 KiB | 5.4 KiB | 469.3 KiB |

A long message encrypts in 0.3–0.5 ms and decrypts in 0.2–0.3 ms in every case.

## What it shows

- **Everything fits Firestore at 64 devices.** The largest document, a Welcome,
  is 312 KiB against the 1 MiB document limit. The add Commit is 101 KiB. Neither
  needs chunking.
- **Post-quantum cost is in handshakes, not messages.** Ordinary messages are the
  same size as the classical suite: about 146 bytes of overhead, and 64.1 KiB for
  the longest allowed text. Self-updates and removals are 7–14× larger, because
  each path node carries an ML-KEM key and ciphertext.
- **Speed is not a concern.** The slowest operation on this laptop is 12.6 ms
  (adding four devices to a 60-device group). Even at ten times slower on an
  iPhone X, that stays under 130 ms.
- **Local state** for one device in a 64-device group is 769 KiB, well under the
  8 MiB per-group budget in the design.

## Costs and open issues

- **Code size.** OpenMLS adds about 3.2 MB to a release binary here: the spike is
  3,396,608 bytes against a 131,072-byte std-only baseline. Measure on iOS arm64
  before deciding whether the notification extension links it.
- **Dependencies.** 183 crates in total. The provider brings older major versions
  of primitives the core already pins: `aes-gcm` 0.10 (core 0.11),
  `ed25519-dalek` 2 (core 3), `x25519-dalek` 2 (core 3), `rand_core` 0.6 and
  `getrandom` 0.2 (core 0.10 and 0.4), `hkdf` 0.13 and `sha2` 0.11 (core 0.12 and
  0.10). `ml-kem` 0.3.4 and `ml-dsa` 0.1.2 match the core exactly.
- **Wire identifiers.** 0.9.2 uses the provisional suite id `0x004e` and the
  X-Wing draft-06 KEM, where draft-07 uses `0x0011` and KEM `0x647a`. The
  measurements hold, but groups must not ship until an OpenMLS release uses the
  final identifiers; otherwise every group created would need reinitialising.
- **Not measured.** Storage-provider durability (the design's journal), iPhone
  timings and memory, and concurrent-commit behaviour. The spike uses the in-memory
  provider, which is not suitable for production.

AI assistance: Claude Code.
