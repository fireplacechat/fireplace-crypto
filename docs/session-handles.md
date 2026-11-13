# Live sessions over the C ABI

The JSON-only `fp_session_decrypt` loads a fresh session on every call. Its
ratchet state is byte-compatible with Dart, but the failed-new-chain budget
is deliberately absent from saved JSON. Repeated calls therefore reset the
budget, unlike a long-lived Rust or Dart session. An ongoing app session must
retain that transient state in memory too.

Version 0.1.1 adds an opaque `FpSession` handle. Load existing JSON with
`fp_session_load`, then use `fp_session_encrypt_handle` and
`fp_session_decrypt_handle`. Save with `fp_session_save`, and release exactly
once with `fp_session_destroy`. Destruction drops the existing zeroising
session state. Dart can register destruction with `NativeFinalizer` and
also close a handle explicitly when its account is disposed.

Each handle belongs to its caller. No global session registry, storage,
networking or dependencies are added. A handle must not be accessed
concurrently, used after destruction, or destroyed twice. Input and output
allocations must not alias it, and output buffer descriptors must be distinct.
Every returned buffer still belongs to the core and is freed with `fp_free`.

The new operations export exactly the existing session JSON on success.
Failed decrypts change only the in-memory failure budget; their outputs are
empty and the ratchet remains usable. Bad output arguments are rejected
before encryption can advance the ratchet. Loading a saved copy starts with
an empty budget, matching an app restart in Dart. The stateless ABI remains
available for bounded, one-shot reads such as a notification preview.

Regression tests exercise eight failed new-chain decrypts followed by the
ninth refusal, the exact 60-second expiry boundary, same-chain traffic and
cheap replay refusal at the limit, independence of loaded copies, unchanged
saved JSON on failure, and continuation between C handles and Rust sessions.

The owner reviews, merges and publishes the patch. The mobile application's
crate pin changes in its own pull request after publication. This addition
does not select the Rust backend in production or change the wire or storage
formats.
