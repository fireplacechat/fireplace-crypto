/* C ABI for fireplace_crypto.
 *
 * Every output buffer is allocated by the library. Pass its pointer and
 * length to fp_free. A null pointer or a zero length is ignored.
 * Strings are UTF-8 with no trailing NUL. JSON uses the same field order
 * and omissions as the Dart implementation.
 *
 * Return codes: 0 ok, 1 invalid input, 2 protocol refusal, 3 rate limited,
 * 4 the library panicked and caught it, 5 the generator failed, 6 a null
 * argument. A verify function that returns false is still 0, with *out_ok
 * set to 0.
 *
 * fp_free wipes a returned buffer before freeing it.
 *
 * fp_set_test_rng and fp_clear_test_rng are compiled only with the Cargo
 * feature test-rng, which is off by default. A normal release build does
 * not export them. Define FP_TEST_RNG when the library was built with that
 * feature. With it on, the stream replaces the operating-system generator
 * for this process until it is cleared, and only one thread may use it.
 *
 * fp_session_decrypt reads *now_ms when that pointer is non-null. A null
 * pointer uses the system clock. A null or empty one-time prekey on
 * fp_session_accept means there is none.
 */
#ifndef FIREPLACE_CRYPTO_H
#define FIREPLACE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    FP_OK = 0,
    FP_INVALID = 1,
    FP_CRYPTO = 2,
    FP_RATE_LIMITED = 3,
    FP_PANIC = 4,
    FP_RNG = 5,
    FP_BAD_ARG = 6
};

typedef struct FpBuf {
    uint8_t *ptr;
    size_t len;
} FpBuf;

void fp_free(uint8_t *ptr, size_t len);
#ifdef FP_TEST_RNG
int32_t fp_set_test_rng(const uint8_t *bytes, size_t len);
void fp_clear_test_rng(void);
#endif

int32_t fp_identity_generate(FpBuf *out_json);
int32_t fp_identity_public(const uint8_t *json, size_t json_len, FpBuf *out);
int32_t fp_identity_sign(const uint8_t *json, size_t json_len, const uint8_t *message,
                         size_t message_len, FpBuf *out);
int32_t fp_identity_verify(const uint8_t *public_bytes, size_t public_len, const uint8_t *message,
                           size_t message_len, const uint8_t *signature, size_t signature_len,
                           int32_t *out_ok);
int32_t fp_identity_consistent(const uint8_t *json, size_t json_len, int32_t *out_ok);
int32_t fp_identity_fingerprint(const uint8_t *identity, size_t identity_len, FpBuf *out_text);

int32_t fp_device_generate(FpBuf *out_json);
int32_t fp_device_certify(const uint8_t *device_json, size_t device_len, const uint8_t *identity_json,
                          size_t identity_len, const uint8_t *uid, size_t uid_len, FpBuf *out_json);
int32_t fp_device_verify_cert(const uint8_t *bundle_json, size_t bundle_len, int32_t *out_ok);
int32_t fp_device_consistent(const uint8_t *json, size_t json_len, int32_t *out_ok);

int32_t fp_prekey_generate(int64_t now_ms, FpBuf *out_json);
int32_t fp_prekey_sign(const uint8_t *record_json, size_t record_len, const uint8_t *identity_json,
                       size_t identity_len, const uint8_t *uid, size_t uid_len, const uint8_t *device_id,
                       size_t device_len, FpBuf *out_json);
int32_t fp_prekey_onetime(const uint8_t *record_json, size_t record_len, FpBuf *out_json);
int32_t fp_prekey_verify(const uint8_t *bundle_json, size_t bundle_len, const uint8_t *signed_json,
                         size_t signed_len, int32_t *out_ok);

int32_t fp_session_initiate(const uint8_t *local_json, size_t local_len, const uint8_t *local_bundle_json,
                            size_t local_bundle_len, const uint8_t *remote_json, size_t remote_len,
                            int64_t now_ms, FpBuf *out_session, FpBuf *out_handshake);
int32_t fp_session_accept(const uint8_t *local_json, size_t local_len, const uint8_t *local_bundle_json,
                          size_t local_bundle_len, const uint8_t *remote_json, size_t remote_len,
                          const uint8_t *handshake_json, size_t handshake_len, const uint8_t *signed_json,
                          size_t signed_len, const uint8_t *one_time_json, size_t one_time_len, int64_t now_ms,
                          FpBuf *out_session);
int32_t fp_session_encrypt(const uint8_t *session_json, size_t session_len, const uint8_t *chat_id,
                           size_t chat_len, const uint8_t *plaintext, size_t plain_len, FpBuf *out_session,
                           FpBuf *out_envelope);
int32_t fp_session_decrypt(const uint8_t *session_json, size_t session_len, const uint8_t *envelope_json,
                           size_t envelope_len, const uint8_t *chat_id, size_t chat_len, const int64_t *now_ms,
                           FpBuf *out_session, FpBuf *out_plain);
int32_t fp_session_validate(const uint8_t *json, size_t json_len, int32_t *out_ok);
int32_t fp_session_self_check(const uint8_t *json, size_t json_len, int32_t *out_ok);

/* Live sessions retain the transient failed-chain budget across calls. The
 * JSON-only decrypt above creates a fresh session (and budget) on each call;
 * use it for one-shot copies, not an app's ongoing receive loop.
 *
 * A handle is owned by the caller: use on one thread at a time, destroy
 * exactly once, and never access it after destruction. Destroy accepts null
 * and drops the session, wiping its private state. No handles are global.
 * Output descriptors must be distinct and cannot alias the handle or inputs.
 * Save and successful operations return exactly the existing session JSON;
 * the budget is never persisted. Failed decrypts retain only that budget,
 * leave ratchet state intact, and return empty output buffers.
 */
/* Group chats: compiled only with the Cargo feature groups. Define
 * FP_GROUPS when the library was built with it. One handle is one device's
 * MLS store. fp_group_open takes the saved records (len 0 for a new device)
 * as a length-prefixed list key, value, key, value; fp_group_records returns
 * the same form. fp_group_call takes a JSON request {"op": ...} and returns
 * JSON. A changing request returns "changes" and stays open until the
 * request {"op":"accept"} or {"op":"rollback"}; see src/group/mod.rs. */
#ifdef FP_GROUPS
typedef struct FpGroups FpGroups;
int32_t fp_group_open(const uint8_t *records, size_t len, FpGroups **out);
void fp_group_destroy(FpGroups *handle);
int32_t fp_group_records(FpGroups *handle, FpBuf *out);
int32_t fp_group_call(FpGroups *handle, const uint8_t *request, size_t len, FpBuf *out);
#endif

typedef struct FpSession FpSession;
int32_t fp_session_load(const uint8_t *json, size_t len, FpSession **out);
void fp_session_destroy(FpSession *handle);
int32_t fp_session_save(FpSession *handle, FpBuf *out);
int32_t fp_session_encrypt_handle(FpSession *handle, const uint8_t *chat, size_t chat_len,
                                  const uint8_t *plain, size_t plain_len,
                                  FpBuf *out_session, FpBuf *out_envelope);
int32_t fp_session_decrypt_handle(FpSession *handle, const uint8_t *envelope, size_t envelope_len,
                                  const uint8_t *chat, size_t chat_len, const int64_t *now_ms,
                                  FpBuf *out_session, FpBuf *out_plain);

int32_t fp_recovery_generate(FpBuf *out_key);
int32_t fp_recovery_display(const uint8_t *key, size_t key_len, FpBuf *out_text);
int32_t fp_recovery_parse(const uint8_t *text, size_t text_len, FpBuf *out_key);
int32_t fp_recovery_encrypt(const uint8_t *identity_json, size_t identity_len, const uint8_t *key,
                            size_t key_len, FpBuf *out_blob);
int32_t fp_recovery_decrypt(const uint8_t *blob, size_t blob_len, const uint8_t *key, size_t key_len,
                            FpBuf *out_json);

int32_t fp_link_fingerprint(const uint8_t *x25519, size_t x_len, const uint8_t *kem, size_t kem_len,
                            FpBuf *out_text);
int32_t fp_link_confirmation(const uint8_t *identity_pub, size_t identity_len, const uint8_t *x25519,
                             size_t x_len, const uint8_t *kem, size_t kem_len, FpBuf *out_text);
int32_t fp_link_seal(const uint8_t *identity_json, size_t identity_len, const uint8_t *uid, size_t uid_len,
                     const uint8_t *device_id, size_t device_len, const uint8_t *x25519, size_t x_len,
                     const uint8_t *kem, size_t kem_len, FpBuf *out_json);
int32_t fp_link_open(const uint8_t *sealed_json, size_t sealed_len, const uint8_t *uid, size_t uid_len,
                     const uint8_t *device_json, size_t device_len, FpBuf *out_json);

int32_t fp_safety_number(const uint8_t *identity_a, size_t a_len, const uint8_t *identity_b, size_t b_len,
                         FpBuf *out_text);

#ifdef __cplusplus
}
#endif

#endif
