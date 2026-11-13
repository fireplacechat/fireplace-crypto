//! C ABI. Every output buffer is allocated by the library and released with
//! [`fp_free`]. A panic inside an exported function becomes `FP_PANIC` and
//! does not unwind into the caller.
//!
//! The test stream (`fp_set_test_rng`) replaces the operating-system generator
//! for every call until it is cleared. It is process-global and meant for one
//! thread.
//!
//! # Safety
//!
//! Each pointer must address `len` bytes, or be null where this file says a
//! null is allowed. An output `FpBuf` must be writable. The caller releases
//! every returned buffer with [`fp_free`] and does not use it afterwards.
//! [`fp_set_test_rng`] is one thread at a time. The functions share that
//! contract, so the per-function safety lint is allowed here.

#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc, clippy::too_many_arguments)]

use std::panic::AssertUnwindSafe;
use std::sync::Mutex;

use crate::device::{DeviceBundle, DeviceKeys};
use crate::error::{Error, Result};
use crate::fingerprint::{identity_fingerprint, safety_number};
use crate::identity::AccountIdentity;
use crate::link::{self, SealedIdentity};
use crate::prekeys::{self, PreKeyBundle, PreKeyRecord};
use crate::recovery::{self, RecoveryKey};
use crate::rng::Rng;
use crate::session::{self, Envelope, HandshakeInit, Session};

pub const FP_OK: i32 = 0;
pub const FP_INVALID: i32 = 1;
pub const FP_CRYPTO: i32 = 2;
pub const FP_RATE_LIMITED: i32 = 3;
pub const FP_PANIC: i32 = 4;
pub const FP_RNG: i32 = 5;
pub const FP_BAD_ARG: i32 = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FpBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

struct TestStream {
    data: Vec<u8>,
}

static TEST_RNG: Mutex<Option<TestStream>> = Mutex::new(None);

fn with_rng<T>(body: impl FnOnce(&mut Rng) -> Result<T>) -> Result<T> {
    let mut guard = TEST_RNG.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(stream) = guard.as_mut() {
        let mut rng = Rng::stream(std::mem::take(&mut stream.data));
        let result = body(&mut rng);
        if let Some(left) = rng.remaining() {
            let data = rng_into_rest(&mut rng, left);
            stream.data = data;
        }
        result
    } else {
        drop(guard);
        body(&mut Rng::os())
    }
}

fn rng_into_rest(rng: &mut Rng, left: usize) -> Vec<u8> {
    // Rebuild the unconsumed tail by drawing it. `remaining` was checked by
    // the caller, so this draw succeeds and leaves the original stream empty.
    rng.bytes(left).unwrap_or_default()
}

fn code(error: Error) -> i32 {
    match error {
        Error::Invalid(_) => FP_INVALID,
        Error::Crypto(_) => FP_CRYPTO,
        Error::RateLimited => FP_RATE_LIMITED,
        Error::Rng => FP_RNG,
        Error::BadArg => FP_BAD_ARG,
    }
}

fn finish(result: Result<()>) -> i32 {
    match result {
        Ok(()) => FP_OK,
        Err(error) => code(error),
    }
}

fn call(body: impl FnOnce() -> Result<()>) -> i32 {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(result) => finish(result),
        Err(_) => FP_PANIC,
    }
}

unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Error::BadArg);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

unsafe fn text<'a>(ptr: *const u8, len: usize) -> Result<&'a str> {
    let bytes = unsafe { slice(ptr, len)? };
    std::str::from_utf8(bytes).map_err(|_| Error::Invalid("utf8"))
}

fn write_buf(out: *mut FpBuf, bytes: Vec<u8>) -> Result<()> {
    if out.is_null() {
        return Err(Error::BadArg);
    }
    let len = bytes.len();
    let ptr = if len == 0 {
        std::ptr::null_mut()
    } else {
        Box::into_raw(bytes.into_boxed_slice()).cast::<u8>()
    };
    unsafe {
        *out = FpBuf { ptr, len };
    }
    Ok(())
}

fn clear_buf(out: *mut FpBuf) {
    if !out.is_null() {
        unsafe {
            *out = FpBuf {
                ptr: std::ptr::null_mut(),
                len: 0,
            };
        }
    }
}

/// Drop a buffer this call already published, so a later failure does not leak it.
fn rollback(out: *mut FpBuf) {
    if out.is_null() {
        return;
    }
    let buf = unsafe { *out };
    clear_buf(out);
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
    }));
}

fn write_two(
    first: *mut FpBuf,
    first_bytes: Vec<u8>,
    second: *mut FpBuf,
    second_bytes: Vec<u8>,
) -> Result<()> {
    write_buf(first, first_bytes)?;
    if let Err(error) = write_buf(second, second_bytes) {
        rollback(first);
        return Err(error);
    }
    Ok(())
}

fn write_flag(slot: *mut i32, value: bool) -> Result<()> {
    if slot.is_null() {
        return Err(Error::BadArg);
    }
    unsafe {
        *slot = i32::from(value);
    }
    Ok(())
}

/// Release a buffer returned by this library. `len` must be the length that
/// was returned with `ptr`. A null pointer is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }));
}

/// Install a finite stream used instead of the operating system. An empty
/// slice clears it. Single-threaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_set_test_rng(bytes: *const u8, len: usize) -> i32 {
    call(|| {
        let data = unsafe { slice(bytes, len)? }.to_vec();
        let mut guard = TEST_RNG.lock().unwrap_or_else(|poison| poison.into_inner());
        *guard = if data.is_empty() {
            None
        } else {
            Some(TestStream { data })
        };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn fp_clear_test_rng() {
    if let Ok(mut guard) = TEST_RNG.lock() {
        *guard = None;
    } else if let Err(poison) = TEST_RNG.lock() {
        *poison.into_inner() = None;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_identity_generate(out_json: *mut FpBuf) -> i32 {
    clear_buf(out_json);
    call(|| {
        let identity = with_rng(AccountIdentity::generate)?;
        write_buf(out_json, identity.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_identity_public(
    json: *const u8,
    json_len: usize,
    out: *mut FpBuf,
) -> i32 {
    clear_buf(out);
    call(|| {
        let identity = AccountIdentity::from_json(unsafe { text(json, json_len)? })?;
        write_buf(out, identity.public_bytes()?)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_identity_sign(
    json: *const u8,
    json_len: usize,
    message: *const u8,
    message_len: usize,
    out: *mut FpBuf,
) -> i32 {
    clear_buf(out);
    call(|| {
        let identity = AccountIdentity::from_json(unsafe { text(json, json_len)? })?;
        let message = unsafe { slice(message, message_len)? };
        let signature = with_rng(|rng| identity.sign(message, rng))?;
        write_buf(out, signature)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_identity_verify(
    public_bytes: *const u8,
    public_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
    out_ok: *mut i32,
) -> i32 {
    call(|| {
        let ok = AccountIdentity::verify(
            unsafe { slice(public_bytes, public_len)? },
            unsafe { slice(message, message_len)? },
            unsafe { slice(signature, signature_len)? },
        );
        write_flag(out_ok, ok)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_identity_consistent(
    json: *const u8,
    json_len: usize,
    out_ok: *mut i32,
) -> i32 {
    call(|| {
        let identity = AccountIdentity::from_json(unsafe { text(json, json_len)? })?;
        let ok = with_rng(|rng| identity.consistent(rng))?;
        write_flag(out_ok, ok)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_device_generate(out_json: *mut FpBuf) -> i32 {
    clear_buf(out_json);
    call(|| {
        let keys = with_rng(DeviceKeys::generate)?;
        write_buf(out_json, keys.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_device_certify(
    device_json: *const u8,
    device_len: usize,
    identity_json: *const u8,
    identity_len: usize,
    uid: *const u8,
    uid_len: usize,
    out_json: *mut FpBuf,
) -> i32 {
    clear_buf(out_json);
    call(|| {
        let keys = DeviceKeys::from_json(unsafe { text(device_json, device_len)? })?;
        let identity = AccountIdentity::from_json(unsafe { text(identity_json, identity_len)? })?;
        let uid = unsafe { text(uid, uid_len)? };
        let bundle = with_rng(|rng| keys.certify(&identity, uid, rng))?;
        write_buf(out_json, bundle.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_device_verify_cert(
    bundle_json: *const u8,
    bundle_len: usize,
    out_ok: *mut i32,
) -> i32 {
    call(|| {
        let bundle = DeviceBundle::from_json(unsafe { text(bundle_json, bundle_len)? })?;
        write_flag(out_ok, bundle.verify_cert())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_device_consistent(
    json: *const u8,
    json_len: usize,
    out_ok: *mut i32,
) -> i32 {
    call(|| {
        let keys = DeviceKeys::from_json(unsafe { text(json, json_len)? })?;
        write_flag(out_ok, keys.consistent())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_prekey_generate(now_ms: i64, out_json: *mut FpBuf) -> i32 {
    clear_buf(out_json);
    call(|| {
        let record = with_rng(|rng| PreKeyRecord::generate(rng, now_ms))?;
        write_buf(out_json, record.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_prekey_sign(
    record_json: *const u8,
    record_len: usize,
    identity_json: *const u8,
    identity_len: usize,
    uid: *const u8,
    uid_len: usize,
    device_id: *const u8,
    device_len: usize,
    out_json: *mut FpBuf,
) -> i32 {
    clear_buf(out_json);
    call(|| {
        let record = PreKeyRecord::from_json(unsafe { text(record_json, record_len)? })?;
        let identity = AccountIdentity::from_json(unsafe { text(identity_json, identity_len)? })?;
        let uid = unsafe { text(uid, uid_len)? };
        let device_id = unsafe { text(device_id, device_len)? };
        let signed = with_rng(|rng| prekeys::sign(&record, &identity, uid, device_id, rng))?;
        write_buf(out_json, signed.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_prekey_onetime(
    record_json: *const u8,
    record_len: usize,
    out_json: *mut FpBuf,
) -> i32 {
    clear_buf(out_json);
    call(|| {
        let record = PreKeyRecord::from_json(unsafe { text(record_json, record_len)? })?;
        write_buf(out_json, prekeys::one_time(&record).to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_prekey_verify(
    bundle_json: *const u8,
    bundle_len: usize,
    signed_json: *const u8,
    signed_len: usize,
    out_ok: *mut i32,
) -> i32 {
    call(|| {
        let bundle = DeviceBundle::from_json(unsafe { text(bundle_json, bundle_len)? })?;
        let signed =
            prekeys::PublishedPreKey::from_json(unsafe { text(signed_json, signed_len)? })?;
        write_flag(out_ok, prekeys::verify_signed(&bundle, &signed))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_initiate(
    local_json: *const u8,
    local_len: usize,
    local_bundle_json: *const u8,
    local_bundle_len: usize,
    remote_json: *const u8,
    remote_len: usize,
    now_ms: i64,
    out_session: *mut FpBuf,
    out_handshake: *mut FpBuf,
) -> i32 {
    clear_buf(out_session);
    clear_buf(out_handshake);
    call(|| {
        let local = DeviceKeys::from_json(unsafe { text(local_json, local_len)? })?;
        let local_bundle =
            DeviceBundle::from_json(unsafe { text(local_bundle_json, local_bundle_len)? })?;
        let remote = PreKeyBundle::from_json(unsafe { text(remote_json, remote_len)? })?;
        let (session, handshake) =
            with_rng(|rng| Session::initiate(&local, &local_bundle, &remote, rng, now_ms))?;
        write_two(
            out_session,
            session.to_json().into_bytes(),
            out_handshake,
            handshake.to_json().into_bytes(),
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_accept(
    local_json: *const u8,
    local_len: usize,
    local_bundle_json: *const u8,
    local_bundle_len: usize,
    remote_json: *const u8,
    remote_len: usize,
    handshake_json: *const u8,
    handshake_len: usize,
    signed_json: *const u8,
    signed_len: usize,
    one_time_json: *const u8,
    one_time_len: usize,
    now_ms: i64,
    out_session: *mut FpBuf,
) -> i32 {
    clear_buf(out_session);
    call(|| {
        let local = DeviceKeys::from_json(unsafe { text(local_json, local_len)? })?;
        let local_bundle =
            DeviceBundle::from_json(unsafe { text(local_bundle_json, local_bundle_len)? })?;
        let remote = DeviceBundle::from_json(unsafe { text(remote_json, remote_len)? })?;
        let handshake = HandshakeInit::from_json(unsafe { text(handshake_json, handshake_len)? })?;
        let signed = PreKeyRecord::from_json(unsafe { text(signed_json, signed_len)? })?;
        let one_time = if one_time_json.is_null() || one_time_len == 0 {
            None
        } else {
            Some(PreKeyRecord::from_json(unsafe {
                text(one_time_json, one_time_len)?
            })?)
        };
        let session = Session::accept(
            &local,
            &local_bundle,
            &remote,
            &handshake,
            &signed,
            one_time.as_ref(),
            now_ms,
        )?;
        write_buf(out_session, session.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_encrypt(
    session_json: *const u8,
    session_len: usize,
    chat_id: *const u8,
    chat_len: usize,
    plaintext: *const u8,
    plain_len: usize,
    out_session: *mut FpBuf,
    out_envelope: *mut FpBuf,
) -> i32 {
    clear_buf(out_session);
    clear_buf(out_envelope);
    call(|| {
        let mut session = Session::from_json(unsafe { text(session_json, session_len)? })?;
        let chat = unsafe { text(chat_id, chat_len)? };
        let plain = unsafe { slice(plaintext, plain_len)? };
        let envelope = with_rng(|rng| session.encrypt(plain, chat, rng))?;
        write_two(
            out_session,
            session.to_json().into_bytes(),
            out_envelope,
            envelope.to_json().into_bytes(),
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_decrypt(
    session_json: *const u8,
    session_len: usize,
    envelope_json: *const u8,
    envelope_len: usize,
    chat_id: *const u8,
    chat_len: usize,
    now_ms: *const i64,
    out_session: *mut FpBuf,
    out_plain: *mut FpBuf,
) -> i32 {
    clear_buf(out_session);
    clear_buf(out_plain);
    call(|| {
        let mut session = Session::from_json(unsafe { text(session_json, session_len)? })?;
        let envelope = Envelope::from_json(unsafe { text(envelope_json, envelope_len)? })?;
        let chat = unsafe { text(chat_id, chat_len)? };
        let now = if now_ms.is_null() {
            session::system_now_ms()
        } else {
            unsafe { *now_ms }
        };
        let plain = with_rng(|rng| session.decrypt(&envelope, chat, rng, now))?;
        write_two(
            out_session,
            session.to_json().into_bytes(),
            out_plain,
            plain,
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_validate(
    json: *const u8,
    json_len: usize,
    out_ok: *mut i32,
) -> i32 {
    if out_ok.is_null() {
        return FP_BAD_ARG;
    }
    call(|| {
        let ok = match unsafe { text(json, json_len) } {
            Ok(text) => Session::try_from_json(text).is_some(),
            Err(_) => false,
        };
        write_flag(out_ok, ok)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_self_check(
    json: *const u8,
    json_len: usize,
    out_ok: *mut i32,
) -> i32 {
    call(|| {
        let session = Session::from_json(unsafe { text(json, json_len)? })?;
        write_flag(out_ok, session.self_check())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_recovery_generate(out_key: *mut FpBuf) -> i32 {
    clear_buf(out_key);
    call(|| {
        let key = with_rng(RecoveryKey::generate)?;
        write_buf(out_key, key.as_bytes().to_vec())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_recovery_display(
    key: *const u8,
    key_len: usize,
    out_text: *mut FpBuf,
) -> i32 {
    clear_buf(out_text);
    call(|| {
        let key = RecoveryKey::from_bytes(unsafe { slice(key, key_len)? })?;
        write_buf(out_text, key.display()?.into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_recovery_parse(
    text_ptr: *const u8,
    text_len: usize,
    out_key: *mut FpBuf,
) -> i32 {
    clear_buf(out_key);
    call(|| {
        let text = unsafe { text(text_ptr, text_len)? };
        match RecoveryKey::parse(text)? {
            Some(key) => write_buf(out_key, key.as_bytes().to_vec()),
            None => Err(Error::Invalid("recovery key")),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_recovery_encrypt(
    identity_json: *const u8,
    identity_len: usize,
    key: *const u8,
    key_len: usize,
    out_blob: *mut FpBuf,
) -> i32 {
    clear_buf(out_blob);
    call(|| {
        let identity = AccountIdentity::from_json(unsafe { text(identity_json, identity_len)? })?;
        let key = RecoveryKey::from_bytes(unsafe { slice(key, key_len)? })?;
        let blob = with_rng(|rng| recovery::encrypt(&identity, &key, rng))?;
        write_buf(out_blob, blob.into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_recovery_decrypt(
    blob: *const u8,
    blob_len: usize,
    key: *const u8,
    key_len: usize,
    out_json: *mut FpBuf,
) -> i32 {
    clear_buf(out_json);
    call(|| {
        let blob = unsafe { text(blob, blob_len)? };
        let key = RecoveryKey::from_bytes(unsafe { slice(key, key_len)? })?;
        let identity = recovery::decrypt(blob, &key)?;
        write_buf(out_json, identity.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_link_fingerprint(
    x25519: *const u8,
    x_len: usize,
    kem: *const u8,
    kem_len: usize,
    out_text: *mut FpBuf,
) -> i32 {
    clear_buf(out_text);
    call(|| {
        let text = link::request_fingerprint(unsafe { slice(x25519, x_len)? }, unsafe {
            slice(kem, kem_len)?
        })?;
        write_buf(out_text, text.into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_link_confirmation(
    identity_pub: *const u8,
    identity_len: usize,
    x25519: *const u8,
    x_len: usize,
    kem: *const u8,
    kem_len: usize,
    out_text: *mut FpBuf,
) -> i32 {
    clear_buf(out_text);
    call(|| {
        let text = link::confirmation_code(
            unsafe { slice(identity_pub, identity_len)? },
            unsafe { slice(x25519, x_len)? },
            unsafe { slice(kem, kem_len)? },
        )?;
        write_buf(out_text, text.into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_link_seal(
    identity_json: *const u8,
    identity_len: usize,
    uid: *const u8,
    uid_len: usize,
    device_id: *const u8,
    device_len: usize,
    x25519: *const u8,
    x_len: usize,
    kem: *const u8,
    kem_len: usize,
    out_json: *mut FpBuf,
) -> i32 {
    clear_buf(out_json);
    call(|| {
        let identity = AccountIdentity::from_json(unsafe { text(identity_json, identity_len)? })?;
        let uid = unsafe { text(uid, uid_len)? };
        let device_id = unsafe { text(device_id, device_len)? };
        let x25519 = unsafe { slice(x25519, x_len)? }.to_vec();
        let kem = unsafe { slice(kem, kem_len)? }.to_vec();
        let sealed = with_rng(|rng| link::seal(&identity, uid, device_id, &x25519, &kem, rng))?;
        write_buf(out_json, sealed.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_link_open(
    sealed_json: *const u8,
    sealed_len: usize,
    uid: *const u8,
    uid_len: usize,
    device_json: *const u8,
    device_len: usize,
    out_json: *mut FpBuf,
) -> i32 {
    clear_buf(out_json);
    call(|| {
        let sealed = SealedIdentity::from_json(unsafe { text(sealed_json, sealed_len)? })?;
        let uid = unsafe { text(uid, uid_len)? };
        let keys = DeviceKeys::from_json(unsafe { text(device_json, device_len)? })?;
        let identity = link::open(&sealed, uid, &keys)?;
        write_buf(out_json, identity.to_json().into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_safety_number(
    identity_a: *const u8,
    a_len: usize,
    identity_b: *const u8,
    b_len: usize,
    out_text: *mut FpBuf,
) -> i32 {
    clear_buf(out_text);
    call(|| {
        let text = safety_number(unsafe { slice(identity_a, a_len)? }, unsafe {
            slice(identity_b, b_len)?
        })?;
        write_buf(out_text, text.into_bytes())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_identity_fingerprint(
    identity: *const u8,
    identity_len: usize,
    out_text: *mut FpBuf,
) -> i32 {
    clear_buf(out_text);
    call(|| {
        let text = identity_fingerprint(unsafe { slice(identity, identity_len)? })?;
        write_buf(out_text, text.into_bytes())
    })
}
