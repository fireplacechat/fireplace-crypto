//! A live session retains its transient failed-chain budget between C calls.
//! JSON-only operations remain available for one-shot, read-only consumers.

use super::{FP_BAD_ARG, FpBuf, call, clear_buf, slice, text, with_rng, write_buf, write_two};
use crate::{Envelope, Error, Session, system_now_ms};

/// Opaque to C. Access on one thread at a time and destroy exactly once.
pub struct FpSession {
    session: Session,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_load(
    json: *const u8,
    len: usize,
    out: *mut *mut FpSession,
) -> i32 {
    if out.is_null() {
        return FP_BAD_ARG;
    }
    unsafe { *out = std::ptr::null_mut() };
    call(|| {
        let session = Session::from_json(unsafe { text(json, len)? })?;
        let handle = Box::new(FpSession { session });
        unsafe { *out = Box::into_raw(handle) };
        Ok(())
    })
}

/// Suitable for a Dart NativeFinalizer. A null pointer is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_destroy(handle: *mut FpSession) {
    if !handle.is_null() {
        let _ = std::panic::catch_unwind(|| drop(unsafe { Box::from_raw(handle) }));
    }
}

unsafe fn session<'a>(handle: *mut FpSession) -> crate::Result<&'a mut Session> {
    if handle.is_null() {
        return Err(Error::BadArg);
    }
    Ok(unsafe { &mut (*handle).session })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_save(handle: *mut FpSession, out: *mut FpBuf) -> i32 {
    clear_buf(out);
    call(|| {
        let session = unsafe { session(handle)? };
        write_buf(out, session.to_json().into_bytes())
    })
}

// Validate outputs before advancing a live session. Distinct descriptors prevent
// overwriting an allocation and leaking it when C supplies the same slot twice.
fn outputs(first: *mut FpBuf, second: *mut FpBuf) -> crate::Result<()> {
    if first.is_null() || second.is_null() || first == second {
        return Err(Error::BadArg);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_session_encrypt_handle(
    handle: *mut FpSession,
    chat: *const u8,
    chat_len: usize,
    plain: *const u8,
    plain_len: usize,
    out_session: *mut FpBuf,
    out_envelope: *mut FpBuf,
) -> i32 {
    clear_buf(out_session);
    clear_buf(out_envelope);
    call(|| {
        outputs(out_session, out_envelope)?;
        let session = unsafe { session(handle)? };
        let chat = unsafe { text(chat, chat_len)? };
        let plain = unsafe { slice(plain, plain_len)? };
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
pub unsafe extern "C" fn fp_session_decrypt_handle(
    handle: *mut FpSession,
    envelope: *const u8,
    envelope_len: usize,
    chat: *const u8,
    chat_len: usize,
    now_ms: *const i64,
    out_session: *mut FpBuf,
    out_plain: *mut FpBuf,
) -> i32 {
    clear_buf(out_session);
    clear_buf(out_plain);
    call(|| {
        outputs(out_session, out_plain)?;
        let session = unsafe { session(handle)? };
        let envelope = Envelope::from_json(unsafe { text(envelope, envelope_len)? })?;
        let chat = unsafe { text(chat, chat_len)? };
        let now = if now_ms.is_null() {
            system_now_ms()
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
