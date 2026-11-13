//! The C ABI, including the process-global test stream. One lock covers every
//! test in this file because cargo runs tests in parallel.

use std::sync::Mutex;

use fireplace_crypto::ffi::{
    FP_BAD_ARG, FP_INVALID, FP_OK, FpBuf, fp_clear_test_rng, fp_free, fp_identity_generate,
    fp_recovery_parse, fp_session_validate, fp_set_test_rng,
};

static LOCK: Mutex<()> = Mutex::new(());

struct Owned(FpBuf);

impl Owned {
    fn text(&self) -> &str {
        assert!(!self.0.ptr.is_null());
        let bytes = unsafe { std::slice::from_raw_parts(self.0.ptr, self.0.len) };
        std::str::from_utf8(bytes).unwrap()
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { fp_free(self.0.ptr, self.0.len) };
    }
}

fn generate_identity() -> (i32, Owned) {
    let mut out = FpBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    let code = unsafe { fp_identity_generate(&mut out) };
    (code, Owned(out))
}

#[test]
fn seeded_identity_matches_and_null_arguments_are_rejected() {
    let _guard = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let stream: Vec<u8> = (0..128).map(|i| (i * 17 + 3) as u8).collect();
    assert_eq!(
        unsafe { fp_set_test_rng(stream.as_ptr(), stream.len()) },
        FP_OK
    );
    let (code, first) = generate_identity();
    assert_eq!(code, FP_OK);
    assert!(first.text().contains("edSeed"));
    assert_eq!(
        unsafe { fp_set_test_rng(stream.as_ptr(), stream.len()) },
        FP_OK
    );
    let (code, second) = generate_identity();
    assert_eq!(code, FP_OK);
    assert_eq!(first.text(), second.text());
    assert_eq!(
        unsafe { fp_identity_generate(std::ptr::null_mut()) },
        FP_BAD_ARG
    );
    unsafe { fp_free(std::ptr::null_mut(), 0) };
    fp_clear_test_rng();
    drop(first);
    drop(second);
}

#[test]
fn malformed_recovery_and_session_json_do_not_look_valid() {
    let _guard = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    fp_clear_test_rng();
    let text = b"not-a-recovery-key";
    let mut out = FpBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    let code = unsafe { fp_recovery_parse(text.as_ptr(), text.len(), &mut out) };
    assert_eq!(code, FP_INVALID);
    assert!(out.ptr.is_null());
    let mut flag = 1;
    let bad = b"nope";
    assert_eq!(
        unsafe { fp_session_validate(bad.as_ptr(), bad.len(), &mut flag) },
        FP_OK
    );
    assert_eq!(flag, 0);
    assert_eq!(
        unsafe { fp_session_validate(bad.as_ptr(), bad.len(), std::ptr::null_mut()) },
        FP_BAD_ARG
    );
}
