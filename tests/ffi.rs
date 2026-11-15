//! The C ABI, including the process-global test stream. One lock covers every
//! test in this file because cargo runs tests in parallel.

use std::sync::Mutex;

use fireplace_crypto::ffi::{
    FP_BAD_ARG, FP_INVALID, FP_OK, FpBuf, fp_recovery_parse, fp_session_validate,
};
#[cfg(feature = "test-rng")]
use fireplace_crypto::ffi::{fp_clear_test_rng, fp_free, fp_identity_generate, fp_set_test_rng};

static LOCK: Mutex<()> = Mutex::new(());

#[cfg(feature = "test-rng")]
struct Owned(FpBuf);

#[cfg(feature = "test-rng")]
impl Owned {
    fn text(&self) -> &str {
        assert!(!self.0.ptr.is_null());
        let bytes = unsafe { std::slice::from_raw_parts(self.0.ptr, self.0.len) };
        std::str::from_utf8(bytes).unwrap()
    }
}

#[cfg(feature = "test-rng")]
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { fp_free(self.0.ptr, self.0.len) };
    }
}

#[cfg(feature = "test-rng")]
fn generate_identity() -> (i32, Owned) {
    let mut out = FpBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    let code = unsafe { fp_identity_generate(&mut out) };
    (code, Owned(out))
}

#[cfg(feature = "test-rng")]
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
    #[cfg(feature = "test-rng")]
    fp_clear_test_rng();
    let text = b"not-a-recovery-key";
    let mut out = FpBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    let code = unsafe { fp_recovery_parse(text.as_ptr(), text.len(), &mut out) };
    assert_eq!(code, FP_INVALID);
    assert!(out.ptr.is_null());
    // Text with a longer character in it is refused the same way.
    let text = format!("{}\u{e9}AAA", "A".repeat(31));
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

#[test]
fn link_seal_and_open_take_the_qr_secret() {
    use fireplace_crypto::ffi::{fp_free, fp_link_open_v2, fp_link_seal_v2};
    use fireplace_crypto::{AccountIdentity, DeviceKeys, Rng};

    let _guard = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    #[cfg(feature = "test-rng")]
    fp_clear_test_rng();
    let mut rng = Rng::os();
    let identity = AccountIdentity::generate(&mut rng).unwrap().to_json();
    let device = DeviceKeys::generate(&mut rng).unwrap();
    let device_json = device.to_json();
    let uid = b"ada";
    let secret = [9u8; 16];
    let empty = || FpBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
    };

    let seal = |secret: &[u8], out: &mut FpBuf| unsafe {
        fp_link_seal_v2(
            identity.as_ptr(),
            identity.len(),
            uid.as_ptr(),
            uid.len(),
            device.device_id.as_ptr(),
            device.device_id.len(),
            device.x25519_pub.as_ptr(),
            device.x25519_pub.len(),
            device.kem_pub.as_ptr(),
            device.kem_pub.len(),
            secret.as_ptr(),
            secret.len(),
            out,
        )
    };
    let mut sealed = empty();
    assert_eq!(seal(&secret, &mut sealed), FP_OK);
    let open = |secret: &[u8], out: &mut FpBuf| unsafe {
        fp_link_open_v2(
            sealed.ptr,
            sealed.len,
            uid.as_ptr(),
            uid.len(),
            device_json.as_ptr(),
            device_json.len(),
            secret.as_ptr(),
            secret.len(),
            out,
        )
    };

    let mut opened = empty();
    assert_eq!(open(&secret, &mut opened), FP_OK);
    let text = unsafe { std::slice::from_raw_parts(opened.ptr, opened.len) };
    assert_eq!(text, identity.as_bytes());
    unsafe { fp_free(opened.ptr, opened.len) };

    // A wrong secret gives an error and no output; so does one that is too short.
    let mut refused = empty();
    assert_ne!(open(&[8u8; 16], &mut refused), FP_OK);
    assert!(refused.ptr.is_null());
    assert_eq!(open(&secret[..15], &mut refused), FP_INVALID);
    assert!(refused.ptr.is_null());
    assert_eq!(seal(&secret[..15], &mut refused), FP_INVALID);
    assert!(refused.ptr.is_null());

    unsafe { fp_free(sealed.ptr, sealed.len) };
}
