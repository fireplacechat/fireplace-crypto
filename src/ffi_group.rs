//! C functions for group chats (Cargo feature `groups`). One handle is one
//! device's [`GroupStore`]; requests and results are JSON (see `group/mod.rs`).
//!
//! Saved records cross the boundary as one binary blob: a length-prefixed list
//! `key, value, key, value, ...` (the codec's `lp`), because a store can hold
//! several megabytes and JSON with base64 would add a third.

use std::collections::HashMap;

use super::{FP_BAD_ARG, FpBuf, call, clear_buf, slice, text, write_buf};
use crate::codec::{lp, unlp};
use crate::group::{GroupStore, MAX_INPUT};
use crate::{Error, Result};

/// Opaque to C. Use on one thread at a time and destroy exactly once.
pub struct FpGroups {
    store: GroupStore,
}

fn decode_records(bytes: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    if bytes.is_empty() {
        return Ok(HashMap::new());
    }
    let parts = unlp(bytes)?;
    if parts.len() % 2 != 0 {
        return Err(Error::Invalid("records"));
    }
    let mut records = HashMap::with_capacity(parts.len() / 2);
    let mut it = parts.into_iter();
    while let (Some(k), Some(v)) = (it.next(), it.next()) {
        if records.insert(k, v).is_some() {
            return Err(Error::Invalid("duplicate record"));
        }
    }
    Ok(records)
}

fn encode_records(records: &HashMap<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>> {
    let mut keys: Vec<&Vec<u8>> = records.keys().collect();
    keys.sort();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(records.len() * 2);
    for k in keys {
        parts.push(k);
        parts.push(&records[k]);
    }
    lp(&parts)
}

/// Opens a store from saved records (`len` 0 for a new device).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_group_open(
    records: *const u8,
    len: usize,
    out: *mut *mut FpGroups,
) -> i32 {
    if out.is_null() {
        return FP_BAD_ARG;
    }
    unsafe { *out = std::ptr::null_mut() };
    call(|| {
        let records = decode_records(unsafe { slice(records, len)? })?;
        let handle = Box::new(FpGroups {
            store: GroupStore::open(records),
        });
        unsafe { *out = Box::into_raw(handle) };
        Ok(())
    })
}

/// Suitable for a Dart NativeFinalizer. A null pointer is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_group_destroy(handle: *mut FpGroups) {
    if !handle.is_null() {
        let _ = std::panic::catch_unwind(|| drop(unsafe { Box::from_raw(handle) }));
    }
}

unsafe fn store<'a>(handle: *mut FpGroups) -> Result<&'a mut GroupStore> {
    if handle.is_null() {
        return Err(Error::BadArg);
    }
    Ok(unsafe { &mut (*handle).store })
}

/// Every record, for a complete save.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_group_records(handle: *mut FpGroups, out: *mut FpBuf) -> i32 {
    clear_buf(out);
    call(|| {
        let store = unsafe { store(handle)? };
        write_buf(out, encode_records(&store.records())?)
    })
}

/// Runs one JSON request and returns its JSON result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_group_call(
    handle: *mut FpGroups,
    request: *const u8,
    len: usize,
    out: *mut FpBuf,
) -> i32 {
    clear_buf(out);
    call(|| {
        if out.is_null() {
            return Err(Error::BadArg);
        }
        if len > MAX_INPUT {
            return Err(Error::Invalid("request too large"));
        }
        let store = unsafe { store(handle)? };
        let result = store.call(unsafe { text(request, len)? })?;
        write_buf(out, result.into_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_through_the_blob() {
        let mut records = HashMap::new();
        records.insert(b"k1".to_vec(), b"v1".to_vec());
        records.insert(b"k2".to_vec(), vec![]);
        let blob = encode_records(&records).unwrap();
        assert_eq!(decode_records(&blob).unwrap(), records);
        assert!(decode_records(&lp(&[b"only-a-key"]).unwrap()).is_err());
        assert!(decode_records(&lp(&[b"k", b"a", b"k", b"b"]).unwrap()).is_err());
    }

    #[test]
    fn calls_refuse_null_arguments_and_unknown_operations() {
        let mut handle = std::ptr::null_mut();
        assert_eq!(
            unsafe { fp_group_open(std::ptr::null(), 0, &mut handle) },
            0
        );
        let mut out = FpBuf {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let request = br#"{"op":"nope"}"#;
        assert_eq!(
            unsafe { fp_group_call(handle, request.as_ptr(), request.len(), &mut out) },
            1
        );
        assert!(out.ptr.is_null());
        let request = br#"{"op":"groups"}"#;
        assert_eq!(
            unsafe { fp_group_call(handle, request.as_ptr(), request.len(), &mut out) },
            0
        );
        unsafe { super::super::fp_free(out.ptr, out.len) };
        assert_eq!(
            unsafe {
                fp_group_call(
                    std::ptr::null_mut(),
                    request.as_ptr(),
                    request.len(),
                    &mut out,
                )
            },
            6
        );
        unsafe { fp_group_destroy(handle) };
    }
}
