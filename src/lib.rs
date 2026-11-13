//! Fireplace end-to-end encryption.
//!
//! Byte-compatible with the Dart implementation in the Fireplace app. The
//! post-quantum crates this builds on say they have not been independently
//! audited. This crate does not claim an audit either.

#![deny(unsafe_code)]

mod aead;
mod codec;
mod device;
mod error;
pub mod ffi;
mod fingerprint;
mod identity;
mod kdf;
mod link;
mod prekeys;
mod prim;
mod recovery;
mod rng;
mod session;

#[cfg(test)]
mod dart_vectors;

pub use device::{DeviceBundle, DeviceKeys};
pub use error::{Error, Result};
pub use fingerprint::{identity_fingerprint, safety_number};
pub use identity::AccountIdentity;
pub use link::{
    SealedIdentity, confirmation_code, open as link_open, request_fingerprint, seal as link_seal,
};
pub use prekeys::{
    PreKeyBundle, PreKeyKind, PreKeyRecord, PublishedPreKey, one_time, sign as sign_prekey,
    verify_signed,
};
pub use recovery::{RecoveryKey, decrypt as recovery_decrypt, encrypt as recovery_encrypt};
pub use rng::Rng;
pub use session::{Envelope, HandshakeInit, PROTOCOL_VERSION, Session, system_now_ms};
