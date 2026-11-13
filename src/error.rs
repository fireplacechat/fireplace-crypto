//! Failures that can cross the library boundary. Messages are static and never
//! include key material.

use core::fmt;

/// A protocol, parsing, or randomness failure.
///
/// `Invalid` is a malformed input (what Dart raises as `FormatException`).
/// `Crypto` is a protocol refusal (what Dart raises as `SessionException`,
/// `LinkException`, or `BackupException`). `RateLimited` is the one refusal a
/// caller should retry later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid(&'static str),
    Crypto(&'static str),
    RateLimited,
    Rng,
    BadArg,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(msg) => write!(f, "invalid: {msg}"),
            Error::Crypto(msg) => write!(f, "crypto: {msg}"),
            Error::RateLimited => f.write_str("rate limited"),
            Error::Rng => f.write_str("rng"),
            Error::BadArg => f.write_str("bad argument"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
