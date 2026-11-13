//! Random bytes.
//!
//! The default source is the operating system (`getrandom`). Tests can pass a
//! finite stream instead. A short stream fails the call and does not consume a
//! partial chunk, so a scripted transcript either matches byte for byte or
//! errors. Nothing here is used unless the caller asks for it.

use crate::error::{Error, Result};
use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

#[derive(Clone)]
enum Source {
    Os,
    Stream { data: Vec<u8>, pos: usize },
}

/// A random-byte source. `Debug` does not print the stream.
pub struct Rng {
    source: Source,
    failed: bool,
}

impl core::fmt::Debug for Rng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.source {
            Source::Os => f.write_str("Rng::Os"),
            Source::Stream { data, pos } => {
                write!(f, "Rng::Stream(pos={pos}, len={})", data.len())
            }
        }
    }
}

impl Rng {
    /// Operating-system randomness.
    pub fn os() -> Self {
        Self {
            source: Source::Os,
            failed: false,
        }
    }

    /// A fixed transcript. Draws walk the slice from the start.
    pub fn stream(data: impl Into<Vec<u8>>) -> Self {
        Self {
            source: Source::Stream {
                data: data.into(),
                pos: 0,
            },
            failed: false,
        }
    }

    /// Bytes still available in a stream. `None` for the operating system.
    pub fn remaining(&self) -> Option<usize> {
        match &self.source {
            Source::Os => None,
            Source::Stream { data, pos } => Some(data.len().saturating_sub(*pos)),
        }
    }

    /// True after a draw that could not be satisfied.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Fill `dst` completely, or leave it untouched and return [`Error::Rng`].
    pub fn fill(&mut self, dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        match &mut self.source {
            Source::Os => match getrandom::fill(dst) {
                Ok(()) => Ok(()),
                Err(_) => {
                    dst.zeroize();
                    self.failed = true;
                    Err(Error::Rng)
                }
            },
            Source::Stream { data, pos } => {
                let Some(end) = pos.checked_add(dst.len()) else {
                    self.failed = true;
                    return Err(Error::Rng);
                };
                if end > data.len() {
                    self.failed = true;
                    return Err(Error::Rng);
                }
                dst.copy_from_slice(&data[*pos..end]);
                *pos = end;
                Ok(())
            }
        }
    }

    /// `n` fresh bytes.
    pub fn bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; n];
        self.fill(&mut out)?;
        Ok(out)
    }

    /// A fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        self.fill(&mut out)?;
        Ok(out)
    }
}

impl TryRng for Rng {
    type Error = Error;

    fn try_next_u32(&mut self) -> Result<u32> {
        let b = self.array::<4>()?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64> {
        let b = self.array::<8>()?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        self.fill(dst)
    }
}

impl TryCryptoRng for Rng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_does_not_consume_a_short_draw() {
        let mut rng = Rng::stream(vec![1, 2, 3, 4]);
        assert!(rng.array::<8>().is_err());
        assert_eq!(rng.remaining(), Some(4));
        assert_eq!(rng.array::<4>().unwrap(), [1, 2, 3, 4]);
        assert_eq!(rng.remaining(), Some(0));
    }
}
