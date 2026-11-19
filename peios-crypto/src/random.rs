//! Cryptographically secure random bytes.

use crate::{Error, Result};

/// Fills `buffer` with random bytes from the system's secure generator.
pub fn fill(buffer: &mut [u8]) -> Result<()> {
    aws_lc_rs::rand::fill(buffer).map_err(|_| Error::Backend)
}
