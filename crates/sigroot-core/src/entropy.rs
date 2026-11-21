use crate::Error;

/// Source of cryptographically secure random bytes.
pub trait Entropy {
	/// Fills `dest` entirely with random bytes.
	///
	/// # Errors
	///
	/// Returns [`Error::Entropy`] if the source cannot provide randomness. Implementations must
	/// never fall back to a deterministic or weaker source.
	fn fill(&mut self, dest: &mut [u8]) -> Result<(), Error>;
}

/// Entropy from the operating system.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

#[cfg(feature = "std")]
impl Entropy for OsEntropy {
	fn fill(&mut self, dest: &mut [u8]) -> Result<(), Error> {
		getrandom::fill(dest).map_err(|_| Error::Entropy)
	}
}
