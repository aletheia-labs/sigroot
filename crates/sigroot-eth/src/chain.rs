use crate::Error;

/// EIP-155 chain identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId(u64);

impl ChainId {
	/// Largest supported chain ID, as proposed by EIP-2294.
	pub const MAX: u64 = 9_223_372_036_854_775_771;

	/// Validates a chain ID.
	///
	/// # Errors
	///
	/// Returns [`Error::Unsupported`] for zero or values above [`ChainId::MAX`].
	pub const fn new(id: u64) -> Result<Self, Error> {
		if id == 0 || id > Self::MAX { Err(Error::Unsupported) } else { Ok(Self(id)) }
	}

	/// Numeric value.
	pub const fn get(self) -> u64 {
		self.0
	}
}
