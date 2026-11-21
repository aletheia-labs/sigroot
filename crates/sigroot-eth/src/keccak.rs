use sha3::{Digest, Keccak256};

#[cfg(feature = "address")]
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
	Keccak256::digest(data).into()
}

#[cfg(any(
	feature = "eip191",
	feature = "tx-legacy",
	feature = "tx-eip2930",
	feature = "tx-eip1559",
))]
pub(crate) struct Keccak(Keccak256);

#[cfg(any(
	feature = "eip191",
	feature = "tx-legacy",
	feature = "tx-eip2930",
	feature = "tx-eip1559",
))]
impl Keccak {
	pub(crate) fn new() -> Self {
		Self(Keccak256::new())
	}

	pub(crate) fn update(&mut self, data: &[u8]) {
		self.0.update(data);
	}

	pub(crate) fn finalize(self) -> [u8; 32] {
		self.0.finalize().into()
	}
}

#[cfg(feature = "eip191")]
impl core::fmt::Write for Keccak {
	fn write_str(&mut self, s: &str) -> core::fmt::Result {
		self.update(s.as_bytes());
		Ok(())
	}
}
