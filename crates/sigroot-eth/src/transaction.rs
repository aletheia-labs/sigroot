use crate::{Address, ChainId, U256};

/// Fields shared by supported transaction types, as checked by policy.
pub trait Transaction {
	/// Chain the transaction is valid on.
	fn chain_id(&self) -> ChainId;
	/// Recipient, or `None` for contract creation.
	fn to(&self) -> Option<Address>;
	/// Transferred value in wei.
	fn value(&self) -> U256;
	/// Call data.
	fn input(&self) -> &[u8];
	/// Gas limit.
	fn gas_limit(&self) -> u64;
	/// Highest price per gas the sender may pay.
	fn max_fee_per_gas(&self) -> u128;

	/// Highest total fee in wei, or `None` on overflow.
	fn max_fee(&self) -> Option<u128> {
		self.max_fee_per_gas().checked_mul(u128::from(self.gas_limit()))
	}
}

with_tx! {
	use crate::Error;

	/// Maximum encoded transaction size accepted by decoders.
	pub const MAX_TX_LEN: usize = 131_072;

	pub(crate) const fn check_len(bytes: &[u8]) -> Result<(), Error> {
		if bytes.len() > MAX_TX_LEN { Err(Error::LimitExceeded) } else { Ok(()) }
	}
}

with_access_list! {
	use crate::Signature;
	use crate::rlp::{self, Reader, Sink};

	pub(crate) fn typed_list(bytes: &[u8], ty: u8) -> Result<Reader<'_>, Error> {
		let (&first, rest) = bytes.split_first().ok_or(Error::InvalidEncoding)?;
		if first != ty {
			return Err(Error::Unsupported);
		}
		rlp::single_list(rest)
	}

	pub(crate) fn write_signature(s: &mut dyn Sink, signature: &Signature) -> Result<(), Error> {
		rlp::u64(s, u64::from(signature.y_parity()))?;
		rlp::uint(s, signature.r())?;
		rlp::uint(s, signature.s())
	}

	pub(crate) fn read_signature(list: &mut Reader<'_>) -> Result<Signature, Error> {
		let y_parity = match list.u64()? {
			0 => false,
			1 => true,
			_ => return Err(Error::InvalidSignature),
		};
		let r = list.uint()?;
		let s = list.uint()?;
		Signature::new(r, s, y_parity)
	}
}
