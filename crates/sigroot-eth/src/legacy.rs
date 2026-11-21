use crate::rlp::{self, Reader, Sink};
use crate::{Address, ChainId, Error, Signature, Transaction, U256};

/// Legacy transaction with EIP-155 replay protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyTx<'a> {
	/// Chain the transaction is valid on.
	pub chain_id: ChainId,
	/// Sender nonce.
	pub nonce: u64,
	/// Price per gas in wei.
	pub gas_price: u128,
	/// Gas limit.
	pub gas_limit: u64,
	/// Recipient, or `None` for contract creation.
	pub to: Option<Address>,
	/// Transferred value in wei.
	pub value: U256,
	/// Call data.
	pub input: &'a [u8],
}

impl_tx!(LegacyTx);

impl<'a> LegacyTx<'a> {
	fn write_fields(&self, s: &mut dyn Sink) -> Result<(), Error> {
		rlp::u64(s, self.nonce)?;
		rlp::u128(s, self.gas_price)?;
		rlp::u64(s, self.gas_limit)?;
		rlp::to(s, self.to.as_ref())?;
		rlp::u256(s, &self.value)?;
		rlp::bytes(s, self.input)
	}

	fn write_unsigned(&self, s: &mut dyn Sink) -> Result<(), Error> {
		rlp::list(s, &|s| {
			self.write_fields(s)?;
			rlp::u64(s, self.chain_id.get())?;
			rlp::u64(s, 0)?;
			rlp::u64(s, 0)
		})
	}

	fn write_signed(&self, signature: &Signature, s: &mut dyn Sink) -> Result<(), Error> {
		let v = self
			.chain_id
			.get()
			.checked_mul(2)
			.and_then(|v| v.checked_add(35))
			.and_then(|v| v.checked_add(u64::from(signature.y_parity())))
			.ok_or(Error::LimitExceeded)?;
		rlp::list(s, &|s| {
			self.write_fields(s)?;
			rlp::u64(s, v)?;
			rlp::uint(s, signature.r())?;
			rlp::uint(s, signature.s())
		})
	}

	fn read_fields(list: &mut Reader<'a>, chain_id: ChainId) -> Result<Self, Error> {
		Ok(Self {
			chain_id,
			nonce: list.u64()?,
			gas_price: list.u128()?,
			gas_limit: list.u64()?,
			to: list.to()?,
			value: list.u256()?,
			input: list.bytes()?,
		})
	}

	fn read_unsigned(bytes: &'a [u8]) -> Result<Self, Error> {
		let mut list = rlp::single_list(bytes)?;
		let mut tail = list;
		for _ in 0..6 {
			tail.bytes()?;
		}
		let chain_id = ChainId::new(tail.u64()?)?;
		if tail.u64()? != 0 || tail.u64()? != 0 {
			return Err(Error::Unsupported);
		}
		tail.finish()?;
		Self::read_fields(&mut list, chain_id)
	}

	fn read_signed(bytes: &'a [u8]) -> Result<(Self, Signature), Error> {
		let mut list = rlp::single_list(bytes)?;
		let mut tail = list;
		for _ in 0..6 {
			tail.bytes()?;
		}
		let v = tail.u64()?.checked_sub(35).ok_or(Error::Unsupported)?;
		let chain_id = ChainId::new(v >> 1)?;
		let signature = Signature::new(tail.uint()?, tail.uint()?, v & 1 == 1)?;
		tail.finish()?;
		Ok((Self::read_fields(&mut list, chain_id)?, signature))
	}
}

impl Transaction for LegacyTx<'_> {
	fn chain_id(&self) -> ChainId {
		self.chain_id
	}

	fn to(&self) -> Option<Address> {
		self.to
	}

	fn value(&self) -> U256 {
		self.value
	}

	fn input(&self) -> &[u8] {
		self.input
	}

	fn gas_limit(&self) -> u64 {
		self.gas_limit
	}

	fn max_fee_per_gas(&self) -> u128 {
		self.gas_price
	}
}
