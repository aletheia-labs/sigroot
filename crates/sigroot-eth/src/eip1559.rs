use crate::rlp::{self, Reader, Sink};
use crate::transaction::{read_signature, typed_list, write_signature};
use crate::{AccessList, Address, ChainId, Error, Signature, Transaction, U256};

const TYPE: u8 = 0x02;

/// EIP-1559 transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eip1559Tx<'a> {
	/// Chain the transaction is valid on.
	pub chain_id: ChainId,
	/// Sender nonce.
	pub nonce: u64,
	/// Priority fee per gas in wei.
	pub max_priority_fee_per_gas: u128,
	/// Maximum total fee per gas in wei.
	pub max_fee_per_gas: u128,
	/// Gas limit.
	pub gas_limit: u64,
	/// Recipient, or `None` for contract creation.
	pub to: Option<Address>,
	/// Transferred value in wei.
	pub value: U256,
	/// Call data.
	pub input: &'a [u8],
	/// Pre-declared accounts and storage slots.
	pub access_list: AccessList<'a>,
}

impl_tx!(Eip1559Tx);

impl<'a> Eip1559Tx<'a> {
	fn write_fields(&self, s: &mut dyn Sink) -> Result<(), Error> {
		rlp::u64(s, self.chain_id.get())?;
		rlp::u64(s, self.nonce)?;
		rlp::u128(s, self.max_priority_fee_per_gas)?;
		rlp::u128(s, self.max_fee_per_gas)?;
		rlp::u64(s, self.gas_limit)?;
		rlp::to(s, self.to.as_ref())?;
		rlp::u256(s, &self.value)?;
		rlp::bytes(s, self.input)?;
		self.access_list.write(s)
	}

	fn write_unsigned(&self, s: &mut dyn Sink) -> Result<(), Error> {
		s.put(&[TYPE])?;
		rlp::list(s, &|s| self.write_fields(s))
	}

	fn write_signed(&self, signature: &Signature, s: &mut dyn Sink) -> Result<(), Error> {
		s.put(&[TYPE])?;
		rlp::list(s, &|s| {
			self.write_fields(s)?;
			write_signature(s, signature)
		})
	}

	fn read_fields(list: &mut Reader<'a>) -> Result<Self, Error> {
		Ok(Self {
			chain_id: ChainId::new(list.u64()?)?,
			nonce: list.u64()?,
			max_priority_fee_per_gas: list.u128()?,
			max_fee_per_gas: list.u128()?,
			gas_limit: list.u64()?,
			to: list.to()?,
			value: list.u256()?,
			input: list.bytes()?,
			access_list: AccessList::read(list)?,
		})
	}

	fn read_unsigned(bytes: &'a [u8]) -> Result<Self, Error> {
		let mut list = typed_list(bytes, TYPE)?;
		let tx = Self::read_fields(&mut list)?;
		list.finish()?;
		Ok(tx)
	}

	fn read_signed(bytes: &'a [u8]) -> Result<(Self, Signature), Error> {
		let mut list = typed_list(bytes, TYPE)?;
		let tx = Self::read_fields(&mut list)?;
		let signature = read_signature(&mut list)?;
		list.finish()?;
		Ok((tx, signature))
	}
}

impl Transaction for Eip1559Tx<'_> {
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
		self.max_fee_per_gas
	}
}
