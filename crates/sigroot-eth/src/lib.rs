//! Ethereum addresses, keys, transactions, and offline signing for sigroot.

#![no_std]

#[cfg(all(
	feature = "alloc",
	any(feature = "tx-legacy", feature = "tx-eip2930", feature = "tx-eip1559"),
))]
extern crate alloc;

macro_rules! with_payload {
	($($item:item)*) => {$(
		#[cfg(any(
			feature = "eip191",
			feature = "tx-legacy",
			feature = "tx-eip2930",
			feature = "tx-eip1559",
			feature = "unchecked-prehash",
		))]
		$item
	)*};
}

macro_rules! with_tx {
	($($item:item)*) => {$(
		#[cfg(any(feature = "tx-legacy", feature = "tx-eip2930", feature = "tx-eip1559"))]
		$item
	)*};
}

macro_rules! with_access_list {
	($($item:item)*) => {$(
		#[cfg(any(feature = "tx-eip2930", feature = "tx-eip1559"))]
		$item
	)*};
}

#[cfg(any(feature = "tx-legacy", feature = "tx-eip2930", feature = "tx-eip1559"))]
macro_rules! impl_tx {
	($ty:ident) => {
		impl<'a> $ty<'a> {
			/// Hash signed for this transaction.
			///
			/// # Errors
			///
			/// Returns an error if the transaction cannot be encoded.
			pub fn signing_hash(&self) -> Result<[u8; 32], crate::Error> {
				let mut hasher = crate::keccak::Keccak::new();
				self.write_unsigned(&mut hasher)?;
				Ok(hasher.finalize())
			}

			/// Length of the unsigned encoding.
			///
			/// # Errors
			///
			/// Returns an error if the transaction cannot be encoded.
			pub fn unsigned_len(&self) -> Result<usize, crate::Error> {
				let mut counter = crate::rlp::Counter::default();
				self.write_unsigned(&mut counter)?;
				Ok(counter.len())
			}

			/// Writes the unsigned encoding into `buf` and returns its length.
			///
			/// # Errors
			///
			/// Returns [`crate::Error::BufferTooSmall`] if `buf` is too short.
			pub fn encode_unsigned(&self, buf: &mut [u8]) -> Result<usize, crate::Error> {
				let mut sink = crate::rlp::SliceSink::new(buf);
				self.write_unsigned(&mut sink)?;
				Ok(sink.len())
			}

			/// Decodes a canonical unsigned encoding.
			///
			/// # Errors
			///
			/// Returns [`crate::Error::LimitExceeded`] above [`crate::MAX_TX_LEN`],
			/// [`crate::Error::Unsupported`] for another transaction type, and
			/// [`crate::Error::InvalidEncoding`] for malformed or non-canonical input.
			pub fn decode_unsigned(bytes: &'a [u8]) -> Result<Self, crate::Error> {
				crate::transaction::check_len(bytes)?;
				Self::read_unsigned(bytes)
			}

			/// Length of the signed encoding.
			///
			/// # Errors
			///
			/// Returns an error if the transaction cannot be encoded.
			pub fn signed_len(&self, signature: &crate::Signature) -> Result<usize, crate::Error> {
				let mut counter = crate::rlp::Counter::default();
				self.write_signed(signature, &mut counter)?;
				Ok(counter.len())
			}

			/// Writes the signed encoding into `buf` and returns its length.
			///
			/// # Errors
			///
			/// Returns [`crate::Error::BufferTooSmall`] if `buf` is too short.
			pub fn encode_signed(
				&self,
				signature: &crate::Signature,
				buf: &mut [u8],
			) -> Result<usize, crate::Error> {
				let mut sink = crate::rlp::SliceSink::new(buf);
				self.write_signed(signature, &mut sink)?;
				Ok(sink.len())
			}

			/// Decodes a canonical signed encoding.
			///
			/// # Errors
			///
			/// As [`Self::decode_unsigned`], plus [`crate::Error::InvalidSignature`] for an
			/// invalid signature.
			pub fn decode_signed(
				bytes: &'a [u8],
			) -> Result<(Self, crate::Signature), crate::Error> {
				crate::transaction::check_len(bytes)?;
				Self::read_signed(bytes)
			}

			/// Unsigned encoding.
			///
			/// # Errors
			///
			/// Returns an error if the transaction cannot be encoded.
			#[cfg(feature = "alloc")]
			pub fn unsigned_to_vec(&self) -> Result<alloc::vec::Vec<u8>, crate::Error> {
				let mut out = alloc::vec::Vec::new();
				self.write_unsigned(&mut out)?;
				Ok(out)
			}

			/// Signed encoding.
			///
			/// # Errors
			///
			/// Returns an error if the transaction cannot be encoded.
			#[cfg(feature = "alloc")]
			pub fn signed_to_vec(
				&self,
				signature: &crate::Signature,
			) -> Result<alloc::vec::Vec<u8>, crate::Error> {
				let mut out = alloc::vec::Vec::new();
				self.write_signed(signature, &mut out)?;
				Ok(out)
			}
		}
	};
}

mod chain;
mod signature;
mod uint;

#[cfg(feature = "address")]
mod address;
#[cfg(feature = "tx-eip1559")]
mod eip1559;
#[cfg(feature = "eip191")]
mod eip191;
#[cfg(feature = "tx-eip2930")]
mod eip2930;
#[cfg(feature = "erc20")]
mod erc20;
#[cfg(feature = "hd")]
pub mod hd;
#[cfg(any(feature = "address", feature = "eip191"))]
mod keccak;
#[cfg(feature = "keys")]
mod keys;
#[cfg(feature = "tx-legacy")]
mod legacy;
#[cfg(feature = "policy")]
mod policy;
#[cfg(feature = "pubkey")]
mod pubkey;
#[cfg(feature = "address")]
mod transaction;

with_access_list! {
	mod access_list;
	pub use access_list::{AccessList, AccessListItem, AccessListIter, StorageKeys};
}

with_tx! {
	mod rlp;
	pub use transaction::MAX_TX_LEN;
}

#[cfg(feature = "address")]
pub use address::Address;
pub use chain::ChainId;
#[cfg(feature = "eip191")]
pub use eip191::PersonalMessage;
#[cfg(feature = "tx-eip1559")]
pub use eip1559::Eip1559Tx;
#[cfg(feature = "tx-eip2930")]
pub use eip2930::Eip2930Tx;
#[cfg(feature = "erc20")]
pub use erc20::Erc20Call;
#[cfg(feature = "keys")]
pub use keys::SigningKey;
#[cfg(feature = "tx-legacy")]
pub use legacy::LegacyTx;
#[cfg(feature = "policy")]
pub use policy::{Calls, Policy, Violation};
#[cfg(feature = "pubkey")]
pub use pubkey::PublicKey;
pub use signature::Signature;
#[cfg(feature = "unchecked-prehash")]
pub use signature::UncheckedPrehash;
#[cfg(feature = "std")]
pub use sigroot_core::OsEntropy;
pub use sigroot_core::{Entropy, Error, Secret};
#[cfg(feature = "address")]
pub use transaction::Transaction;
pub use uint::U256;

with_payload! {
	pub use signature::{Payload, Signer};
}
