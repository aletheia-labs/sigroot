use crate::rlp::{self, Reader, SliceSink, Sink};
use crate::{Address, Error};

/// EIP-2930 access list, held as its validated RLP encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessList<'a>(&'a [u8]);

/// Access list entry.
#[derive(Clone, Copy, Debug)]
pub struct AccessListItem<'a> {
	/// Accessed account.
	pub address: Address,
	/// Accessed storage slots.
	pub storage_keys: StorageKeys<'a>,
}

/// Storage slots of an [`AccessListItem`].
#[derive(Clone, Copy, Debug)]
pub struct StorageKeys<'a>(Keys<'a>);

#[derive(Clone, Copy, Debug)]
enum Keys<'a> {
	Slice(&'a [[u8; 32]]),
	Rlp(Reader<'a>),
}

/// Iterator over [`AccessList`] entries.
#[derive(Clone, Copy, Debug)]
pub struct AccessListIter<'a>(Reader<'a>);

impl<'a> AccessList<'a> {
	/// Empty access list.
	pub const EMPTY: Self = Self(&[0xc0]);

	/// Validates a canonical RLP-encoded access list.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidEncoding`] for malformed or non-canonical input.
	pub fn from_rlp(bytes: &'a [u8]) -> Result<Self, Error> {
		let mut reader = Reader::new(bytes);
		let list = Self::read(&mut reader)?;
		reader.finish()?;
		Ok(list)
	}

	/// Encodes `items` into `buf`.
	///
	/// # Errors
	///
	/// Returns [`Error::BufferTooSmall`] if `buf` is too short.
	pub fn encode(items: &[AccessListItem<'_>], buf: &'a mut [u8]) -> Result<Self, Error> {
		let mut sink = SliceSink::new(buf);
		rlp::list(&mut sink, &|s| {
			for item in items {
				rlp::list(s, &|s| {
					rlp::address(s, &item.address)?;
					rlp::list(s, &|s| {
						for key in item.storage_keys {
							rlp::bytes(s, &key)?;
						}
						Ok(())
					})
				})?;
			}
			Ok(())
		})?;
		Ok(Self(sink.into_written()))
	}

	/// RLP encoding.
	pub const fn as_rlp(&self) -> &'a [u8] {
		self.0
	}

	/// Whether the list has no entries.
	pub fn is_empty(&self) -> bool {
		self.0 == [0xc0]
	}

	/// Entries.
	pub fn iter(&self) -> AccessListIter<'a> {
		AccessListIter(rlp::single_list(self.0).unwrap_or(Reader::new(&[])))
	}

	pub(crate) fn read(reader: &mut Reader<'a>) -> Result<Self, Error> {
		let start = reader.remaining();
		let mut items = reader.list()?;
		while !items.is_empty() {
			let mut item = items.list()?;
			item.address()?;
			let mut keys = item.list()?;
			while !keys.is_empty() {
				if keys.bytes()?.len() != 32 {
					return Err(Error::InvalidEncoding);
				}
			}
			item.finish()?;
		}
		let len = start.len().checked_sub(reader.remaining().len()).ok_or(Error::InvalidEncoding)?;
		start.get(..len).map(Self).ok_or(Error::InvalidEncoding)
	}

	pub(crate) fn write(&self, s: &mut dyn Sink) -> Result<(), Error> {
		s.put(self.0)
	}
}

impl<'a> IntoIterator for AccessList<'a> {
	type Item = AccessListItem<'a>;
	type IntoIter = AccessListIter<'a>;

	fn into_iter(self) -> Self::IntoIter {
		self.iter()
	}
}

impl<'a> StorageKeys<'a> {
	/// Wraps storage slots for [`AccessList::encode`].
	pub const fn new(keys: &'a [[u8; 32]]) -> Self {
		Self(Keys::Slice(keys))
	}
}

impl Iterator for StorageKeys<'_> {
	type Item = [u8; 32];

	fn next(&mut self) -> Option<[u8; 32]> {
		match &mut self.0 {
			Keys::Slice(keys) => {
				let (first, rest) = keys.split_first()?;
				*keys = rest;
				Some(*first)
			},
			Keys::Rlp(reader) => reader.bytes().ok()?.try_into().ok(),
		}
	}
}

impl<'a> Iterator for AccessListIter<'a> {
	type Item = AccessListItem<'a>;

	fn next(&mut self) -> Option<AccessListItem<'a>> {
		let mut item = self.0.list().ok()?;
		let address = item.address().ok()?;
		let keys = item.list().ok()?;
		Some(AccessListItem { address, storage_keys: StorageKeys(Keys::Rlp(keys)) })
	}
}
