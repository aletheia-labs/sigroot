#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::keccak::Keccak;
use crate::{Address, Error, U256};

pub(crate) trait Sink {
	fn put(&mut self, bytes: &[u8]) -> Result<(), Error>;
}

#[derive(Default)]
pub(crate) struct Counter(usize);

impl Counter {
	pub(crate) const fn len(&self) -> usize {
		self.0
	}
}

impl Sink for Counter {
	fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
		self.0 = self.0.checked_add(bytes.len()).ok_or(Error::LimitExceeded)?;
		Ok(())
	}
}

pub(crate) struct SliceSink<'a> {
	buf: &'a mut [u8],
	len: usize,
}

impl<'a> SliceSink<'a> {
	pub(crate) const fn new(buf: &'a mut [u8]) -> Self {
		Self { buf, len: 0 }
	}

	pub(crate) const fn len(&self) -> usize {
		self.len
	}

	#[cfg(any(feature = "tx-eip2930", feature = "tx-eip1559"))]
	pub(crate) fn into_written(self) -> &'a [u8] {
		let buf: &'a [u8] = self.buf;
		buf.get(..self.len).unwrap_or(&[])
	}
}

impl Sink for SliceSink<'_> {
	fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
		let end = self.len.checked_add(bytes.len()).ok_or(Error::BufferTooSmall)?;
		self.buf.get_mut(self.len..end).ok_or(Error::BufferTooSmall)?.copy_from_slice(bytes);
		self.len = end;
		Ok(())
	}
}

impl Sink for Keccak {
	fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
		self.update(bytes);
		Ok(())
	}
}

#[cfg(feature = "alloc")]
impl Sink for Vec<u8> {
	fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
		self.extend_from_slice(bytes);
		Ok(())
	}
}

fn strip(be: &[u8]) -> &[u8] {
	let zeros = be.iter().take_while(|&&b| b == 0).count();
	be.get(zeros..).unwrap_or(&[])
}

fn header(s: &mut dyn Sink, offset: u8, len: usize) -> Result<(), Error> {
	match u8::try_from(len) {
		Ok(short) if short < 56 => s.put(&[offset.checked_add(short).ok_or(Error::LimitExceeded)?]),
		_ => {
			let be = u64::try_from(len).map_err(|_| Error::LimitExceeded)?.to_be_bytes();
			let len_bytes = strip(&be);
			let tag = u8::try_from(len_bytes.len())
				.ok()
				.and_then(|n| offset.checked_add(55)?.checked_add(n))
				.ok_or(Error::LimitExceeded)?;
			s.put(&[tag])?;
			s.put(len_bytes)
		},
	}
}

pub(crate) fn bytes(s: &mut dyn Sink, bytes: &[u8]) -> Result<(), Error> {
	match bytes {
		[single] if *single < 0x80 => s.put(bytes),
		_ => {
			header(s, 0x80, bytes.len())?;
			s.put(bytes)
		},
	}
}

pub(crate) fn uint(s: &mut dyn Sink, be: &[u8]) -> Result<(), Error> {
	bytes(s, strip(be))
}

pub(crate) fn u64(s: &mut dyn Sink, value: u64) -> Result<(), Error> {
	uint(s, &value.to_be_bytes())
}

pub(crate) fn u128(s: &mut dyn Sink, value: u128) -> Result<(), Error> {
	uint(s, &value.to_be_bytes())
}

pub(crate) fn u256(s: &mut dyn Sink, value: &U256) -> Result<(), Error> {
	uint(s, value.as_be_bytes())
}

pub(crate) fn address(s: &mut dyn Sink, address: &Address) -> Result<(), Error> {
	bytes(s, address.as_bytes())
}

pub(crate) fn to(s: &mut dyn Sink, to: Option<&Address>) -> Result<(), Error> {
	match to {
		Some(address) => self::address(s, address),
		None => bytes(s, &[]),
	}
}

pub(crate) fn list(
	s: &mut dyn Sink,
	items: &dyn Fn(&mut dyn Sink) -> Result<(), Error>,
) -> Result<(), Error> {
	let mut counter = Counter::default();
	items(&mut counter)?;
	header(s, 0xc0, counter.len())?;
	items(s)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
	pub(crate) const fn new(bytes: &'a [u8]) -> Self {
		Self(bytes)
	}

	#[cfg(any(feature = "tx-eip2930", feature = "tx-eip1559"))]
	pub(crate) const fn remaining(&self) -> &'a [u8] {
		self.0
	}

	#[cfg(any(feature = "tx-eip2930", feature = "tx-eip1559"))]
	pub(crate) const fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	pub(crate) const fn finish(self) -> Result<(), Error> {
		if self.0.is_empty() { Ok(()) } else { Err(Error::InvalidEncoding) }
	}

	fn item(&mut self) -> Result<(bool, &'a [u8]), Error> {
		let (&prefix, rest) = self.0.split_first().ok_or(Error::InvalidEncoding)?;
		let (is_list, len, rest) = match prefix {
			0x00..=0x7f => {
				let (single, rest) = self.0.split_at_checked(1).ok_or(Error::InvalidEncoding)?;
				self.0 = rest;
				return Ok((false, single));
			},
			0x80..=0xb7 => (false, usize::from(prefix.wrapping_sub(0x80)), rest),
			0xb8..=0xbf => {
				let (len, rest) = long_len(rest, prefix.wrapping_sub(0xb7))?;
				(false, len, rest)
			},
			0xc0..=0xf7 => (true, usize::from(prefix.wrapping_sub(0xc0)), rest),
			0xf8..=0xff => {
				let (len, rest) = long_len(rest, prefix.wrapping_sub(0xf7))?;
				(true, len, rest)
			},
		};
		let (payload, rest) = rest.split_at_checked(len).ok_or(Error::InvalidEncoding)?;
		if !is_list && len == 1 && payload.first().is_some_and(|&b| b < 0x80) {
			return Err(Error::InvalidEncoding);
		}
		self.0 = rest;
		Ok((is_list, payload))
	}

	pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Error> {
		match self.item()? {
			(false, payload) => Ok(payload),
			(true, _) => Err(Error::InvalidEncoding),
		}
	}

	pub(crate) fn list(&mut self) -> Result<Self, Error> {
		match self.item()? {
			(true, payload) => Ok(Self(payload)),
			(false, _) => Err(Error::InvalidEncoding),
		}
	}

	pub(crate) fn uint<const N: usize>(&mut self) -> Result<[u8; N], Error> {
		let be = self.bytes()?;
		if be.len() > N || be.first() == Some(&0) {
			return Err(Error::InvalidEncoding);
		}
		let mut out = [0; N];
		for (out, byte) in out.iter_mut().rev().zip(be.iter().rev()) {
			*out = *byte;
		}
		Ok(out)
	}

	pub(crate) fn u64(&mut self) -> Result<u64, Error> {
		self.uint().map(u64::from_be_bytes)
	}

	pub(crate) fn u128(&mut self) -> Result<u128, Error> {
		self.uint().map(u128::from_be_bytes)
	}

	pub(crate) fn u256(&mut self) -> Result<U256, Error> {
		self.uint().map(U256::from_be_bytes)
	}

	#[cfg(any(feature = "tx-eip2930", feature = "tx-eip1559"))]
	pub(crate) fn address(&mut self) -> Result<Address, Error> {
		let bytes = self.bytes()?.try_into().map_err(|_| Error::InvalidEncoding)?;
		Ok(Address::from_bytes(bytes))
	}

	pub(crate) fn to(&mut self) -> Result<Option<Address>, Error> {
		let bytes = self.bytes()?;
		if bytes.is_empty() {
			return Ok(None);
		}
		let bytes = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
		Ok(Some(Address::from_bytes(bytes)))
	}
}

fn long_len(rest: &[u8], len_bytes: u8) -> Result<(usize, &[u8]), Error> {
	let (be, rest) = rest.split_at_checked(usize::from(len_bytes)).ok_or(Error::InvalidEncoding)?;
	if be.len() > 8 || be.first() == Some(&0) {
		return Err(Error::InvalidEncoding);
	}
	let mut buf = [0; 8];
	for (out, byte) in buf.iter_mut().rev().zip(be.iter().rev()) {
		*out = *byte;
	}
	let len = usize::try_from(u64::from_be_bytes(buf)).map_err(|_| Error::InvalidEncoding)?;
	if len < 56 {
		return Err(Error::InvalidEncoding);
	}
	Ok((len, rest))
}

pub(crate) fn single_list(bytes: &[u8]) -> Result<Reader<'_>, Error> {
	let mut outer = Reader::new(bytes);
	let list = outer.list()?;
	outer.finish()?;
	Ok(list)
}
