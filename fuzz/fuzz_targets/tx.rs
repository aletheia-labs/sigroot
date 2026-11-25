#![no_main]

use libfuzzer_sys::fuzz_target;
use sigroot_eth::{Eip1559Tx, Eip2930Tx, LegacyTx};

fuzz_target!(|data: &[u8]| {
	let mut buf = vec![0; data.len()];

	if let Ok(tx) = LegacyTx::decode_unsigned(data) {
		assert_eq!(tx.unsigned_len().ok(), Some(data.len()));
		assert_eq!(tx.encode_unsigned(&mut buf).ok(), Some(data.len()));
		assert_eq!(buf, data);
		let _ = tx.signing_hash();
	}
	if let Ok((tx, signature)) = LegacyTx::decode_signed(data) {
		assert_eq!(tx.signed_len(&signature).ok(), Some(data.len()));
		assert_eq!(tx.encode_signed(&signature, &mut buf).ok(), Some(data.len()));
		assert_eq!(buf, data);
	}

	if let Ok(tx) = Eip2930Tx::decode_unsigned(data) {
		assert_eq!(tx.unsigned_len().ok(), Some(data.len()));
		assert_eq!(tx.encode_unsigned(&mut buf).ok(), Some(data.len()));
		assert_eq!(buf, data);
		let _ = tx.signing_hash();
	}
	if let Ok((tx, signature)) = Eip2930Tx::decode_signed(data) {
		assert_eq!(tx.signed_len(&signature).ok(), Some(data.len()));
		assert_eq!(tx.encode_signed(&signature, &mut buf).ok(), Some(data.len()));
		assert_eq!(buf, data);
	}

	if let Ok(tx) = Eip1559Tx::decode_unsigned(data) {
		assert_eq!(tx.unsigned_len().ok(), Some(data.len()));
		assert_eq!(tx.encode_unsigned(&mut buf).ok(), Some(data.len()));
		assert_eq!(buf, data);
		let _ = tx.signing_hash();
	}
	if let Ok((tx, signature)) = Eip1559Tx::decode_signed(data) {
		assert_eq!(tx.signed_len(&signature).ok(), Some(data.len()));
		assert_eq!(tx.encode_signed(&signature, &mut buf).ok(), Some(data.len()));
		assert_eq!(buf, data);
	}
});
