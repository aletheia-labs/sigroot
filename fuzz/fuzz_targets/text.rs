#![no_main]

use libfuzzer_sys::fuzz_target;
use sigroot_eth::Address;
use sigroot_hd::{DerivationPath, HARDENED, Mnemonic};

fuzz_target!(|data: &[u8]| {
	let Ok(text) = core::str::from_utf8(data) else { return };

	if let Ok(address) = Address::parse(text) {
		assert_eq!(address.to_string(), text);
	}

	if let Ok(path) = DerivationPath::parse(text) {
		let mut formatted = String::from("m");
		for &index in path.as_slice() {
			if index >= HARDENED {
				formatted.push_str(&format!("/{}'", index - HARDENED));
			} else {
				formatted.push_str(&format!("/{index}"));
			}
		}
		assert_eq!(formatted, text);
	}

	if let Ok(mnemonic) = Mnemonic::parse(text) {
		let words: Vec<&str> = mnemonic.words().collect();
		assert_eq!(words, text.split_ascii_whitespace().collect::<Vec<_>>());
	}
});
