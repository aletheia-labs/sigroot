#![no_main]

use libfuzzer_sys::fuzz_target;
use sigroot_eth::Erc20Call;

fuzz_target!(|data: &[u8]| {
	let Ok(call) = Erc20Call::decode(data) else { return };
	assert_eq!(call.encoded_len(), data.len());

	let mut buf = vec![0; data.len()];
	assert_eq!(call.encode(&mut buf).ok(), Some(data.len()));
	assert_eq!(buf, data);
});
