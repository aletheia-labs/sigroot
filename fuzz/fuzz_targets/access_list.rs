#![no_main]

use libfuzzer_sys::fuzz_target;
use sigroot_eth::{AccessList, AccessListItem};

fuzz_target!(|data: &[u8]| {
	let Ok(list) = AccessList::from_rlp(data) else { return };
	assert_eq!(list.as_rlp(), data);

	let items: Vec<AccessListItem<'_>> = list.iter().collect();
	let mut buf = vec![0; data.len()];
	let encoded = AccessList::encode(&items, &mut buf).map(|list| list.as_rlp().to_vec());
	assert_eq!(encoded.ok().as_deref(), Some(data));
});
