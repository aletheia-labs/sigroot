//! Ethereum tests against specification examples, mainnet transactions, and independent
//! implementations.

use core::error::Error as StdError;

use rlp::RlpStream;
use secp256k1::ecdsa::RecoverableSignature;
use sigroot_eth::hd::{self, Mnemonic, PROFILE, WordCount};
use sigroot_eth::{
	AccessList, AccessListItem, Address, Calls, ChainId, Eip1559Tx, Eip2930Tx, Entropy, Erc20Call,
	Error, LegacyTx, MAX_TX_LEN, Payload, PersonalMessage, Policy, PublicKey, Secret, Signature,
	Signer, SigningKey, StorageKeys, Transaction, U256, UncheckedPrehash, Violation,
};
use tiny_keccak::{Hasher, Keccak};

type Result<T = ()> = core::result::Result<T, Box<dyn StdError>>;

const HALF_ORDER: &str = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
const HALF_ORDER_PLUS_ONE: &str =
	"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1";
const ORDER: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

fn hex(s: &str) -> Result<Vec<u8>> {
	s.strip_prefix("0x")
		.unwrap_or(s)
		.as_bytes()
		.chunks(2)
		.map(|pair| Ok(u8::from_str_radix(core::str::from_utf8(pair)?, 16)?))
		.collect()
}

fn array<const N: usize>(s: &str) -> Result<[u8; N]> {
	Ok(hex(s)?.try_into().map_err(|_| "wrong length")?)
}

fn address(s: &str) -> Result<Option<Address>> {
	if s.is_empty() { Ok(None) } else { Ok(Some(Address::from_bytes(array(s)?))) }
}

fn key46() -> Result<SigningKey> {
	Ok(SigningKey::from_secret(&Secret::new([0x46; 32]))?)
}

struct Fixed<'a>(&'a [u8]);

impl Entropy for Fixed<'_> {
	fn fill(&mut self, dest: &mut [u8]) -> core::result::Result<(), Error> {
		dest.copy_from_slice(self.0.get(..dest.len()).ok_or(Error::Entropy)?);
		Ok(())
	}
}

struct Failing;

impl Entropy for Failing {
	fn fill(&mut self, _: &mut [u8]) -> core::result::Result<(), Error> {
		Err(Error::Entropy)
	}
}

type Core<D> = <D as sha2::digest::block_api::CoreProxy>::Core;

#[test]
fn rfc6979_state_zeroizes_on_drop() {
	fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
	// `Hmac` has no marker of its own; its state is two of these cores and this buffer.
	zeroize_on_drop::<Core<sha2::Sha256>>();
	zeroize_on_drop::<sha2::digest::block_api::Buffer<Core<sha2::Sha256>>>();
}

#[test]
fn invalid_keys() -> Result {
	for secret in [[0; 32], array(ORDER)?, [0xff; 32]] {
		assert_eq!(SigningKey::from_secret(&Secret::new(secret)).err(), Some(Error::InvalidKey));
	}
	assert_eq!(PublicKey::from_sec1_bytes(&[4; 64]), Err(Error::InvalidKey));
	assert_eq!(PublicKey::from_sec1_bytes(&[4; 65]), Err(Error::InvalidKey));
	assert_eq!(format!("{:?}", key46()?), "SigningKey([REDACTED])");
	Ok(())
}

#[test]
fn generate() -> Result {
	let key = SigningKey::generate(&mut Fixed(&[0x46; 32]))?;
	assert_eq!(key.address(), key46()?.address());
	assert_eq!(SigningKey::generate(&mut Fixed(&[0; 32])).err(), Some(Error::InvalidKey));
	assert_eq!(SigningKey::generate(&mut Failing).err(), Some(Error::Entropy));
	let mnemonic = hd::generate_mnemonic(&mut Fixed(&[0; 32]))?;
	assert_eq!(mnemonic.word_count(), WordCount::W24);
	assert_eq!(hd::generate_mnemonic(&mut Failing).err(), Some(Error::Entropy));
	Ok(())
}

#[test]
fn eip55() -> Result {
	for s in [
		"0x52908400098527886E0F7030069857D2E4169EE7",
		"0x8617E340B3D01FA5F11F306F4090FD50E238070D",
		"0xde709f2102306220921060314715629080e2fb77",
		"0x27b1fdb04752bbc536007a920d24acb045561c26",
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	] {
		let parsed = Address::parse(s)?;
		assert_eq!(parsed.to_string(), s);
		assert_eq!(address(s)?, Some(parsed));
	}
	for (s, error) in [
		("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", Error::InvalidChecksum),
		("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", Error::InvalidChecksum),
		("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", Error::InvalidEncoding),
		("0X5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", Error::InvalidEncoding),
		("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe", Error::InvalidEncoding),
		("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed0", Error::InvalidEncoding),
		("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg", Error::InvalidEncoding),
		("0x+aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", Error::InvalidEncoding),
		("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beé", Error::InvalidEncoding),
	] {
		assert_eq!(Address::parse(s), Err(error), "{s}");
	}
	Ok(())
}

#[test]
fn unchecked_prehash() -> Result {
	let key = key46()?;
	let message = PersonalMessage::new(b"hello");
	let prehash = UncheckedPrehash(message.signing_hash()?);
	assert_eq!(
		key.sign(Payload::UncheckedPrehash(&prehash))?,
		key.sign(Payload::PersonalMessage(&message))?
	);
	Ok(())
}

#[test]
fn signature() -> Result {
	let one = array::<32>(&format!("{:064x}", 1))?;
	let half = array::<32>(HALF_ORDER)?;
	let signature = Signature::new(one, half, true)?;
	assert_eq!(Signature::from_rsv(&signature.to_rsv())?, signature);
	assert_eq!(signature.to_rsv().last(), Some(&28));
	assert_eq!(Signature::new(one, one, false)?.to_rsv().last(), Some(&27));
	let mut rsv = signature.to_rsv();
	for (v, parity) in [(0, false), (1, true), (27, false), (28, true)] {
		*rsv.last_mut().ok_or("empty")? = v;
		assert_eq!(Signature::from_rsv(&rsv)?.y_parity(), parity);
	}
	for v in [2, 26, 29, 37] {
		*rsv.last_mut().ok_or("empty")? = v;
		assert_eq!(Signature::from_rsv(&rsv), Err(Error::InvalidSignature));
	}
	for (r, s) in [
		([0; 32], one),
		(one, [0; 32]),
		(array(ORDER)?, one),
		([0xff; 32], one),
		(one, array(HALF_ORDER_PLUS_ONE)?),
		(one, array(ORDER)?),
	] {
		assert_eq!(Signature::new(r, s, false), Err(Error::InvalidSignature));
	}
	Ok(())
}

#[test]
fn chain_id() -> Result {
	assert_eq!(ChainId::new(0), Err(Error::Unsupported));
	assert_eq!(ChainId::new(1)?.get(), 1);
	assert_eq!(ChainId::new(ChainId::MAX)?.get(), ChainId::MAX);
	assert_eq!(
		ChainId::new(ChainId::MAX.checked_add(1).ok_or("overflow")?),
		Err(Error::Unsupported)
	);
	assert_eq!(ChainId::new(u64::MAX), Err(Error::Unsupported));
	Ok(())
}

#[test]
fn legacy_rlp() -> Result {
	let valid = hex("c9800101808080250101")?;
	let (tx, signature) = LegacyTx::decode_signed(&valid)?;
	assert_eq!(tx.chain_id.get(), 1);
	assert_eq!(tx.to, None);
	assert!(!signature.y_parity());
	assert!(LegacyTx::decode_signed(&hex("c9800101808080260101")?)?.1.y_parity());

	for (bytes, error) in [
		("c98001018080801b0101", Error::Unsupported),
		("c98001018080801c0101", Error::Unsupported),
		("c9800101808080220101", Error::Unsupported),
		("c9800101808080230101", Error::Unsupported),
		("c9000101808080250101", Error::InvalidEncoding),
		("ca80018101808080250101", Error::InvalidEncoding),
		("cb8001820001808080250101", Error::InvalidEncoding),
		("f809800101808080250101", Error::InvalidEncoding),
		("c98001018080802501", Error::InvalidEncoding),
		("c880010180808025010101", Error::InvalidEncoding),
		("ca800101808080250101", Error::InvalidEncoding),
		("ca80010180808025010101", Error::InvalidEncoding),
		("c9800101c08080250101", Error::InvalidEncoding),
		("c9800101058080250101", Error::InvalidEncoding),
		("c9800101808080258001", Error::InvalidSignature),
		("c9800101808080250180", Error::InvalidSignature),
		(
			"e98001018080802501a07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
			Error::InvalidSignature,
		),
		("09800101808080250101", Error::InvalidEncoding),
		("", Error::InvalidEncoding),
	] {
		assert_eq!(LegacyTx::decode_signed(&hex(bytes)?).err(), Some(error), "{bytes}");
	}

	let unsigned = hex("c9800101808080018080")?;
	assert_eq!(LegacyTx::decode_unsigned(&unsigned)?.chain_id.get(), 1);
	for bytes in ["c9800101808080800180", "c9800101808080010180", "c9800101808080010001"] {
		assert!(LegacyTx::decode_unsigned(&hex(bytes)?).is_err(), "{bytes}");
	}

	let oversized = vec![0; MAX_TX_LEN.checked_add(1).ok_or("overflow")?];
	assert_eq!(LegacyTx::decode_signed(&oversized).err(), Some(Error::LimitExceeded));
	assert_eq!(Eip1559Tx::decode_unsigned(&oversized).err(), Some(Error::LimitExceeded));
	Ok(())
}

#[test]
fn typed_rlp() -> Result {
	let raw = MAINNET_EIP2930.raw;
	assert_eq!(raw.matches("c001a0").count(), 1);
	for (from, to, error) in [
		("c001a0", "c002a0", Error::InvalidSignature),
		("c001a0", "c000a0", Error::InvalidEncoding),
		("c001a0", "c0c0a0", Error::InvalidEncoding),
		("c001a0", "c18001a0", Error::InvalidEncoding),
	] {
		let mutated = hex(&raw.replacen(from, to, 1))?;
		assert_eq!(Eip2930Tx::decode_signed(&mutated).err(), Some(error), "{to}");
	}

	assert_eq!(AccessList::from_rlp(&hex("c0")?)?, AccessList::EMPTY);
	let entry = hex("d7d6940000000000000000000000000000000000000000c0")?;
	assert_eq!(AccessList::from_rlp(&entry)?.iter().count(), 1);
	for bytes in [
		"",
		"80",
		"c0c0",
		"c1c0",
		"d6d5940000000000000000000000000000000000000000",
		"d8d7940000000000000000000000000000000000000000c0c0",
		"f7f6940000000000000000000000000000000000000000e09f00000000000000000000000000000000000000000000000000000000000000",
		"d6d59300000000000000000000000000000000000000c0",
		"d8d7940000000000000000000000000000000000000000c180",
	] {
		assert_eq!(
			AccessList::from_rlp(&hex(bytes)?).err(),
			Some(Error::InvalidEncoding),
			"{bytes}"
		);
	}

	let keys = [[7; 32]];
	let items = [AccessListItem {
		address: Address::from_bytes([1; 20]),
		storage_keys: StorageKeys::new(&keys),
	}];
	let mut short = [0; 10];
	assert_eq!(AccessList::encode(&items, &mut short).err(), Some(Error::BufferTooSmall));
	Ok(())
}

#[test]
fn erc20() -> Result {
	let recipient = Address::from_bytes([0x35; 20]);
	let input = hex("a9059cbb0000000000000000000000003535353535353535353535353535353535353535\
		 0000000000000000000000000000000000000000000000000de0b6b3a7640000")?;
	let call = Erc20Call::decode(&input)?;
	assert_eq!(
		call,
		Erc20Call::Transfer { to: recipient, amount: U256::from(1_000_000_000_000_000_000_u128) }
	);

	for call in [
		call,
		Erc20Call::TransferFrom {
			from: Address::from_bytes([1; 20]),
			to: recipient,
			amount: U256::MAX,
		},
		Erc20Call::Approve { spender: recipient, amount: U256::from(5_u64) },
	] {
		let mut buf = vec![0xaa; call.encoded_len()];
		assert_eq!(call.encode(&mut buf)?, call.encoded_len());
		assert_eq!(Erc20Call::decode(&buf)?, call);
		let (_, short) = buf.split_last_mut().ok_or("empty")?;
		assert_eq!(call.encode(short), Err(Error::BufferTooSmall));
	}
	assert_eq!(input.len(), 68);

	let mut extra = input.clone();
	extra.push(0);
	let mut padded = input.clone();
	*padded.get_mut(4).ok_or("short")? = 1;
	let mut unknown = input.clone();
	*unknown.first_mut().ok_or("empty")? = 0;
	for (bytes, error) in [
		(extra, Error::InvalidEncoding),
		(input.get(..67).ok_or("short")?.to_vec(), Error::InvalidEncoding),
		(input.get(..36).ok_or("short")?.to_vec(), Error::InvalidEncoding),
		(input.get(..3).ok_or("short")?.to_vec(), Error::InvalidEncoding),
		(padded, Error::InvalidEncoding),
		(unknown, Error::Unsupported),
	] {
		assert_eq!(Erc20Call::decode(&bytes), Err(error));
	}
	Ok(())
}

fn tx(to: Option<Address>, value: u64, input: &[u8]) -> Result<Eip1559Tx<'_>> {
	Ok(Eip1559Tx {
		chain_id: ChainId::new(1)?,
		nonce: 0,
		max_priority_fee_per_gas: 1,
		max_fee_per_gas: 10,
		gas_limit: 21_000,
		to,
		value: U256::from(value),
		input,
		access_list: AccessList::EMPTY,
	})
}

fn call(call: Erc20Call) -> Result<Vec<u8>> {
	let mut buf = vec![0; call.encoded_len()];
	call.encode(&mut buf)?;
	Ok(buf)
}

#[test]
fn policy() -> Result {
	let recipient = Address::from_bytes([0x35; 20]);
	let stranger = Address::from_bytes([0x66; 20]);
	let token = Address::from_bytes([0x6b; 20]);
	let chains = [ChainId::new(1)?];
	let recipients = [recipient];
	let tokens = [token];
	let policy = Policy {
		chain_ids: &chains,
		recipients: Some(&recipients),
		max_value: Some(U256::from(1_000_u64)),
		max_fee: Some(210_000),
		calls: Calls::Erc20 { tokens: &tokens, allow_approve: true },
	};

	let transfer = call(Erc20Call::Transfer { to: recipient, amount: U256::MAX })?;
	let transfer_from =
		call(Erc20Call::TransferFrom { from: stranger, to: recipient, amount: U256::from(1_u64) })?;
	let bad_transfer = call(Erc20Call::Transfer { to: stranger, amount: U256::from(1_u64) })?;
	let approve = call(Erc20Call::Approve { spender: recipient, amount: U256::from(1_u64) })?;
	let approve_stranger =
		call(Erc20Call::Approve { spender: stranger, amount: U256::from(1_u64) })?;
	let unlimited = call(Erc20Call::Approve { spender: recipient, amount: U256::MAX })?;
	let garbage = [0xde, 0xad, 0xbe, 0xef];

	assert_eq!(policy.check(&tx(Some(recipient), 1_000, &[])?), Ok(()));
	assert_eq!(policy.check(&tx(Some(token), 0, &transfer)?), Ok(()));
	assert_eq!(policy.check(&tx(Some(token), 0, &transfer_from)?), Ok(()));
	assert_eq!(policy.check(&tx(Some(token), 0, &approve)?), Ok(()));

	let mut other_chain = tx(Some(recipient), 1, &[])?;
	other_chain.chain_id = ChainId::new(5)?;
	let mut expensive = tx(Some(recipient), 1, &[])?;
	expensive.max_fee_per_gas = 11;
	let mut overflowing = tx(Some(recipient), 1, &[])?;
	overflowing.max_fee_per_gas = u128::MAX;
	assert_eq!(overflowing.max_fee(), None);

	for (tx, violation) in [
		(other_chain, Violation::ChainId),
		(expensive, Violation::Fee),
		(overflowing, Violation::Fee),
		(tx(Some(recipient), 1_001, &[])?, Violation::Value),
		(tx(None, 0, &[])?, Violation::ContractCreation),
		(tx(Some(stranger), 1, &[])?, Violation::Recipient),
		(tx(Some(stranger), 0, &transfer)?, Violation::Token),
		(tx(Some(token), 1, &transfer)?, Violation::Value),
		(tx(Some(token), 0, &bad_transfer)?, Violation::Recipient),
		(tx(Some(token), 0, &approve_stranger)?, Violation::Recipient),
		(tx(Some(token), 0, &unlimited)?, Violation::UnlimitedApproval),
		(tx(Some(token), 0, &garbage)?, Violation::ContractCall),
	] {
		assert_eq!(policy.check(&tx), Err(violation));
	}

	let no_approve =
		Policy { calls: Calls::Erc20 { tokens: &tokens, allow_approve: false }, ..policy };
	assert_eq!(no_approve.check(&tx(Some(token), 0, &approve)?), Err(Violation::Approve));
	assert_eq!(no_approve.check(&tx(Some(token), 0, &transfer)?), Ok(()));

	let deny = Policy { calls: Calls::Deny, ..policy };
	assert_eq!(deny.check(&tx(Some(token), 0, &transfer)?), Err(Violation::ContractCall));

	let any =
		Policy { calls: Calls::Any, recipients: None, max_value: None, max_fee: None, ..policy };
	assert_eq!(any.check(&tx(Some(stranger), u64::MAX, &garbage)?), Ok(()));
	assert_eq!(any.check(&overflowing), Ok(()));
	assert_eq!(any.check(&tx(None, 0, &garbage)?), Err(Violation::ContractCreation));
	Ok(())
}

fn keccak(data: &[u8]) -> [u8; 32] {
	let mut out = [0; 32];
	let mut hasher = Keccak::v256();
	hasher.update(data);
	hasher.finalize(&mut out);
	out
}

#[test]
fn eip155_example() -> Result {
	let tx = LegacyTx {
		chain_id: ChainId::new(1)?,
		nonce: 9,
		gas_price: 20_000_000_000,
		gas_limit: 21_000,
		to: address("0x3535353535353535353535353535353535353535")?,
		value: U256::from(1_000_000_000_000_000_000_u128),
		input: &[],
	};
	let mut unsigned = vec![0; tx.unsigned_len()?];
	tx.encode_unsigned(&mut unsigned)?;
	assert_eq!(
		unsigned,
		hex(
			"ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
		)?
	);
	assert_eq!(
		tx.signing_hash()?,
		array::<32>("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")?
	);
	let key = key46()?;
	let signature = key.sign(Payload::Legacy(&tx))?;
	let mut signed = vec![0; tx.signed_len(&signature)?];
	tx.encode_signed(&signature, &mut signed)?;
	assert_eq!(
		signed,
		hex(
			"f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
		)?
	);
	assert_eq!(key.address().to_string(), "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F");
	Ok(())
}

#[test]
fn hardhat_accounts() -> Result {
	assert_eq!(PROFILE, "eth-bip44-v1");
	let mnemonic = Mnemonic::parse("test test test test test test test test test test test junk")?;
	let seed = mnemonic.to_seed("")?;
	for (index, secret, checksummed) in [
		(
			0,
			"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
			"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		),
		(
			1,
			"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
			"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		),
		(
			2,
			"5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
			"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		),
	] {
		let key = hd::derive(&seed, index)?;
		assert_eq!(key.to_secret().expose(), &array::<32>(secret)?);
		assert_eq!(key.address().to_string(), checksummed);
	}
	assert_eq!(hd::derive(&seed, 0x8000_0000).err(), Some(Error::Unsupported));
	assert_eq!(hd::derive_from_mnemonic(&mnemonic, "", 0).err(), Some(Error::Unsupported));

	let long = Mnemonic::parse(&format!("{} art", ["abandon"; 23].join(" ")))?;
	assert_eq!(long.word_count(), WordCount::W24);
	for (passphrase, index) in [("", 0), ("", 1), ("TREZOR", 0x7fff_ffff)] {
		assert_eq!(
			hd::derive_from_mnemonic(&long, passphrase, index)?.address(),
			hd::derive(&long.to_seed(passphrase)?, index)?.address()
		);
	}
	Ok(())
}

struct Mainnet {
	block: u64,
	hash: &'static str,
	sender: &'static str,
	raw: &'static str,
}

const MAINNET_LEGACY: Mainnet = Mainnet {
	block: 26_380_388,
	hash: "eb166375ff11253878bdaf16ff6bac41a869e7b3e060f3830929643e88e481f2",
	sender: "39d5978253169aa55b83329532fb020e23b9fba9",
	raw: "f8a880843b9aca0082ea6094dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb00000000000000000000000064cdaa89629fe003eaa31b480d8b63372d109a5300000000000000000000000000000000000000000000000000000000216531c026a0e0dd20b059320e3978840127a58ae5328e47bff9c4839941c592041397e50bcfa073a22de199ef5254b5e62b1076041f7e40150f606c7e83a9ac95bfd9cf37d245",
};

const MAINNET_EIP2930: Mainnet = Mainnet {
	block: 26_380_329,
	hash: "b3b7f8abc412dd42db1581cca379c871ba6cf0760c7711d480504b11b061fc1c",
	sender: "892a07aa433d14fd04ea98df4c46c28ff2fc4af6",
	raw: "01f8ab0104840761e56e8301add794dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000000073e8934ddee6900ed3af1e691e0a6b128e715c000000000000000000000000000000000000000000000000000000001e19b040c001a0cf1fa9949ef0d210768db953b376ba8e1a256c40a4b27427664264d08c3aa6f2a04180cfce2d2e7f59d8c6ea96ed8838e152b74ff68490e3cdb7519032f4d71f03",
};

const MAINNET_EIP1559: Mainnet = Mainnet {
	block: 26_380_384,
	hash: "7a1b3ec046d5cc6fbfc927986037939622b00eec91511a6cfc4432cf1775e4d1",
	sender: "3e10ab3b27129eebf0c06b7f8ed5c47119416977",
	raw: "02f902e30183013f7a83a1b5668404812bb7830927df94278d858f05b94576c1e6f73285886876ff6ef8d280b8c742e3dcf300000000000000000000000000000000000000000000000000eeadb6595905d7000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000164a29e5f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000004068038ab5490063a3ead93b3712ed082e62bd59000000000000000000000000000000000000000000000000000000006af24c74000012f901acf8599400f3c42833c3170159af4e92dbb451fb3f708917f842a068a747a5bd5a1901186493b5d706d3245c48381971800ac70de0ff94e5a16ac1a0797d825201411a6bcf33f1b2c0a2e1754985ca0c2e1a2e9235e771eaf1a99982f8dd944068038ab5490063a3ead93b3712ed082e62bd59f8c6a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000008a0733e5000b8000853f478eac1b497fc0c6c7a5e5899388a335d6730922974fbced69499dfe137707048b353897d70fc561996e2725172c0f85994c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f842a0592aeb7ad511ee59238be0b105ceaa41b4c9d767664193982b5467d8da2abc2aa09f7bb584ea6b4a2bee460841a29cfb9c00b987e4bd1a78dccee5591def8d121980a022214189983526d830e5369428351ab9ea952402fdcad22b3a6019edd7850a55a00af13089e3bb57d5001dd21f81b07c42bf50400d2684a8f3008f5e37bc98ab7e",
};

macro_rules! check_mainnet {
	($ty:ident, $variant:path, $anchor:expr, $raw:expr) => {{
		let anchor = $anchor;
		let raw: &[u8] = $raw;
		assert_eq!(keccak(raw), array::<32>(anchor.hash)?, "block {}", anchor.block);
		let (tx, signature) = $ty::decode_signed(raw)?;
		assert_eq!(tx.chain_id.get(), 1);
		assert_eq!(Some(signature.recover($variant(&tx))?.address()), address(anchor.sender)?);
		let mut encoded = vec![0; tx.signed_len(&signature)?];
		tx.encode_signed(&signature, &mut encoded)?;
		assert_eq!(encoded, raw);
		tx
	}};
}

#[test]
fn mainnet_transactions() -> Result {
	let usdt = address("0xdac17f958d2ee523a2206206994597c13d831ec7")?;

	let raw = hex(MAINNET_LEGACY.raw)?;
	let legacy = check_mainnet!(LegacyTx, Payload::Legacy, MAINNET_LEGACY, &raw);
	assert_eq!(legacy.to, usdt);
	assert_eq!(
		Erc20Call::decode(legacy.input)?,
		Erc20Call::Transfer {
			to: Address::from_bytes(array("64cdaa89629fe003eaa31b480d8b63372d109a53")?),
			amount: U256::from(0x2165_31c0_u64),
		}
	);

	let raw = hex(MAINNET_EIP2930.raw)?;
	let eip2930 = check_mainnet!(Eip2930Tx, Payload::Eip2930, MAINNET_EIP2930, &raw);
	assert_eq!(eip2930.to, usdt);
	assert!(eip2930.access_list.is_empty());
	assert_eq!(
		Erc20Call::decode(eip2930.input)?,
		Erc20Call::Transfer {
			to: Address::from_bytes(array("0073e8934ddee6900ed3af1e691e0a6b128e715c")?),
			amount: U256::from(0x1e19_b040_u64),
		}
	);

	let raw = hex(MAINNET_EIP1559.raw)?;
	let eip1559 = check_mainnet!(Eip1559Tx, Payload::Eip1559, MAINNET_EIP1559, &raw);
	let entries: Vec<_> =
		eip1559.access_list.iter().map(|item| (item.address, item.storage_keys.count())).collect();
	assert_eq!(entries.iter().map(|(_, keys)| *keys).collect::<Vec<_>>(), [2, 6, 0, 2]);
	assert_eq!(Erc20Call::decode(eip1559.input).err(), Some(Error::Unsupported));
	Ok(())
}

struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
		let mut z = self.0;
		z = (z ^ z.wrapping_shr(30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
		z = (z ^ z.wrapping_shr(27)).wrapping_mul(0x94d0_49bb_1331_11eb);
		z ^ z.wrapping_shr(31)
	}

	fn below(&mut self, n: u64) -> u64 {
		self.next().checked_rem(n).unwrap_or(0)
	}

	fn len(&mut self, max: u64) -> usize {
		usize::try_from(self.below(max.saturating_add(1))).unwrap_or(0)
	}

	fn int(&mut self) -> u64 {
		let shift = u32::try_from(self.below(65)).unwrap_or(0);
		self.next().checked_shr(shift).unwrap_or(0)
	}

	fn wide(&mut self) -> u128 {
		u128::from(self.int()).checked_shl(self.int().count_ones()).unwrap_or(0)
			| u128::from(self.int())
	}

	fn byte(&mut self) -> u8 {
		self.next().to_be_bytes().first().copied().unwrap_or(0)
	}

	fn array<const N: usize>(&mut self) -> [u8; N] {
		let mut out = [0; N];
		out.iter_mut().for_each(|b| *b = self.byte());
		out
	}

	fn bytes(&mut self, max: u64) -> Vec<u8> {
		let len = self.len(max);
		(0..len).map(|_| self.byte()).collect()
	}

	fn u256(&mut self) -> U256 {
		let len = self.len(32);
		let mut out = [0; 32];
		out.iter_mut().rev().take(len).for_each(|b| *b = self.byte());
		U256::from_be_bytes(out)
	}

	fn chain_id(&mut self) -> Result<ChainId> {
		let id = match self.below(3) {
			0 => self.below(ChainId::MAX),
			1 => self.below(100_000),
			_ => ChainId::MAX.checked_sub(self.below(3)).ok_or("underflow")?,
		};
		Ok(ChainId::new(id.max(1))?)
	}

	fn key(&mut self) -> Result<(SigningKey, secp256k1::SecretKey)> {
		let secret = self.array::<32>();
		let theirs =
			secp256k1::SecretKey::from_secret_bytes(secret).map_err(|e| format!("{e:?}"))?;
		Ok((SigningKey::from_secret(&Secret::new(secret))?, theirs))
	}
}

fn append_uint(stream: &mut RlpStream, be: &[u8]) {
	let zeros = be.iter().take_while(|&&b| b == 0).count();
	stream.append(&be.get(zeros..).unwrap_or(&[]).to_vec());
}

fn append_to(stream: &mut RlpStream, to: Option<Address>) {
	match to {
		Some(address) => stream.append(&address.as_bytes().to_vec()),
		None => stream.append_empty_data(),
	};
}

fn append_access_list(stream: &mut RlpStream, entries: &[(Address, Vec<[u8; 32]>)]) {
	stream.begin_list(entries.len());
	for (address, keys) in entries {
		stream.begin_list(2);
		stream.append(&address.as_bytes().to_vec());
		stream.begin_list(keys.len());
		for key in keys {
			stream.append(&key.to_vec());
		}
	}
}

fn typed(
	ty: u8,
	fields: usize,
	signature: Option<&Signature>,
	append: impl Fn(&mut RlpStream),
) -> Vec<u8> {
	let len = if signature.is_some() { fields.saturating_add(3) } else { fields };
	let mut stream = RlpStream::new_list(len);
	append(&mut stream);
	if let Some(signature) = signature {
		stream.append(&u64::from(signature.y_parity()));
		append_uint(&mut stream, signature.r());
		append_uint(&mut stream, signature.s());
	}
	let mut out = vec![ty];
	out.extend_from_slice(&stream.out());
	out
}

fn reference_signature(hash: [u8; 32], key: &secp256k1::SecretKey) -> Result<Signature> {
	let (id, rs) =
		RecoverableSignature::sign_ecdsa_recoverable(secp256k1::Message::from_digest(hash), key)
			.serialize_compact();
	let (r, s) = rs.split_first_chunk::<32>().ok_or("signature")?;
	Ok(Signature::new(*r, s.try_into()?, u8::from(id) == 1)?)
}

macro_rules! differential {
	($ty:ident, $variant:path, $tx:expr, $keys:expr, $reference:expr) => {{
		let tx = $tx;
		let (key, theirs) = $keys;
		let reference = $reference;
		let unsigned = reference(None);
		let mut buf = vec![0; tx.unsigned_len()?];
		tx.encode_unsigned(&mut buf)?;
		assert_eq!(buf, unsigned);
		assert_eq!(tx.signing_hash()?, keccak(&unsigned));
		assert_eq!($ty::decode_unsigned(&unsigned)?, tx);

		let signature = key.sign($variant(&tx))?;
		assert_eq!(signature, reference_signature(keccak(&unsigned), theirs)?);
		let signed = reference(Some(&signature));
		let mut buf = vec![0; tx.signed_len(&signature)?];
		tx.encode_signed(&signature, &mut buf)?;
		assert_eq!(buf, signed);
		assert_eq!($ty::decode_signed(&signed)?, (tx, signature));
		assert_eq!(signature.recover($variant(&tx))?, key.public_key());
	}};
}

const ROUNDS: u32 = 200;

#[test]
fn differential_keys() -> Result {
	let mut rng = Rng(1);
	for _ in 0..ROUNDS {
		let (key, theirs) = rng.key()?;
		let public = secp256k1::PublicKey::from_secret_key(&theirs).serialize_uncompressed();
		assert_eq!(key.public_key().to_uncompressed(), public);
		let hash = keccak(public.get(1..).ok_or("public key")?);
		assert_eq!(Some(key.address().as_bytes().as_slice()), hash.get(12..));
	}
	Ok(())
}

#[test]
fn differential_personal_sign() -> Result {
	let mut rng = Rng(2);
	for _ in 0..ROUNDS {
		let (key, theirs) = rng.key()?;
		let message = rng.bytes(300);
		let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
		prefixed.extend_from_slice(&message);
		let hash = keccak(&prefixed);

		let message = PersonalMessage::new(&message);
		assert_eq!(message.signing_hash()?, hash);
		let signature = key.sign(Payload::PersonalMessage(&message))?;
		assert_eq!(signature, reference_signature(hash, &theirs)?);
		assert_eq!(key.sign(Payload::UncheckedPrehash(&UncheckedPrehash(hash)))?, signature);
	}
	Ok(())
}

#[test]
fn differential_transactions() -> Result {
	let mut rng = Rng(3);
	for round in 0..ROUNDS.saturating_mul(3) {
		let keys = rng.key()?;
		let chain_id = rng.chain_id()?;
		let to = if rng.below(10) == 0 { None } else { Some(Address::from_bytes(rng.array())) };
		let value = rng.u256();
		let max_input = if rng.below(4) == 0 { 2000 } else { 60 };
		let input = rng.bytes(max_input);
		let mut entries = Vec::new();
		for _ in 0..rng.len(3) {
			let address = Address::from_bytes(rng.array());
			let count = rng.len(3);
			let keys: Vec<[u8; 32]> = (0..count).map(|_| rng.array()).collect();
			entries.push((address, keys));
		}
		let items: Vec<_> = entries
			.iter()
			.map(|(address, keys)| AccessListItem {
				address: *address,
				storage_keys: StorageKeys::new(keys),
			})
			.collect();
		let mut access_buf = vec![0; 1024];
		let access_list = AccessList::encode(&items, &mut access_buf)?;
		let nonce = rng.int();
		let gas_limit = rng.int();

		match round.checked_rem(3) {
			Some(0) => {
				let tx = LegacyTx {
					chain_id,
					nonce,
					gas_price: rng.wide(),
					gas_limit,
					to,
					value,
					input: &input,
				};
				differential!(
					LegacyTx,
					Payload::Legacy,
					tx,
					(&keys.0, &keys.1),
					|signature: Option<&Signature>| {
						let mut stream = RlpStream::new_list(9);
						stream.append(&tx.nonce).append(&tx.gas_price).append(&tx.gas_limit);
						append_to(&mut stream, tx.to);
						append_uint(&mut stream, tx.value.as_be_bytes());
						stream.append(&tx.input.to_vec());
						match signature {
							None => {
								stream.append(&tx.chain_id.get()).append(&0_u64).append(&0_u64);
							},
							Some(signature) => {
								let v = u128::from(tx.chain_id.get()) * 2
									+ 35 + u128::from(signature.y_parity());
								stream.append(&v);
								append_uint(&mut stream, signature.r());
								append_uint(&mut stream, signature.s());
							},
						}
						stream.out().to_vec()
					}
				);
			},
			Some(1) => {
				let tx = Eip2930Tx {
					chain_id,
					nonce,
					gas_price: rng.wide(),
					gas_limit,
					to,
					value,
					input: &input,
					access_list,
				};
				differential!(Eip2930Tx, Payload::Eip2930, tx, (&keys.0, &keys.1), |signature| {
					typed(1, 8, signature, |stream| {
						stream
							.append(&tx.chain_id.get())
							.append(&tx.nonce)
							.append(&tx.gas_price)
							.append(&tx.gas_limit);
						append_to(stream, tx.to);
						append_uint(stream, tx.value.as_be_bytes());
						stream.append(&tx.input.to_vec());
						append_access_list(stream, &entries);
					})
				});
			},
			_ => {
				let tx = Eip1559Tx {
					chain_id,
					nonce,
					max_priority_fee_per_gas: rng.wide(),
					max_fee_per_gas: rng.wide(),
					gas_limit,
					to,
					value,
					input: &input,
					access_list,
				};
				differential!(Eip1559Tx, Payload::Eip1559, tx, (&keys.0, &keys.1), |signature| {
					typed(2, 9, signature, |stream| {
						stream
							.append(&tx.chain_id.get())
							.append(&tx.nonce)
							.append(&tx.max_priority_fee_per_gas)
							.append(&tx.max_fee_per_gas)
							.append(&tx.gas_limit);
						append_to(stream, tx.to);
						append_uint(stream, tx.value.as_be_bytes());
						stream.append(&tx.input.to_vec());
						append_access_list(stream, &entries);
					})
				});
			},
		}
	}
	Ok(())
}
