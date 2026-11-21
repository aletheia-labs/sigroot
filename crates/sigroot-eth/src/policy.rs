use crate::{Address, ChainId, Erc20Call, Transaction, U256};

/// Rules a transaction must satisfy before signing.
#[derive(Clone, Copy, Debug)]
pub struct Policy<'a> {
	/// Allowed chains.
	pub chain_ids: &'a [ChainId],
	/// Allowed recipients, or `None` for any.
	pub recipients: Option<&'a [Address]>,
	/// Maximum transferred value in wei.
	pub max_value: Option<U256>,
	/// Maximum total fee in wei.
	pub max_fee: Option<u128>,
	/// Allowed contract calls.
	pub calls: Calls<'a>,
}

/// Allowed contract calls.
#[derive(Clone, Copy, Debug)]
pub enum Calls<'a> {
	/// Plain value transfers only.
	Deny,
	/// ERC-20 `transfer` and `transferFrom` on listed tokens, and `approve` if allowed.
	Erc20 {
		/// Allowed token contracts.
		tokens: &'a [Address],
		/// Whether bounded `approve` is allowed.
		allow_approve: bool,
	},
	/// Any call data.
	Any,
}

/// Reason a transaction was rejected.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
	/// Chain not allowed.
	ChainId,
	/// Fee above the limit or overflowing.
	Fee,
	/// Value above the limit, or non-zero for a token call.
	Value,
	/// Contract creation.
	ContractCreation,
	/// Call data not allowed.
	ContractCall,
	/// Recipient not allowed.
	Recipient,
	/// Token contract not allowed.
	Token,
	/// `approve` not allowed.
	Approve,
	/// Unlimited `approve`.
	UnlimitedApproval,
}

impl Policy<'_> {
	/// Checks `tx` against this policy.
	///
	/// # Errors
	///
	/// Returns the first [`Violation`] found.
	pub fn check(&self, tx: &impl Transaction) -> Result<(), Violation> {
		if !self.chain_ids.contains(&tx.chain_id()) {
			return Err(Violation::ChainId);
		}
		if let Some(limit) = self.max_fee
			&& tx.max_fee().is_none_or(|fee| fee > limit)
		{
			return Err(Violation::Fee);
		}
		if self.max_value.is_some_and(|limit| tx.value() > limit) {
			return Err(Violation::Value);
		}
		let to = tx.to().ok_or(Violation::ContractCreation)?;
		if tx.input().is_empty() {
			return self.recipient(&to);
		}
		match self.calls {
			Calls::Deny => Err(Violation::ContractCall),
			Calls::Any => self.recipient(&to),
			Calls::Erc20 { tokens, allow_approve } => {
				if !tokens.contains(&to) {
					return Err(Violation::Token);
				}
				if tx.value() != U256::ZERO {
					return Err(Violation::Value);
				}
				match Erc20Call::decode(tx.input()).map_err(|_| Violation::ContractCall)? {
					Erc20Call::Transfer { to, .. } | Erc20Call::TransferFrom { to, .. } => {
						self.recipient(&to)
					},
					Erc20Call::Approve { .. } if !allow_approve => Err(Violation::Approve),
					Erc20Call::Approve { amount, .. } if amount == U256::MAX => {
						Err(Violation::UnlimitedApproval)
					},
					Erc20Call::Approve { spender, .. } => self.recipient(&spender),
				}
			},
		}
	}

	fn recipient(&self, address: &Address) -> Result<(), Violation> {
		match self.recipients {
			Some(allowed) if !allowed.contains(address) => Err(Violation::Recipient),
			_ => Ok(()),
		}
	}
}
