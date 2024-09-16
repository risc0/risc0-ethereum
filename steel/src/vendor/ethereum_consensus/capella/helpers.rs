use crate::ethereum_consensus::{
    phase0::validator::Validator,
    primitives::{Epoch, Gwei, ETH1_ADDRESS_WITHDRAWAL_PREFIX},
    state_transition::Context,
};

pub fn has_eth1_withdrawal_credential(validator: &Validator) -> bool {
    validator.withdrawal_credentials[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
}

pub fn is_fully_withdrawable_validator(validator: &Validator, balance: Gwei, epoch: Epoch) -> bool {
    has_eth1_withdrawal_credential(validator)
        && validator.withdrawable_epoch <= epoch
        && balance > 0
}

pub fn is_partially_withdrawable_validator(
    validator: &Validator,
    balance: Gwei,
    context: &Context,
) -> bool {
    let has_max_effective_balance = validator.effective_balance == context.max_effective_balance;
    let has_excess_balance = balance > context.max_effective_balance;
    has_eth1_withdrawal_credential(validator) && has_max_effective_balance && has_excess_balance
}
