pub fn calculate_vault_balance(deposit: u64, yield_bps: u64) -> u64 {
    deposit.saturating_add(deposit.saturating_mul(yield_bps) / 10_000)
}
