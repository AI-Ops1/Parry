pub fn add_mint_reward(current: u64, bonus: u64) -> Option<u64> {
    current.checked_add(bonus)
}
