use solana_program::clock::Clock;
pub fn select_winner_seed() -> u64 {
    Clock::get().unwrap().unix_timestamp as u64
}
