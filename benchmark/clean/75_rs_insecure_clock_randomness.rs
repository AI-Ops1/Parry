pub fn select_winner_seed(oracle_vrf_seed: [u8; 32]) -> u64 {
    u64::from_le_bytes(oracle_vrf_seed[..8].try_into().unwrap())
}
