pub fn select_winner_seed(oracle_vrf_seed: [u8; 32]) -> u64 {
    // Safety: slice [..8] is guaranteed to be exactly 8 bytes for [u8; 8] conversion
    u64::from_le_bytes(oracle_vrf_seed[..8].try_into().unwrap())
}
