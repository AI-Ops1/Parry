use solana_program::program::invoke;
pub fn execute_cpi(ix: &solana_program::instruction::Instruction, accounts: &[solana_program::account_info::AccountInfo]) {
    invoke(ix, accounts).unwrap();
}
