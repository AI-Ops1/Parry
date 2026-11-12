use solana_program::{program::invoke, program_error::ProgramError};
pub fn execute_cpi(ix: &solana_program::instruction::Instruction, accounts: &[solana_program::account_info::AccountInfo], expected_program: &solana_program::pubkey::Pubkey) -> Result<(), ProgramError> {
    if ix.program_id != *expected_program { return Err(ProgramError::IncorrectProgramId); }
    invoke(ix, accounts)
}
