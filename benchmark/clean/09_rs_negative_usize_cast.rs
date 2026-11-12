pub fn safe_buffer_offset(base: i64) -> Result<usize, std::num::TryFromIntError> {
    usize::try_from(base)
}
