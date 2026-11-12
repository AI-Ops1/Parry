pub fn to_index(offset: i64) -> Result<usize, std::num::TryFromIntError> {
    usize::try_from(offset)
}
