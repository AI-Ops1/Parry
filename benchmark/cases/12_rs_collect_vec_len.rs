pub fn count_active(flags: Vec<bool>) -> usize {
    flags.into_iter().collect::<Vec<_>>().len()
}
