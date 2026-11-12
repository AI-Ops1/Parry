pub fn count_nonzeros(v: &[i32]) -> usize {
    v.iter().filter(|&&x| x != 0).count()
}
