pub fn slice_window(buf: &[u8], offset: i64) -> usize {
    let idx = offset as usize;
    buf.len().saturating_sub(idx)
}
