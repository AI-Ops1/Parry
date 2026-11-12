pub fn read_offset_ptr(slice: &[u8]) -> Option<u8> {
    slice.first().copied()
}
