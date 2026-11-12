pub fn read_offset_ptr(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}
