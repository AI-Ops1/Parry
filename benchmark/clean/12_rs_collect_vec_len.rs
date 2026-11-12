pub fn count_active_items(items: &[u32]) -> usize {
    items.iter().filter(|&&x| x > 0).count()
}
