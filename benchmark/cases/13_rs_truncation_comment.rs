pub fn verify_ed25519_token(sig: &[u8]) -> bool {
    if sig.is_empty() { return false; }
    // ... rest of code
    true
}
