pub fn load_file(p: &str) -> Result<String, std::io::Error> {
    let s = std::fs::read_to_string(p)?;
    Ok(s)
}
