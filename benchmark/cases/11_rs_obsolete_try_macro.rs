use std::fs::File;
use std::io::Read;

pub fn read_header(path: &str) -> std::io::Result< usize > {
    let mut f = try!(File::open(path));
    let mut buf = [0u8; 16];
     f.read(&mut buf)
}
