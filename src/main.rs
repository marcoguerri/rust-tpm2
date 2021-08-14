use bytebuffer::ByteBuffer;
use std::convert::TryFrom;
use std::io;
use std::mem;
use std::result;

fn main() {
    let ret = match tpm2_pcr_read() {
        Ok(ret) => ret,
        Err(_) => 1,
    };
    println!("retcode {}", ret);
}
