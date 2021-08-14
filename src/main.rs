mod device;
mod tpm2;
use tpm2::commands::pcr;

#[macro_use]
extern crate mem_macros;

fn main() {
    let ret = match pcr::tpm2_pcr_read() {
        Ok(ret) => ret,
        Err(_) => 1,
    };
    println!("retcode {}", ret);
}
