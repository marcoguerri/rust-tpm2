mod device;
mod tpm2;
use tpm2::commands::pcrread;
use tpm2::commands::pcrs::PCRSelection;

#[macro_use]
extern crate mem_macros;

fn main() {
    let selection = PCRSelection::new();
    let ret = match pcrread::tpm2_pcr_read(&[selection]) {
        Ok(ret) => {
            println!("{:?}", ret);
            0
        }
        Err(err) => {
            println!("{:?}", err);
            1
        }
    };
}
