mod device;
mod tpm2;
use tpm2::commands::pcrread;
use tpm2::commands::pcrs::PCRSelection;

#[macro_use]
extern crate mem_macros;

fn main() {
    let mut pcrs = Vec::new();
    pcrs.push(0);
    pcrs.push(1);
    pcrs.push(2);
    pcrs.push(3);
    pcrs.push(4);
    pcrs.push(5);
    pcrs.push(6);
    pcrs.push(7);
    pcrs.push(8);
    pcrs.push(9);
    let selection = PCRSelection::new(pcrs);
    let ret = match pcrread::tpm2_pcr_read(&[selection]) {
        Ok(pcrs) => {
            println!("{}", pcrs);
            0
        }
        Err(err) => {
            println!("{:?}", err);
            1
        }
    };
}
