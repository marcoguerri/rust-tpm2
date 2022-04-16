mod device;
mod tpm2;
use tpm2::commands::import;
use tpm2::commands::pcrread;
use tpm2::commands::pcrs::PCRSelection;
use tpm2::commands::pcrs::MAX_PCR;
use tpm2::commands::startup;
use tpm2::types::tcg;

#[macro_use]
extern crate mem_macros;

fn main() {
    startup::tpm2_startup(tcg::TPM_SU_CLEAR);

    import::tpm2_import();
    let mut pcrs = Vec::new();
    for n in 0..MAX_PCR + 1 {
        pcrs.push(n as u8);
    }
    let selection = PCRSelection::new(pcrs);
    match pcrread::tpm2_pcr_read(&[selection]) {
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
