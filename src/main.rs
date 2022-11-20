mod crypto;
mod device;
mod tpm2;
use crate::device::raw;
use crate::device::tcp;
use crate::tcg::Handle;
use crate::tpm2::commands::session;
use tpm2::commands::import;
use tpm2::commands::pcrs::PCRSelection;
use tpm2::commands::pcrs::MAX_PCR;
use tpm2::commands::startup;
use tpm2::types::tcg;

#[macro_use]
extern crate mem_macros;

fn main() {
    let mut pcrs = Vec::new();
    for n in 0..MAX_PCR + 1 {
        pcrs.push(n as u8);
    }
    let selection = PCRSelection::new(pcrs);
    //match pcrread::tpm2_pcr_read(&[selection]) {
    //    Ok(pcrs) => {
    //        println!("{}", pcrs);
    //        0
    //    }
    //    Err(err) => {
    //        println!("There was an error {:?}", err);
    //        1
    //    }
    //};

    let mut stream = tcp::TpmSwtpmIO::new();
    let mut tpm: raw::TpmDevice = raw::TpmDevice { rw: &mut stream };

    startup::tpm2_startup(&mut tpm, tcg::TPM_SU_CLEAR);
    let auth: tcg::TpmsAuthCommand = session::tpm2_startauth_session(&mut tpm).unwrap();

    println!("auth command is {:?}", auth);

    let handle: Handle = 0x80000000;
    // Create import blob
    //
    session::tpm2_policy_secret(&mut tpm, 0x4000000B, auth);
    import::tpm2_import(&mut tpm, handle, auth);
}
