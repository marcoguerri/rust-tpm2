mod crypto;
mod device;
mod tpm2;
use device::raw;
use device::tcp;
use tcg::Handle;
use tpm2::commands::import;
use tpm2::commands::pcrs::PCRSelection;
use tpm2::commands::pcrs::MAX_PCR;
use tpm2::commands::session;
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

    println!("startup");
    startup::tpm2_startup(&mut tpm, tcg::TPM_SU_CLEAR);
    println!("auth session");
    let auth: tcg::TpmsAuthCommand = session::tpm2_startauth_session(&mut tpm).unwrap();

    let handle: Handle = 0x80000000;
    // Create import blob
    println!("policy secret");
    session::tpm2_policy_secret(&mut tpm, 0x4000000B, auth);
    println!("import");
    let data: tcg::Tpm2bData = import::tpm2_import(&mut tpm, handle, auth).unwrap();
}
