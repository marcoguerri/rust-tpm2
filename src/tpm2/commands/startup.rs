use crate::device;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
use crate::tpm2::commands::run::run_command;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;

use crate::tpm2::types::tcg;
use std::result;

pub fn tpm2_startup(
    tpm: &mut device::raw::TpmDeviceOps,
    startup_type: tcg::TpmSu,
) -> result::Result<(), errors::CommandError> {
    let params: [&dyn inout::Tpm2StructOut; 1] = [&startup_type];

    let auth: [tcg::TpmsAuthCommand; 0] = [];
    let handles: [tcg::Handle; 0] = [];
    let mut resp_buff = inout::StaticByteBuffer::new();
    let ret = run_command(
        tpm,
        tcg::TPM_START_AUTH_SESSION,
        &handles,
        &auth,
        &params,
        &mut resp_buff,
    )?;

    Ok(())
}
