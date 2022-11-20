use crate::device;
use crate::tcg;
use crate::tpm2::commands::commands;
use crate::tpm2::commands::run;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use std::result;

#[derive(Copy, Clone, Debug)]
pub struct UnsealResponse {
    header: commands::ResponseHeader,
    data: tcg::Tpm2bData,
}

impl inout::Tpm2StructIn for UnsealResponse {
    fn unpack(
        &mut self,
        buff: &mut dyn inout::RwBytes,
    ) -> result::Result<(), errors::DeserializationError> {
        self.header.unpack(buff)?;
        self.data.unpack(buff)?;
        Ok(())
    }
}

pub fn tpm2_unseal(
    tpm: &mut dyn device::raw::TpmDeviceOps,
    handle: tcg::Handle,
) -> result::Result<tcg::Tpm2bData, errors::CommandError> {
    let handles: [tcg::Handle; 1] = [handle];

    let auths: [tcg::TpmsAuthCommand; 1] = [tcg::TpmsAuthCommand {
        session_handle: tcg::TPM_RS_PW,
        nonce: tcg::Tpm2bNonce::new(),
        session_attributes: tcg::TPMA_SESSION_CONTINUE_SESSION,
        hmac: tcg::Tpm2bAuth::new(),
    }];

    let params: [&dyn inout::Tpm2StructOut; 0] = [];

    let mut resp_buff = inout::StaticByteBuffer::new();

    let ret = run::run_command(
        tpm,
        tcg::TPM_CC_UNSEAL,
        &handles,
        &auths,
        &params,
        &mut resp_buff,
    )?;

    let mut unseal_response: UnsealResponse = UnsealResponse {
        header: commands::ResponseHeader::new(),
        data: tcg::Tpm2bData {
            size: 0,
            buffer: [0; 1024],
        },
    };
    unseal_response.unpack(&mut resp_buff)?;
    return Ok(unseal_response.data);
}
