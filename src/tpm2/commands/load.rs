use crate::device;
use crate::tcg;
use crate::tpm2::commands::commands;
use crate::tpm2::commands::run;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use std::result;

#[derive(Copy, Clone, Debug)]
pub struct LoadResponse {
    header: commands::ResponseHeader,
    handle: tcg::Handle,
    name: tcg::Tpm2bDigest,
}

impl inout::Tpm2StructIn for LoadResponse {
    fn unpack(
        &mut self,
        buff: &mut dyn inout::RwBytes,
    ) -> result::Result<(), errors::DeserializationError> {
        self.header.unpack(buff)?;
        self.handle.unpack(buff)?;

        let mut paramSize: u32 = 0;
        paramSize.unpack(buff)?;
        self.name.unpack(buff)?;

        Ok(())
    }
}

impl LoadResponse {
    pub fn new(
        buff: &mut dyn inout::RwBytes,
    ) -> result::Result<Self, errors::DeserializationError> {
        let mut resp = LoadResponse {
            header: commands::ResponseHeader::new(),
            handle: 0,
            name: tcg::Tpm2bDigest::new(),
        };

        resp.unpack(buff)?;
        Ok(resp)
    }
}

pub fn tpm2_load(
    tpm: &mut dyn device::raw::TpmDeviceOps,
    parent: tcg::Handle,
    auth: tcg::TpmsAuthCommand,
    in_private: tcg::Tpm2bPrivate,
    in_public: tcg::Tpm2bPublic,
) -> result::Result<tcg::Handle, errors::CommandError> {
    let handles: [tcg::Handle; 1] = [parent];

    let auths: [tcg::TpmsAuthCommand; 1] = [auth];

    // Parameters for PolicySecretCommand command:
    // nonce
    // cpHashA
    // policyRef
    // expiration
    let params: [&dyn inout::Tpm2StructOut; 2] = [&in_private, &in_public];

    let mut resp_buff = inout::StaticByteBuffer::new();

    let ret = run::run_command(
        tpm,
        tcg::TPM_CC_LOAD,
        &handles,
        &auths,
        &params,
        &mut resp_buff,
    )?;

    let resp = LoadResponse::new(&mut resp_buff)?;
    Ok(resp.handle)
}
