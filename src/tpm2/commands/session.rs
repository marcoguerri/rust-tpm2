use crate::device;
use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use crate::tcg;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
use crate::tpm2::commands::run;
use crate::tpm2::commands::run::runCommand;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::RwBytes;
use crate::tpm2::serialization::inout::StaticByteBuffer;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::serialization::inout::Tpm2StructOut;
use crate::tpm2::types::tcg;
use std::mem;
use std::result;

// Initiates Auth session and returns TPMS_AUTH_COMMAND structure
pub fn tpm2_startauth_session(
    tpm: &mut dyn device::raw::TpmDeviceOps,
) -> result::Result<tcg::TpmsAuthCommand, errors::CommandError> {
    let mut nonce: [u8; tcg::MAX_HASH_SIZE] = [0; tcg::MAX_HASH_SIZE];
    nonce[0] = 0x01;
    nonce[1] = 0x02;
    nonce[2] = 0x03;
    nonce[3] = 0x04;
    nonce[4] = 0x04;
    nonce[5] = 0x06;
    nonce[6] = 0x07;

    let mut resp_buff = inout::StaticByteBuffer::new();

    // TPM_SE_POLICY indicates a policy session, which therefore does not
    // make use of HMAC authorization. From TPM specs:
    // The most typical use of a policy session will be with tpmKey and bind
    // both set to TPM_RH_NULL. When this option is selected, an HMAC computation
    // might not be performed when the policy session is used and the session
    // nonce and auth values may be Empty Buffers (see TPM 2.0 Part 3,
    // TPM2_PolicyAuthValue).

    // Handles for StartAuthSession command
    // tpm key
    // bind key
    let handles: [tcg::Handle; 2] = [tcg::TPM_RH_NULL, tcg::TPM_RH_NULL];

    let auths: [tcg::TpmsAuthCommand; 0] = [];

    // Parameters for StartAuthSession command:
    // nonce caller
    // encrypted salt
    // session type
    // symmetric
    // authentication hash
    let params: [&dyn Tpm2StructOut; 5] = [
        &tcg::Tpm2bDigest {
            size: 16,
            buffer: nonce,
        },
        &tcg::Tpm2bEncryptedSecret::new(),
        &tcg::TPM_SE_POLICY,
        &tcg::TpmtSymDef::new_null(),
        &tcg::TPM_ALG_SHA256,
    ];

    let ret = run::run_command(
        tpm,
        tcg::TPM_START_AUTH_SESSION,
        &handles,
        &auths,
        &params,
        &mut resp_buff,
    )?;

    let session_handle: tcg::TpmiShAuthSession = 0;
    let nonce: tcg::Tpm2bNonce = tcg::Tpm2bNonce::new();

    session_handle.unpack(&mut resp_buff)?;
    nonce.unpack(&mut resp_buff)?;

    Ok(tcg::TpmsAuthCommand {
        session_handle: session_handle,
        nonce: tcg::Tpm2bNonce::new(),
        session_attributes: tcg::TPMA_SESSION_CONTINUE_SESSION,
        hmac: tcg::Tpm2bDigest::new(),
    })
}

pub fn tpm2_policy_secret(
    tpm: &mut dyn device::raw::TpmDeviceOps,
    handle: tcg::Handle,
    auth: tcg::TpmsAuthCommand,
) -> result::Result<(), errors::CommandError> {
    let handles: [tcg::Handle; 2] = [handle, auth.session_handle];

    // We need to give an empty auth to PolicySecret, with TPM_RS_PW authorization
    // (password authorization, it's not necessary to turn it into HMAC authorization
    // TPM_RS_PW is always available and doesn't require to create an authorization
    // session.
    let auths: [tcg::TpmsAuthCommand; 1] = [tcg::TpmsAuthCommand {
        session_handle: tcg::TPM_RS_PW,
        nonce: tcg::Tpm2bNonce::new(),
        session_attributes: tcg::TPMA_SESSION_CONTINUE_SESSION,
        hmac: tcg::Tpm2bAuth::new(),
    }];

    let expiration: u32 = 0;

    // Parameters for PolicySecretCommand command:
    // nonce
    // cpHashA
    // policyRef
    // expiration
    let params: [&dyn Tpm2StructOut; 4] = [
        &tcg::Tpm2bNonce::new(),
        &tcg::Tpm2bDigest::new(),
        &tcg::Tpm2bNonce::new(),
        &expiration,
    ];

    let mut resp_buff = inout::StaticByteBuffer::new();

    let ret = run::run_command(
        tpm,
        tcg::TPM_CC_POLICY_SECRET,
        &handles,
        &auths,
        &params,
        &mut resp_buff,
    )?;

    Ok(())
}
