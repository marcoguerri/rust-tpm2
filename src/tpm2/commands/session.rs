use crate::device;
use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use crate::tcg::Handle;
use crate::tcg::Tpm2bAuth;
use crate::tcg::Tpm2bDigest;
use crate::tcg::Tpm2bEncryptedSecret;
use crate::tcg::Tpm2bNonce;
use crate::tcg::TpmSe;
use crate::tcg::TpmiAlgHash;
use crate::tcg::TpmiShAuthSession;
use crate::tcg::TpmsAuthCommand;
use crate::tcg::TpmtSymDef;
use crate::tcg::TpmuEncryptedSecret;
use crate::tcg::MAX_HASH_SIZE;
use crate::tcg::TPMA_SESSION_CONTINUE_SESSION;
use crate::tcg::TPM_ALG_NULL;
use crate::tcg::TPM_ALG_SHA256;
use crate::tcg::TPM_RH_NULL;
use crate::tcg::TPM_SE_POLICY;
use crate::tcg::TPM_START_AUTH_SESSION;
use crate::tcg::TPM_ST_NO_SESSION;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
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

#[derive(Copy, Clone, Debug)]
pub struct StartAuthSessionResponse {
    session_handle: TpmiShAuthSession,
    nonce: Tpm2bNonce,
}

impl StartAuthSessionResponse {
    pub fn new(buff: &mut dyn inout::RwBytes) -> result::Result<Self, errors::TpmError> {
        let mut resp = StartAuthSessionResponse {
            session_handle: 0x0,
            nonce: Tpm2bDigest::new(),
        };

        resp.session_handle.unpack(buff)?;
        resp.nonce.unpack(buff)?;
        Ok(resp)
    }
}

// Initiates Auth session and returns TPMS_AUTH_COMMAND structure
pub fn tpm2_startauth_session(
    tpm: &mut dyn device::raw::TpmDeviceOps,
) -> result::Result<TpmsAuthCommand, errors::TpmError> {
    let mut nonce: [u8; MAX_HASH_SIZE] = [0; MAX_HASH_SIZE];
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
    // The most typical use of a policy session will be with tpmKey and bind both set to
    // TPM_RH_NULL. When this option is selected, an HMAC computation might not be performed
    // when the policy session is used and the session nonce and auth values may be Empty Buffers
    // (see TPM 2.0 Part 3, TPM2_PolicyAuthValue). NOTE 2 When the session

    // Handles for StartAuthSession command
    // tpm key
    // bind key
    let handles: [tcg::Handle; 2] = [TPM_RH_NULL, TPM_RH_NULL];

    let auths: [tcg::TpmsAuthCommand; 0] = [];

    // Parameters for StartAuthSession command:
    // nonce caller
    // encrypted salt
    // session type
    // symmetric
    // authentication hash
    let params: [&dyn Tpm2StructOut; 5] = [
        &Tpm2bDigest {
            size: 16,
            buffer: nonce,
        },
        &Tpm2bEncryptedSecret::new(),
        &tcg::TPM_SE_POLICY,
        &TpmtSymDef::new_null(),
        &tcg::TPM_ALG_SHA256,
    ];

    let resp_code = runCommand(
        tpm,
        tcg::TPM_START_AUTH_SESSION,
        &handles,
        &auths,
        &params,
        &mut resp_buff,
    );

    match resp_code {
        Ok(retcode) => {
            if retcode != 0 {
                panic!("should not happen");
            }
        }
        Err(err) => {
            return Err(err);
        }
    }

    let resp = StartAuthSessionResponse::new(&mut resp_buff);
    match resp {
        Ok(resp) => {
            println!("start auth response {:?}", resp);
            println!("session handle {:02x?}", resp.session_handle);
            Ok(TpmsAuthCommand {
                session_handle: resp.session_handle,
                nonce: Tpm2bNonce::new(),
                session_attributes: TPMA_SESSION_CONTINUE_SESSION,
                hmac: Tpm2bDigest::new(),
            })
        }
        Err(err) => Err(err),
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PolicySecretCommand {
    pub nonce: Tpm2bNonce,
    pub cpHashA: Tpm2bDigest,
    pub policyRef: Tpm2bNonce,
    pub expiration: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct PolicySecretResponse {}

impl inout::Tpm2StructOut for PolicySecretCommand {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.nonce.pack(buff);
        self.cpHashA.pack(buff);
        self.policyRef.pack(buff);
        self.expiration.pack(buff);
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PolicySecret {
    pub header: CommandHeader,
    pub entityHandle: Handle,
    pub policySession: TpmiShAuthSession,
    // ----
    pub auth: TpmsAuthCommand,
    // ---
    pub command: PolicySecretCommand,
}

impl inout::Tpm2StructOut for PolicySecret {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.header.pack(buff);
        self.entityHandle.pack(buff);
        self.policySession.pack(buff);

        let mut buff_auth = inout::StaticByteBuffer::new();
        self.auth.pack(&mut buff_auth);

        let size_auth: u32 = buff_auth.to_bytes().len() as u32;

        size_auth.pack(buff);
        self.auth.pack(buff);
        self.command.pack(buff);
    }
}

pub fn tpm2_policy_secret(handle: Handle, auth: TpmsAuthCommand) {
    let body = PolicySecretCommand {
        nonce: Tpm2bNonce::new(),
        cpHashA: Tpm2bDigest::new(),
        policyRef: Tpm2bNonce::new(),
        expiration: 0,
    };

    let mut buff = inout::StaticByteBuffer::new();

    let mut resp_buff = inout::StaticByteBuffer::new();

    // We need to give an empty auth to PolicySecret, with TPM_RS_PW authorization
    // (password authorization, it's not necessary to turn it into HMAC authorization
    // TPM_RS_PW is always available and doesn't require to create an authorization
    // session.
    let mut policy_secret = PolicySecret {
        header: CommandHeader {
            // Why does this necessarily need to have authorizaionSize?
            tag: tcg::TPM_ST_SESSIONS,
            command_size: (10 + buff.to_bytes().len()) as u32,
            command_code: tcg::TPM_CC_POLICY_SECRET,
        },
        entityHandle: handle,
        policySession: auth.session_handle,
        auth: TpmsAuthCommand {
            session_handle: tcg::TPM_RS_PW,
            nonce: Tpm2bNonce::new(),
            session_attributes: TPMA_SESSION_CONTINUE_SESSION,
            hmac: Tpm2bAuth::new(),
        },
        command: body,
    };

    let mut tpm_device: raw::TpmDevice = raw::TpmDevice {
        rw: &mut tcp::TpmSwtpmIO::new(),
    };

    let mut buff_policy_secret = inout::StaticByteBuffer::new();
    policy_secret.pack(&mut buff_policy_secret);
    policy_secret.header.command_size = buff_policy_secret.to_bytes().len() as u32;

    let mut buff_policy_secret_new = inout::StaticByteBuffer::new();
    policy_secret.pack(&mut buff_policy_secret_new);

    println!(
        "policy secret buffer {:x?}",
        buff_policy_secret_new.to_bytes()
    );

    let mut resp_buff = inout::StaticByteBuffer::new();

    println!(
        "policy secret buffer {:x?}",
        buff_policy_secret_new.to_bytes().len()
    );

    match tpm_device.send_recv(&mut buff_policy_secret_new, &mut resp_buff) {
        Err(err) => {
            panic!("error");
        }
        _ => (),
    }
    println!("policy secret response buffer {:x?}", resp_buff.to_bytes());
}
