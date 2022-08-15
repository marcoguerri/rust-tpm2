use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use crate::tcg::Handle;
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
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::RwBytes;
use crate::tpm2::serialization::inout::StaticByteBuffer;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::serialization::inout::Tpm2StructOut;
use std::mem;
use std::result;

#[derive(Copy, Clone, Debug)]
pub struct StartAuthSessionCommand {
    // determines how the value of encyprtedSalt is encrypted. The decrypted secret value
    // is used to compute the session key. tpmKey could be TPM_RH_NULL and encryptedSalt
    // could be Empty Buffer
    tpm_key: Handle,
    bind_key: Handle,
    nonce_caller: Tpm2bNonce,
    encrypted_salt: Tpm2bEncryptedSecret,
    session_type: TpmSe,
    symmetric: TpmtSymDef,
    auth_hash: TpmiAlgHash,
}

impl inout::Tpm2StructOut for StartAuthSessionCommand {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.tpm_key.pack(buff);
        self.bind_key.pack(buff);
        self.nonce_caller.pack(buff);
        self.encrypted_salt.pack(buff);
        self.session_type.pack(buff);
        self.symmetric.pack(buff);
        self.auth_hash.pack(buff);
    }
}

#[derive(Copy, Clone, Debug)]
pub struct StartAuthSession {
    header: CommandHeader,
    command: StartAuthSessionCommand,
}

impl inout::Tpm2StructOut for StartAuthSession {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.header.pack(buff);
        self.command.pack(buff);
    }
}

#[derive(Copy, Clone, Debug)]
pub struct StartAuthSessionResponse {
    header: ResponseHeader,
    session_handle: TpmiShAuthSession,
    nonce: Tpm2bNonce,
}

impl StartAuthSessionResponse {
    pub fn new(buff: &mut dyn inout::RwBytes) -> result::Result<Self, errors::TpmError> {
        let mut resp = StartAuthSessionResponse {
            header: ResponseHeader::new(),
            session_handle: 0x0,
            nonce: Tpm2bDigest::new(),
        };

        let unpack_result = resp.unpack(buff);
        match unpack_result {
            Ok(_) => Ok(resp),
            Err(error) => Err(error),
        }
    }
}

impl inout::Tpm2StructIn for StartAuthSessionResponse {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.header.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        match self.session_handle.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        match self.nonce.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        Ok(())
    }
}

// Initiates Auth session and returns TPMS_AUTH_COMMAND structure
pub fn tpm2_startauth_session() -> TpmsAuthCommand {
    let mut nonce: [u8; MAX_HASH_SIZE] = [0; MAX_HASH_SIZE];

    nonce[0] = 0x01;
    nonce[1] = 0x02;
    nonce[2] = 0x03;
    nonce[3] = 0x04;
    nonce[4] = 0x04;
    nonce[5] = 0x06;
    nonce[6] = 0x07;

    let mut buff = inout::StaticByteBuffer::new();

    let body = StartAuthSessionCommand {
        tpm_key: TPM_RH_NULL,
        bind_key: TPM_RH_NULL,
        nonce_caller: Tpm2bDigest {
            size: 16,
            buffer: nonce,
        },
        encrypted_salt: Tpm2bEncryptedSecret {
            size: 0,
            secret: [0; mem::size_of::<TpmuEncryptedSecret>()],
        },
        // This is going to be a policy session, which therefore does not
        // make use of HMAC authorization.
        // From TPM specs:
        // The most typical use of a policy session will be with tpmKey and bind both set to
        // TPM_RH_NULL. When this option is selected, an HMAC computation might not be performed
        // when the policy session is used and the session nonce and auth values may be Empty Buffers
        // (see TPM 2.0 Part 3, TPM2_PolicyAuthValue). NOTE 2 When the session
        session_type: TPM_SE_POLICY,
        symmetric: TpmtSymDef::new_null(),
        auth_hash: TPM_ALG_SHA256,
    };
    body.pack(&mut buff);
    println!("body size {:?}", buff.to_bytes().len());
    println!("command header size {:?}", mem::size_of::<CommandHeader>());

    let auth_command = StartAuthSession {
        header: CommandHeader {
            tag: TPM_ST_NO_SESSION,
            command_size: (10 + buff.to_bytes().len()) as u32,
            command_code: TPM_START_AUTH_SESSION,
        },
        command: body,
    };

    println!("auth command {:?}", auth_command);

    let mut buff_start_auth = inout::StaticByteBuffer::new();
    auth_command.pack(&mut buff_start_auth);

    println!("auth start buffer {:x?}", buff_start_auth.to_bytes());

    let mut resp_buff = inout::StaticByteBuffer::new();

    let mut tpm_device: raw::TpmDevice = raw::TpmDevice {
        rw: &mut tcp::TpmSwtpmIO::new(),
    };

    match tpm_device.send_recv(&mut buff_start_auth, &mut resp_buff) {
        Err(err) => {
            panic!("error");
        }
        _ => (),
    }
    let resp = StartAuthSessionResponse::new(&mut resp_buff);
    match resp {
        Ok(start_auth_response) => {
            println!("start auth response {:?}", start_auth_response);
            // From the documentation:
            // Regardless of the setting of the adminWithPolicy attribute, operations that require ADMIN role
            // authorization may be provided by a policy session that satisfies the object's authPolicy.
            // For TPM2_Import, there should be not need for ADMIN authorization. Therefore for the time
            // being we can just returns a TpmsAuthCommand that contains the session handle and
            // continue session attribute
            //
            println!("session handle {:02x?}", start_auth_response.session_handle);
            TpmsAuthCommand {
                session_handle: start_auth_response.session_handle,
                nonce: Tpm2bNonce {
                    size: 0,
                    buffer: [0; 64],
                },
                session_attributes: TPMA_SESSION_CONTINUE_SESSION,
                hmac: Tpm2bDigest {
                    size: 0,
                    buffer: [0; 64],
                },
            }
        }
        Err(err) => {
            panic!("error");
        }
    }
}
