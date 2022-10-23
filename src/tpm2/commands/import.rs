use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use std::net::{Shutdown, TcpStream};

use crate::device::tcp;
use crate::tcg::TPMA_SESSION_CONTINUE_SESSION;
use crate::tpm2::commands::session::PolicySecret;
use crate::tpm2::commands::session::PolicySecretCommand;
use crate::tpm2_policy_secret;
use crate::tpm2_startauth_session;
use std::{thread, time::Duration};

use crate::tcg::Handle;
use crate::tcg::Tpm2bAuth;
use crate::tcg::Tpm2bData;
use crate::tcg::Tpm2bDigest;
use crate::tcg::Tpm2bEncryptedSecret;
use crate::tcg::Tpm2bNonce;
use crate::tcg::Tpm2bPrivate;
use crate::tcg::Tpm2bPublic;
use crate::tcg::TpmsAuthCommand;
use crate::tcg::TpmtSymDefObject;
use crate::tcg::TPM_ALG_NULL;
use crate::tcg::TPM_ST_SESSIONS;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::RwBytes;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::serialization::inout::Tpm2StructOut;
use crate::tpm2::types::tcg;
use pem::parse;
use rsa;
use rsa::pkcs8::DecodePublicKey;
use std::result;

/*

* TPM2B_DATA: the optional symmetric encryption key used as the inner wrapper. Could be very well
* null at this point
* TPM2B_PUBLIC: the public area of the object to be imported
* TPM2B_PRIVATE: symmetrically encrypted duplicate object that may contain an inner symmetric
* wrapper. This is used to decrypt the inner blob. The TPMT_SYM_DEF_OBJECT defines the
* symmetric algorithm used for the inner wrapper.
*
* TPM2B_ENCRYPTED_SECRET: the seed of the symmetric key and HMAC key:
*   if this is specified, the asymmetric parameters and private key of parentHandle are used to
*   recover the seed. So, the seed shoulD BE ENCRYpted with the parentHandle asymmetric parameters.
*   The symmetric key obtained is used to decrypt the data blob.
* TPMT_SYM_DEF_OBJECT: definition for the symmetric algorithm to use for the inner wrapper
*
*
* Rough outline of TPM2_Import algorithm:
*
* if TPMT_SYM_DEF_OBJECT is not null
    TPM2B_DATA contains the encryption key for the inner wrapper
* TPM2B_ENCRYPTED_SECRET inSymSeed is the seed for the outer wrapper, which is encrpyted with the parent,
* which must be able to do key exhange (so, the parent object cannot be a Symmetric algorithM)
* The inSymSeed is decrypted with parent object.
* Compute then the name of TPM2B_PUBLIC object, based on the public area.
* Use inSymSeed to generate private key to retrieve content of TPM2B_PRIVATE. If an inner wrapper
* was specified, the the object needs to be further encrypted with TPM2B_DATA from
* TPMT_SYM_DEF_OBJECT
*/

/*
 *
 * Steps to be implemented:
 * Create public area of the object to be importated
 * Create private area, i.e. TPM2B_PRIVATE
 * Create RSA or ECC seed based on EK type. The seed needs to be encrypted with EK public key
 * Create duplicate object, i.e. TPM2B_PRIVATE
 * Encrypt the secret using the symmetric seed, obtaining TPM2B_ENCRYPTED_SECRET
 * Create HMAC over the encrypted secret, and the name built over the public area
 * Profit
 *
 * */

const SAMPLE: &'static str = "
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArHW0IdnSJFdPzCdfdYSG
XEfZmvj2FjNgcrwlR9dT3yu8YPpo6dHu6clYucsRsfAUoFeFxHEaBEJKECcqua8R
ZxOAb9zn9f2NvX/KNpEJCmrrgNZxd4A6B1nV3YIY5MQlV7CAWsXT4jsnRdzTJJkw
ZkwYv2jWJagEeb0Ba9P+YfSvBlHWYNqMAR0cMLccd0grScw31Z4EWCfnMoceJR5X
gFp4xbXxCvO9JnRRHK9mJMK9SZtcUHZ3utaNoDoTspcf8SF7TOBYhwJttuCVoHhj
sGKcOHvV2pXdaBTpAGb8djNWpvGBlYWps7OY6So7NZoY0aHqTGD/ROEutO/sxltA
qQIDAQAB
-----END PUBLIC KEY-----";

#[derive(Copy, Clone, Debug)]
pub struct ImportCommand {
    encryption_key: Tpm2bData,
    public: Tpm2bPublic,
    duplicate: Tpm2bPrivate,
    symseed: Tpm2bEncryptedSecret,
    alg: TpmtSymDefObject,
}

impl inout::Tpm2StructOut for ImportCommand {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.encryption_key.pack(buff);
        println!("so far buffer is after enc key {:02x?}", buff.to_bytes());
        self.public.pack(buff);
        println!("so far buffer is after public {:02x?}", buff.to_bytes());
        self.duplicate.pack(buff);
        println!("so far buffer is after duplicate {:02x?}", buff.to_bytes());
        self.symseed.pack(buff);
        println!("so far buffer is after symseed {:02x?}", buff.to_bytes());
        self.alg.pack(buff);
        println!("so far buffer is after alg {:02x?}", buff.to_bytes());
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Import {
    header: CommandHeader,
    handle: Handle,
    auth: TpmsAuthCommand,
    command: ImportCommand,
}

impl inout::Tpm2StructOut for Import {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.header.pack(buff);

        self.handle.pack(buff);
        let mut auth_buffer = inout::StaticByteBuffer::new();

        self.auth.pack(&mut auth_buffer);

        let size_auth: u32 = auth_buffer.to_bytes().len() as u32;
        println!("setting size_auth to {:?}", size_auth);
        println!("so far buffer is before auth {:02x?}", buff.to_bytes());
        size_auth.pack(buff);

        buff.write_bytes(auth_buffer.to_bytes());

        println!("so far buffer after auth is {:02x?}", buff.to_bytes());
        self.command.pack(buff);

        println!("so far buffer is {:02x?}", buff.to_bytes());
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ImportResponse {
    header: ResponseHeader,
    out_private: Tpm2bPrivate,
}

impl inout::Tpm2StructIn for ImportResponse {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.header.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        let mut paramSize: u32 = 0;

        paramSize.unpack(buff);

        match self.out_private.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        Ok(())
    }
}
impl ImportResponse {
    pub fn new(buff: &mut dyn inout::RwBytes) -> result::Result<Self, errors::TpmError> {
        let mut resp = ImportResponse {
            header: ResponseHeader::new(),
            out_private: Tpm2bPrivate::new(),
        };

        let unpack_result = resp.unpack(buff);
        match unpack_result {
            Ok(_) => Ok(resp),
            Err(error) => Err(error),
        }
    }
}

pub fn tpm2_import(parent_handle: Handle, auth: TpmsAuthCommand) {
    println!("importing with parent_handle {:02x?}", parent_handle);

    let pem_result = parse(SAMPLE);
    match pem_result {
        Ok(_) => (),
        Err(err) => panic!("pem error"),
    }
    let pem = pem_result.unwrap();
    println!("{}", pem.tag);

    let public_key_result = rsa::RsaPublicKey::from_public_key_pem(SAMPLE);
    match public_key_result {
        Ok(_) => (),
        Err(rr) => panic!("pem error"),
    }
    let public_key = public_key_result.unwrap();

    let secret = "secret data";

    // Create TpmtSensitive, based on the secret provided. This will be used
    // for the creation of `duplicate`.
    let sensitive = tcg::TpmtSensitive::new(secret.as_bytes());

    // Create the TPMT_PUBLIC from the sensitive object
    let public = tcg::TpmtPublic::new_data_object(&sensitive);

    tcg::kdfa(
        &[
            0xda, 0x82, 0xeb, 0x71, 0xb1, 0x8c, 0xb9, 0xae, 0xfc, 0x9c, 0x88, 0xa5, 0xff, 0x03,
            0x01, 0x6f, 0x12, 0xd1, 0x74, 0x0b, 0x05, 0x78, 0x21, 0xcd, 0xff, 0x9e, 0xac, 0xba,
            0xb7, 0xbd, 0xd3, 0xc9,
        ],
        "STORAGE".as_bytes(),
        &[
            0x00, 0x0b, 0x8c, 0xca, 0x34, 0xd8, 0xb9, 0xf4, 0xae, 0xbe, 0xe7, 0x91, 0xf8, 0xd0,
            0xa4, 0xdf, 0xcf, 0xc2, 0x2f, 0x20, 0x87, 0xc1, 0xc9, 0xfa, 0x4c, 0x79, 0xb5, 0xa0,
            0x8b, 0x27, 0xcf, 0x8a, 0xd6, 0x59,
        ],
        &[],
        128,
    );

    let mut enc_seed: Tpm2bEncryptedSecret = Tpm2bEncryptedSecret::new();

    // Create the duplicate (TPM2B_PRIVATE) object based on the sensitive content
    let duplicate = tcg::Tpm2bPrivate::new_duplicate(&public_key, sensitive, public, &mut enc_seed);

    let mut buff_public = inout::StaticByteBuffer::new();
    public.pack(&mut buff_public);

    let import_command = ImportCommand {
        encryption_key: Tpm2bData {
            size: 0,
            buffer: [0; 1024],
        },
        public: Tpm2bPublic {
            size: buff_public.to_bytes().len() as u16,
            public: public,
        },
        duplicate: duplicate,
        symseed: enc_seed,
        alg: TpmtSymDefObject::new_null(),
    };

    let mut buff_import_command = inout::StaticByteBuffer::new();

    parent_handle.pack(&mut buff_import_command);

    let mut buff_auth = inout::StaticByteBuffer::new();
    auth.pack(&mut buff_auth);

    let size_auth: u32 = buff_auth.to_bytes().len() as u32;

    size_auth.pack(&mut buff_import_command);
    buff_import_command.write_bytes(buff_auth.to_bytes());

    import_command.pack(&mut buff_import_command);

    let import = Import {
        header: CommandHeader {
            tag: TPM_ST_SESSIONS,
            command_size: (buff_import_command.to_bytes().len() + 10) as u32,
            command_code: tcg::TPM_CC_IMPORT,
        },
        handle: parent_handle,
        auth: auth,
        command: import_command,
    };

    println!("import buffer {:02x?}", import);

    let mut buff_import = inout::StaticByteBuffer::new();

    import.pack(&mut buff_import);
    let mut resp_buff = inout::StaticByteBuffer::new();

    let mut stream = tcp::TpmSwtpmIO::new();

    let mut tpm_device: raw::TpmDevice = raw::TpmDevice { rw: &mut stream };

    println!(
        "sending buffer import {:02x?}, len {:?}",
        buff_import.to_bytes(),
        buff_import.to_bytes().len()
    );

    match tpm_device.send_recv(&mut buff_import, &mut resp_buff) {
        Err(err) => {
            panic!("error");
        }
        _ => (),
    }

    let ir: ImportResponse;

    let resp = ImportResponse::new(&mut resp_buff);
    match resp {
        Ok(import_response) => {
            ir = import_response;
            println!("import response {:?}", import_response);
        }
        Err(err) => {
            panic!("error");
        }
    }
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
        entityHandle: 0x4000000B,
        policySession: auth.session_handle,
        auth: TpmsAuthCommand {
            session_handle: tcg::TPM_RS_PW,
            nonce: Tpm2bNonce::new(),
            session_attributes: TPMA_SESSION_CONTINUE_SESSION,
            hmac: Tpm2bAuth::new(),
        },
        command: body,
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
    println!("size out_private: {:x?}", ir.out_private);
    println!("size import public: {:x?}", import_command.public);

    let mut load = LoadCommand {
        header: CommandHeader {
            tag: TPM_ST_SESSIONS,
            command_size: 0,
            command_code: tcg::TPM_CC_LOAD,
        },
        handle: parent_handle,
        auth: auth,
        inPrivate: ir.out_private,
        inPublic: import_command.public,
    };

    let mut buff_load = inout::StaticByteBuffer::new();
    let mut load_resp = inout::StaticByteBuffer::new();

    load.pack(&mut buff_load);
    load.header.command_size = buff_load.to_bytes().len() as u32;

    let mut buff_load_new = inout::StaticByteBuffer::new();
    load.pack(&mut buff_load_new);

    println!("load buffer {:02x?}", buff_load.to_bytes());
    println!("load buffer size {:02x?}", load.header.command_size);

    match tpm_device.send_recv(&mut buff_load_new, &mut load_resp) {
        Err(err) => {
            panic!("error");
        }
        _ => (),
    }

    println!("load response {:02x?}", load_resp.to_bytes());

    let mut lr: LoadResponse;

    let load_response = LoadResponse::new(&mut load_resp);
    match load_response {
        Ok(resp) => {
            lr = resp;
            println!("load response {:02x?}", load_response);
        }
        Err(err) => {
            panic!("error");
        }
    }

    // One one TCP session at a time possible
    stream.stream.expect("no stream").shutdown(Shutdown::Both);

    let mut new_stream = tcp::TpmSwtpmIO::new();

    tpm_device = raw::TpmDevice {
        rw: &mut new_stream,
    };
    // This is unnecessary. Just use emptyAuth
    let unseal_session = tpm2_startauth_session(&mut tpm_device);

    let mut unseal = UnsealCommand {
        header: CommandHeader {
            tag: TPM_ST_SESSIONS,
            command_size: 0,
            command_code: tcg::TPM_CC_UNSEAL,
        },
        handle: lr.handle,
        auth: TpmsAuthCommand {
            session_handle: tcg::TPM_RS_PW,
            nonce: Tpm2bNonce::new(),
            session_attributes: TPMA_SESSION_CONTINUE_SESSION,
            hmac: Tpm2bAuth::new(),
        },
    };

    let mut buff_unseal = inout::StaticByteBuffer::new();
    unseal.pack(&mut buff_unseal);

    unseal.header.command_size = buff_unseal.to_bytes().len() as u32;

    let mut buff_unseal_new = inout::StaticByteBuffer::new();
    unseal.pack(&mut buff_unseal_new);

    println!(
        "unseal command structure {:02x?}",
        buff_unseal_new.to_bytes()
    );

    let mut unseal_response_buff = inout::StaticByteBuffer::new();

    match tpm_device.send_recv(&mut buff_unseal_new, &mut unseal_response_buff) {
        Err(err) => {
            panic!("error");
        }
        _ => (),
    }

    let mut unseal_response: UnsealResponse = UnsealResponse {
        header: ResponseHeader::new(),
        data: Tpm2bData {
            size: 0,
            buffer: [0; 1024],
        },
    };
    unseal_response.unpack(&mut unseal_response_buff);

    println!("unseal response structure {:02x?}", unseal_response);

    println!("unseal response {:02x?}", unseal_response_buff.to_bytes());
}

#[derive(Copy, Clone, Debug)]
pub struct LoadCommand {
    header: CommandHeader,
    handle: Handle,
    auth: TpmsAuthCommand,
    inPrivate: Tpm2bPrivate,
    inPublic: Tpm2bPublic,
}

impl inout::Tpm2StructOut for LoadCommand {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.header.pack(buff);
        self.handle.pack(buff);

        let mut auth_buffer = inout::StaticByteBuffer::new();
        self.auth.pack(&mut auth_buffer);

        let size_auth: u32 = auth_buffer.to_bytes().len() as u32;
        size_auth.pack(buff);

        buff.write_bytes(auth_buffer.to_bytes());
        self.inPrivate.pack(buff);
        self.inPublic.pack(buff);
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LoadResponse {
    header: ResponseHeader,
    handle: Handle,
    name: Tpm2bDigest,
}

impl inout::Tpm2StructIn for LoadResponse {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.header.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        self.handle.unpack(buff);

        let mut paramSize: u32 = 0;
        paramSize.unpack(buff);

        self.name.unpack(buff);

        Ok(())
    }
}

impl LoadResponse {
    pub fn new(buff: &mut dyn inout::RwBytes) -> result::Result<Self, errors::TpmError> {
        let mut resp = LoadResponse {
            header: ResponseHeader::new(),
            handle: 0,
            name: Tpm2bDigest::new(),
        };

        let unpack_result = resp.unpack(buff);
        match unpack_result {
            Ok(_) => Ok(resp),
            Err(error) => Err(error),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct UnsealCommand {
    header: CommandHeader,
    handle: Handle,
    auth: TpmsAuthCommand,
}

impl inout::Tpm2StructOut for UnsealCommand {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.header.pack(buff);
        self.handle.pack(buff);

        let mut auth_buff = inout::StaticByteBuffer::new();

        self.auth.pack(&mut auth_buff);

        let size_auth: u32 = auth_buff.to_bytes().len() as u32;
        size_auth.pack(buff);

        self.auth.pack(buff);
    }
}

#[derive(Copy, Clone, Debug)]
pub struct UnsealResponse {
    header: ResponseHeader,
    data: Tpm2bData,
}

impl inout::Tpm2StructIn for UnsealResponse {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.header.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        self.data.unpack(buff);
        Ok(())
    }
}
