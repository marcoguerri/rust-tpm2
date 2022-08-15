use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use std::{thread, time::Duration};

use crate::tcg::Handle;
use crate::tcg::Tpm2bData;
use crate::tcg::Tpm2bEncryptedSecret;
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
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqxsrFgeyHMRV/HjmOQJ7
QQrIf7Lv2Cl1ZR5lEoWSawNau1URHUqs1A2m1PhzcNGSsRvRbOKC7amV/6kOX1Z6
wg7disM80pIGXdFvpizk5bx+1R6HavO5y1iUyRG2VYeshdW7JV97njC8mYdwEDWc
83DNQG5qddSXksADfse6nb8E2zmR+/tjWRxOFCoFAk8XlCTQjFyjEMcYweapbgXM
PL9aI+W9wqaRc7GSHlttzhNxZLz+vicrGBv4l0VvtVG8mghbSU6nwGL/6uLnCWHM
SvNhF6DkppqncLYCmArRUIOcvcaXXPSzADV5fwOgbYyThIZih6NKzRpgkc9dskw6
JwIDAQAB
-----END PUBLIC KEY-----
";

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

    let mut enc_seed: Tpm2bEncryptedSecret = Tpm2bEncryptedSecret::new_empty();

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

    let mut tpm_device: raw::TpmDevice = raw::TpmDevice {
        rw: &mut tcp::TpmSwtpmIO::new(),
    };

    println!(
        "sending buffer import {:02x?}, len {:?}",
        buff_import.to_bytes(),
        buff_import.to_bytes().len()
    );

    thread::sleep(Duration::from_millis(10000));

    match tpm_device.send_recv(&mut buff_import, &mut resp_buff) {
        Err(err) => {
            panic!("error");
        }
        _ => (),
    }

    let resp = ImportResponse::new(&mut resp_buff);
    match resp {
        Ok(import_response) => {
            println!("import response {:?}", import_response);
        }
        Err(err) => {
            panic!("error");
        }
    }
}
