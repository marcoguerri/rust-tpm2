use crate::tpm2::errors;
use std::mem;
use std::result;

use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::RwBytes;

use aes;
use aes::cipher::{AsyncStreamCipher, KeyIvInit};

use byteorder::{BigEndian, ByteOrder};

use crate::tpm2::serialization::inout::Tpm2StructOut;
use sha2::{Digest, Sha256};

use hmac::{Hmac, Mac};

use num_traits::ToPrimitive;
use rand::rngs::OsRng;
use std::fmt;
use std::str;

use rand;
use rand::Rng;
use rsa;
use rsa::PaddingScheme;
use rsa::PublicKey;
use rsa::PublicKeyParts;

// Types
pub type TpmiStCommandTag = u16;
pub type TpmCc = u32;
pub type TpmRc = u32;
pub type TpmAlgId = u16;
pub type TpmSu = u16;
pub type TpmaObject = u32;
pub type TpmaSession = u8;
pub type TpmKeyBits = u16;

pub type Handle = u32;

pub type TpmiShAuthSession = Handle;

pub const TPM_RH_NULL: Handle = 0x40000007;
pub const TPM_RS_PW: Handle = 0x40000009;
pub const TPM_RH_ENDORSEMENT: Handle = 0x4000000B;

pub const TPMA_SESSION_CONTINUE_SESSION: TpmaSession = 0x1;

// Derived types
pub type TpmiAlgPublic = TpmAlgId;
pub type TpmiAlgHash = TpmAlgId;
pub type TpmiAlgKdf = TpmAlgId;
pub type TpmiAlgRsaScheme = TpmAlgId;
pub type TpmiAlgSym = TpmAlgId;
pub type TpmiAlgSymObject = TpmAlgId;
pub type TpmiAlgSymMode = TpmAlgId;

pub type TpmiAlgKeyedHashScheme = TpmAlgId;

pub type TpmiRsaKeyBits = TpmKeyBits;

pub type TpmSe = u8;

pub const TPM_SE_HMAC: TpmSe = 0x00;
pub const TPM_SE_POLICY: TpmSe = 0x01;
pub const TPM_SE_TRIAL: TpmSe = 0x03;

// TPM2 command codes
pub const TPM_CC_PCR_READ: TpmCc = 0x0000017E;
pub const TPM_CC_STARTUP: TpmCc = 0x00000144;
pub const TPM_CC_IMPORT: TpmCc = 0x00000156;
pub const TPM_CC_UNSEAL: TpmCc = 0x0000015E;
pub const TPM_CC_POLICY_SECRET: TpmCc = 0x00000151;
pub const TPM_START_AUTH_SESSION: TpmCc = 0x00000176;
pub const TPM_CC_LOAD: TpmCc = 0x00000157;

pub const TPM2_NUM_PCR_BANKS: usize = 16;
pub const TPM2_MAX_PCRS: usize = 24;
pub const HASH_SIZE: usize = 512;
pub const RSA_KEY_NAX_NUM_BYTES: usize = 256;
pub const TPM2_PCR_SELECT_MAX: usize = (TPM2_MAX_PCRS + 7) / 8;
pub const MAX_SYM_DATA: usize = 128;
pub const RSA_KEY_NUM_BYTES: usize = 2048;
pub const MAX_SEED_LEN: usize = 32;

// TPM2 startup types
pub const TPM_SU_CLEAR: TpmSu = 0x0000;
pub const TPM_SU_STATE: TpmSu = 0x0001;

// Command tags
pub const TPM_ST_NO_SESSION: TpmiStCommandTag = 0x8001;
pub const TPM_ST_SESSIONS: TpmiStCommandTag = 0x8002;

// Algorithms
pub const TPM_ALG_NULL: TpmAlgId = 0x0010;
pub const TPM_ALG_SHA256: TpmAlgId = 0x000B;
pub const TPM_ALG_KEYEDHASH: TpmAlgId = 0x0008;
pub const TPM_ALG_SYMCIPHER: TpmAlgId = 0x0025;
pub const TPM_ALG_RSA: TpmAlgId = 0x0001;
pub const TPM_ALG_RSASSA: TpmAlgId = 0x0014;
pub const TPM_ALG_ECC: TpmAlgId = 0x0023;
pub const TPM_ALG_AES: TpmAlgId = 0x0006;
pub const TPM_ALG_CFB: TpmAlgId = 0x0043;

// MAX_HASH_SIZE represents the size of the longest hash digest supported (sha512)
pub const MAX_HASH_SIZE: usize = 64;

// TPM2B_DIGEST
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bDigest {
    pub size: u16,
    pub buffer: [u8; MAX_HASH_SIZE],
}

impl inout::Tpm2StructOut for Tpm2bDigest {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.size.pack(buff);
        buff.write_bytes(&self.buffer[0..self.size as usize]);
    }
}

impl inout::Tpm2StructIn for Tpm2bDigest {
    fn unpack(
        &mut self,
        buff: &mut dyn inout::RwBytes,
    ) -> result::Result<(), errors::DeserializationError> {
        self.size.unpack(buff)?
        self.buffer[0..self.size as usize].clone_from_slice(buff.read_bytes(self.size as usize));
        Ok(())
    }
}

// Structures defined as TPM2B_DIGEST
pub type Tpm2bAuth = Tpm2bDigest;
pub type Tpm2bNonce = Tpm2bDigest;

impl Tpm2bDigest {
    pub fn new() -> Self {
        Tpm2bDigest {
            size: 0,
            buffer: [0; MAX_HASH_SIZE],
        }
    }
    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer[..]
    }

    pub fn from_vec(size: u16, buffer: &[u8]) -> Self {
        let mut digest_buffer = [0; MAX_HASH_SIZE];
        digest_buffer[0..size as usize].clone_from_slice(buffer);
        Tpm2bDigest {
            size: size,
            buffer: digest_buffer,
        }
    }
}

// TPML_DIGEST
pub struct TpmlDigest {
    count: u32,
    // digests can contain at most 8 entries. From TPM 2.0 Spec, Structures,
    // TPML_DIGEST is defined as digests[count]{:8}
    digests: [Tpm2bDigest; 8],
}

impl TpmlDigest {
    pub fn new() -> Self {
        TpmlDigest {
            count: 0,
            digests: [Tpm2bDigest::new(); 8],
        }
    }
    pub fn get_digest(
        &self,
        num: u32,
    ) -> result::Result<&Tpm2bDigest, errors::TpmStructFormatError> {
        if num >= self.count {
            return Err(errors::TpmStructFormatError {
                msg: String::from(format!(
                    "digest {} is > than available digests {}",
                    num, self.count
                )),
            });
        }
        Ok(&self.digests[num as usize])
    }

    pub fn num_digests(&self) -> u32 {
        return self.count;
    }
}

// TPMS_PCR_SELECTION
#[derive(Copy, Clone, Default, Debug)]
pub struct TpmsPcrSelection {
    pub hash: TpmAlgId,
    pub sizeof_select: u8,
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX],
}

impl TpmsPcrSelection {
    pub fn new() -> Self {
        TpmsPcrSelection {
            hash: 0,
            sizeof_select: 0,
            pcr_select: [0; TPM2_PCR_SELECT_MAX],
        }
    }
}

impl inout::Tpm2StructOut for TpmsPcrSelection {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.hash.pack(buff);
        self.sizeof_select.pack(buff);
        buff.write_bytes(&self.pcr_select);
    }
}

impl inout::Tpm2StructIn for TpmsPcrSelection {
    fn unpack(
        &mut self,
        buff: &mut dyn inout::RwBytes,
    ) -> result::Result<(), errors::DeserializationError> {
        self.hash.unpack(buff)?
        self.sizeof_select.unpack(buff)?
        self.pcr_select
            .clone_from_slice(buff.read_bytes(self.sizeof_select as usize));
        Ok(())
    }
}

impl inout::Tpm2StructIn for TpmlDigest {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::DeserializationError> {
        self.count.unpack(buff)?
        for _pcr_count in 0..self.count {
            let mut size: u16 = 0;
            size.unpack(buff)?
            let buffer = buff.read_bytes(size as usize);
            self.digests[_pcr_count as usize] = Tpm2bDigest::from_vec(size, buffer);
        }
        Ok(())
    }
}

// TPML_PCR_SELECTION
#[derive(Default, Debug, Copy, Clone)]
pub struct TpmlPcrSelection {
    pub count: u32,
    pub pcr_selections: [TpmsPcrSelection; TPM2_NUM_PCR_BANKS],
}

impl TpmlPcrSelection {
    pub fn new() -> Self {
        TpmlPcrSelection {
            count: 0,
            pcr_selections: [TpmsPcrSelection::new(); TPM2_NUM_PCR_BANKS],
        }
    }
}

impl inout::Tpm2StructOut for TpmlPcrSelection {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.count.pack(buff);
        let mut count = 0;
        for pcr_selection in self.pcr_selections.iter() {
            if count >= self.count {
                break;
            }
            pcr_selection.pack(buff);
            count += 1;
        }
    }
}

impl inout::Tpm2StructIn for TpmlPcrSelection {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::DeserializationError> {
        self.count.unpack(buff)?
        for _pcr_count in 0..self.count {
            let mut pcr_selection: TpmsPcrSelection = Default::default();
            pcr_selection.unpack(buff)?
            self.pcr_selections[_pcr_count as usize] = pcr_selection;
        }
        Ok(())
    }
}

// TPMU_ENCRYPTED_SECRET
#[derive(Copy, Clone)]
pub union TpmuEncryptedSecret {
    ecc: [u8; mem::size_of::<TpmsEccPoint>()],
    rsa: [u8; RSA_KEY_NAX_NUM_BYTES],
    symmetric: [u8; mem::size_of::<Tpm2bDigest>()],
    keyed_hash: [u8; mem::size_of::<Tpm2bDigest>()],
}

// TPM2B_ENCRYPTED_SECRET
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bEncryptedSecret {
    pub size: u16,
    // Secret size is defined as the mexium size held by a TpmuEncryptedSecret structure
    pub secret: [u8; mem::size_of::<TpmuEncryptedSecret>()],
}

impl Tpm2bEncryptedSecret {
    pub fn new() -> Self {
        Tpm2bEncryptedSecret {
            size: 0,
            secret: [0; mem::size_of::<TpmuEncryptedSecret>()],
        }
    }
}

impl inout::Tpm2StructOut for Tpm2bEncryptedSecret {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        // If size is 0, this should be an empty buffer
        self.size.pack(buff);
        buff.write_bytes(&self.secret[0..self.size as usize]);
    }
}

#[derive(Copy, Clone)]
pub struct _Private {
    integrity_outer: Tpm2bDigest,
    //integrity_inner: Tpm2bDigest,
    size_sensitive: u16,
    enc_sensitive: [u8; mem::size_of::<Tpm2bSensitive>()],
}

impl inout::Tpm2StructOut for _Private {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.integrity_outer.pack(buff);
        //if self.integrity_inner.size > 0 {
        //    self.integrity_inner.pack(buff);
        //}
        //self.size_sensitive.pack(buff);
        buff.write_bytes(&self.enc_sensitive[0..self.size_sensitive as usize]);
    }
}

// TPM2B_PRIVATE
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bPrivate {
    size: u16,
    // buffer is sized based on _PRIVATE data structure, which is defined
    // as follows:
    // * integrityOuter: TPM2B_DIGEST
    // * integrityInner: TPM2B_DIGEST
    // * se:nsitive: TPM2B_SENSITIVE
    buffer: [u8; mem::size_of::<Tpm2bDigest>() * 2 + mem::size_of::<Tpm2bSensitive>()],
}

impl inout::Tpm2StructOut for Tpm2bPrivate {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.size.pack(buff);
        buff.write_bytes(&self.buffer[0..self.size as usize]);
    }
}

impl Tpm2bPrivate {
    pub fn new() -> Self {
        Tpm2bPrivate {
            size: 0,
            buffer: [0; mem::size_of::<Tpm2bDigest>() * 2 + mem::size_of::<Tpm2bSensitive>()],
        }
    }
}

impl inout::Tpm2StructIn for Tpm2bPrivate {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::DeserializationError> {
        self.size.unpack(buff)?
        self.buffer[0..self.size as usize].clone_from_slice(buff.read_bytes(self.size as usize));
        Ok(())
    }
}

pub fn get_name(public: TpmtPublic) -> [u8; 34] {
    // The name of a TPMT_PUBLIC data structure requires
    // that the algorithm type os pre-pended
    let mut buff = inout::StaticByteBuffer::new();
    public.pack(&mut buff);

    let mut hasher = Sha256::new();
    hasher.update(buff.to_bytes());

    let mut name: [u8; 34] = [0; 34];
    // TODO: this should not be hardcoded
    name[0] = 0x00;
    name[1] = 0x0b;
    name[2..].clone_from_slice(&hasher.finalize()[..]);
    return name;
}

pub fn kdfa(
    key: &[u8],
    label: &[u8],
    contextU: &[u8],
    contextV: &[u8],
    bits: u32,
) -> result::Result<inout::StaticByteBuffer, errors::TpmError> {
    let bytes = (bits + 7) / 8;

    let mut counter: u32 = 1;

    let mut buff4B = [0; 4];

    // TODO: this should not be hardcoded
    type HmacSha256 = Hmac<Sha256>;

    let mut buff = inout::StaticByteBuffer::new();

    while buff.to_bytes().len() < bytes as usize {
        let mut mac = HmacSha256::new_from_slice(key).expect("could not create HMAC");

        BigEndian::write_u32(&mut buff4B, counter);
        mac.update(&buff4B);

        mac.update(label);
        mac.update(&[0x0]);
        mac.update(contextU);
        mac.update(contextV);

        buff4B.fill(0);
        BigEndian::write_u32(&mut buff4B, bits);
        mac.update(&buff4B);

        let result = mac.finalize();
        buff.write_bytes(&result.into_bytes());
    }

    let out: &[u8] = &buff.to_bytes()[0..bytes as usize];

    let mut key = inout::StaticByteBuffer::new();
    let maskBits = bits % 8;
    if maskBits > 0 {
        key.write_bytes(&[out[0] & (1 << maskBits) - 1]);
        key.write_bytes(&out[1..]);
    } else {
        key.write_bytes(out);
    }

    Ok(key)
}

impl Tpm2bPrivate {
    // Creates a `duplicate` object of type TPM2B_PRIVATE
    pub fn new_duplicate(
        parent: &rsa::RsaPublicKey,
        sensitive: TpmtSensitive,
        public: TpmtPublic,
        enc_seed_out: &mut Tpm2bEncryptedSecret,
    ) -> Self {
        // Algorithm for creating a `duplicate` TPM2B_PRIVATE structure is the following:
        // * Create seed for symmetric encryption of sensitive
        // * Encrypt seed with parent object
        // * Create duplicate object
        //
        // The method of generating the key and IV is described in “Protected Storage”
        // subclause “Symmetric Encryption.” in TPM 2.0 Part 1.
        //
        // The symmetric key is derived from a seed value contained in the Storage Parent’s
        // sensitive area and the Name of the protected object. The block cipher used for
        // encrypting the object's sensitive area is the symmetric cipher of the Storage
        // Parent.
        //
        // The symmetric key for the encryption is computed by:
        // symKey ≔ KDFa (pNameAlg, seedValue, “STORAGE”, name, NULL , bits)
        //

        // Create serialized TPM2B_SENSITIVE from TpmtSensitive.
        let mut temp = inout::StaticByteBuffer::new();
        sensitive.pack(&mut temp);
        let size = temp.to_bytes().len() as u16;

        let mut sensitive_buff = inout::StaticByteBuffer::new();
        Tpm2bSensitive {
            size: size,
            sensitive_area: sensitive,
        }
        .pack(&mut sensitive_buff);

        // Encrypt the serialized TPM2B_SENSITIVE structure
        // Equivalent to the call:
        // encryptSecret(packedSecret, seed, nameEncoded, ek)
        // Where
        // packedSecret is sensitive_buff
        let name = get_name(public);
        println!("name is {:02x?}", name);

        let mut public_buff = inout::StaticByteBuffer::new();

        public.pack(&mut public_buff);

        println!("public buff is {:02x?}", public_buff.to_bytes());

        // TPM2B_SENSITIVE is given by the concatenation of
        // `size_buff` and `sensitive_buff`.

        // Create seed and encrypt TPM2B_SENSITIVE
        //let key_bytes = parent.n().to_bytes_le().len();
        //let seed = rand::thread_rng().gen::<[u8; MAX_SEED_LEN]>();

        let seed: [u8; 16] = [
            0x12, 0x39, 0x00, 0x02, 0x67, 0x18, 0x16, 0x50, 0x67, 0x21, 0xf6, 0xfc, 0xe8, 0x80,
            0xb4, 0xab,
        ];

        // Encrypt the seed with parent key. This cannot match the encrypted seed of another
        // implementation because we are reading from rnd.
        let mut rng = rand::thread_rng();

        //let label: &[u8] = &[0x44, 0x55, 0x50, 0x4c, 0x49, 0x43, 0x41, 0x54, 0x45];

        //let label_str = str::from_utf8(label).expect("label is wrong");

        //printl0n!("Label is {:02x?}", label_str);
        println!("Encrypting with parent {:02x?}", parent);

        let padding = PaddingScheme::new_oaep_with_label::<sha2::Sha256, &str>("DUPLICATE\0");
        let enc_seed = parent
            .encrypt(&mut rng, padding, &seed[..])
            .expect("failed to encrypt");

        enc_seed_out.size = enc_seed.len() as u16;
        enc_seed_out.secret[0..enc_seed_out.size as usize].clone_from_slice(&enc_seed);

        println!("encrypted seed is {:02x?}", enc_seed);
        println!("");
        println!("");

        let result = kdfa(&seed[..], "STORAGE".as_bytes(), &name[..], &[], 128);

        let mut key: [u8; 16] = [0; 16];

        match result {
            Ok(res) => {
                key.clone_from_slice(res.to_bytes());
                println!("key is {:x?}", key);
            }
            Err(err) => {
                panic!("error while calculating key");
            }
        }

        type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;

        let iv = [0x00; 16];

        let mut encrypted_buff: [u8; 256] = [0; 256];

        Aes128CfbEnc::new(&key.into(), &iv.into())
            .encrypt_b2b(
                &mut sensitive_buff.to_bytes(),
                &mut encrypted_buff[0..sensitive_buff.to_bytes().len()],
            )
            .unwrap();

        println!("Encrypted buffer is {:x?}", encrypted_buff);

        // Creation of HMAC
        let result = kdfa(&seed[..], "INTEGRITY".as_bytes(), &[], &[], 256);
        let mut mac_key: [u8; 32] = [0; 32];

        match result {
            Ok(res) => {
                mac_key.clone_from_slice(res.to_bytes());
                println!("key is {:x?}", key);
            }
            Err(err) => {
                panic!("error while calculating key");
            }
        }

        println!("MAC key {:x?}", mac_key);
        // TODO: this should not be hardcoded
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&mac_key[..]).expect("could not create HMAC");

        mac.update(&encrypted_buff[0..sensitive_buff.to_bytes().len()]);
        mac.update(&name[..]);

        // Create the _PRIVATE data structure consisting of the following
        // pub struct _Private {
        //    integrity_outer: Tpm2bDigest,
        //    integrity_inner: Tpm2bDigest,
        //    sensitive: Tpm2bSensitive,
        // }
        // Since for creation of duplicate IV was all zero, it doesn't need to
        // be added to _Private, so integrity_inner shall be ignored

        let hmac_result = mac.finalize();
        let hmac_bytes = hmac_result.into_bytes();

        println!("mac bytes are {:x?}", hmac_bytes);

        let mut buffer: [u8; MAX_HASH_SIZE] = [0; MAX_HASH_SIZE];
        buffer[0..32].clone_from_slice(&hmac_bytes[..]);

        let mut enc_sensitive: [u8; mem::size_of::<Tpm2bSensitive>()] =
            [0; mem::size_of::<Tpm2bSensitive>()];
        enc_sensitive[0..256].clone_from_slice(&encrypted_buff);

        let private = _Private {
            integrity_outer: Tpm2bDigest {
                size: hmac_bytes.len() as u16,
                buffer: buffer,
            },
            // Since for creation of duplicate IV was all zero, it doesn't need to
            // be added to _Private, so integrity_inner shall be ignored
            //integrity_inner: Tpm2bDigest {
            //    size: 0,
            //    buffer: [0; 64],
            //},

            // enc_sensitive already includes the size, so size_sensitive is not needed
            // neither is Tpm2bDigest needed
            //size_sensitive: sensitive_buff.to_bytes().len() as u16,
            // I am mi-using size_sensitive here to be able to serialize with specific
            // boundary the enc_sentistive, but its value shoudl be known
            size_sensitive: sensitive_buff.to_bytes().len() as u16,
            enc_sensitive: enc_sensitive,
        };

        // The import blob then consists in:
        // * Duplicate
        // * Encrypted Seed
        // * Public Area
        // * PCRA

        let mut private_buff = inout::StaticByteBuffer::new();
        private.pack(&mut private_buff);

        let mut duplicate = Tpm2bPrivate {
            size: private_buff.to_bytes().len() as u16,
            buffer: [0; mem::size_of::<Tpm2bDigest>() * 2 + mem::size_of::<Tpm2bSensitive>()],
        };
        duplicate.buffer[0..private_buff.to_bytes().len()]
            .clone_from_slice(private_buff.to_bytes());

        let mut duplicate_buff = inout::StaticByteBuffer::new();

        duplicate.pack(&mut duplicate_buff);
        println!("duplicate is {:02x?}", duplicate_buff.to_bytes());

        return duplicate;
    }
}

#[derive(Copy, Clone)]
// TPM2B_SENSITIVE
pub struct Tpm2bSensitive {
    size: u16,
    sensitive_area: TpmtSensitive,
}

impl inout::Tpm2StructOut for Tpm2bSensitive {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.size.pack(buff);
        self.sensitive_area.pack(buff);
    }
}

#[derive(Copy, Clone)]
// TPM2B_SENSITIVE_DATA
pub struct Tpm2bSensitiveData {
    size: u16,
    buffer: [u8; MAX_SYM_DATA],
}

impl inout::Tpm2StructOut for Tpm2bSensitiveData {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.size.pack(buff);
        buff.write_bytes(&self.buffer[0..self.size as usize]);
    }
}

#[derive(Copy, Clone)]
enum TpmuSensitiveComposite {
    Rsa(Tpm2bPublicKeyRsa),
    Ecc(Tpm2bEccParameter),
    Bits(Tpm2bSensitiveData),
}

impl inout::Tpm2StructOut for TpmuSensitiveComposite {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        match *self {
            TpmuSensitiveComposite::Bits(value) => value.pack(buff),
            other => {
                panic!("cannot serialize TpmuSensitiveComposite")
            }
        }
    }
}

#[derive(Copy, Clone)]
// TPMT_SENSITIVE
pub struct TpmtSensitive {
    sensitive_type: TpmiAlgPublic,
    auth_value: Tpm2bAuth,
    seed_value: Tpm2bDigest,
    sensitive: TpmuSensitiveComposite,
}

impl TpmtSensitive {
    // new_sensitive_data_object creates a TPMT_SENSITIVE object
    pub fn new(data: &[u8]) -> Self {
        if data.len() > MAX_SYM_DATA || data.len() > 65536 {
            panic!("data is too large");
        }
        let mut sensitive_buffer = [0; MAX_SYM_DATA];
        sensitive_buffer[0..data.len()].clone_from_slice(data);

        // The seed_value of _SENSITIVE object containing symmetric
        // data object is used to calculate `unique` in TPMT_PUBLIC as
        //
        // unique := Hash(seed_value || sensitive)
        let mut seed_buffer: [u8; MAX_HASH_SIZE] = [
            0xb9, 0xfa, 0x57, 0xb8, 0x5c, 0x55, 0xde, 0x9c, 0xf3, 0xb2, 0x06, 0x47, 0x46, 0xf5,
            0x48, 0x55, 0x1b, 0x7e, 0x35, 0xdf, 0xc5, 0xf2, 0x33, 0x1e, 0x51, 0xe3, 0x06, 0x65,
            0x74, 0xa4, 0x71, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // TODO: This doesn't need to be hash or random, just random
        //let rnd = rand::thread_rng().gen::<[u8; 32]>();
        //let mut hasher = Sha256::new();
        //hasher.update(rnd);
        //let seed_result = hasher.finalize();
        //seed_buffer[0..seed_result.len()].clone_from_slice(&seed_result);

        TpmtSensitive {
            // TPM_ALG_KEYEDHASH indicates a symmetric data representing
            // a sealed data object.
            sensitive_type: TPM_ALG_KEYEDHASH,
            // Empty Auth value indicates that there is no auth associated
            // with this sensitive object
            auth_value: Tpm2bAuth {
                size: 0,
                buffer: [0; MAX_HASH_SIZE],
            },
            // For a symmetric object, seedValue field is used as an
            // obfuscation value
            seed_value: Tpm2bDigest {
                size: 32,
                buffer: seed_buffer,
            },
            sensitive: TpmuSensitiveComposite::Bits(Tpm2bSensitiveData {
                size: data.len() as u16,
                buffer: sensitive_buffer,
            }),
        }
    }
}

impl inout::Tpm2StructOut for TpmtSensitive {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.sensitive_type.pack(buff);
        self.auth_value.pack(buff);
        self.seed_value.pack(buff);
        self.sensitive.pack(buff);
    }
}

// TPMU_PUBLIC_ID
#[derive(Copy, Clone, Debug)]
enum TpmuPublicId {
    KeyedHash(Tpm2bDigest),
    Sym(Tpm2bDigest),
    Rsa(Tpm2bPublicKeyRsa),
    Ecc(TpmsEccPoint),
    Derive(TpmsDerive),
}

impl inout::Tpm2StructOut for TpmuPublicId {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        match *self {
            TpmuPublicId::KeyedHash(value) => {
                value.pack(buff);
            }
            TpmuPublicId::Rsa(value) => {
                value.pack(buff);
            }
            other => {
                panic!("cannot serialize TpmuPublicId");
            }
        }
    }
}

impl TpmuPublicId {
    // new_rsa creates a new TpmuPublicId for RSA keys
    pub fn new_rsa(key: &rsa::RsaPublicKey) -> Self {
        let mut modulus = [0; RSA_KEY_NAX_NUM_BYTES];
        modulus[0..key.size()].clone_from_slice(key.n().to_bytes_le().as_slice());
        let id = TpmuPublicId::Rsa(Tpm2bPublicKeyRsa {
            // size of the buffer containing the modulus
            size: key.size() as u16,
            // The buffer
            buffer: modulus,
        });
        id
    }

    pub fn new_keyed_hash(data: &[u8]) -> Self {
        let mut buffer = [0; MAX_HASH_SIZE];
        buffer[0..data.len()].clone_from_slice(data);
        TpmuPublicId::KeyedHash(Tpm2bDigest {
            size: data.len() as u16,
            buffer: buffer,
        })
    }
}

// TPMS_SCHEME_HASH
#[derive(Copy, Clone, Debug)]
pub struct TpmsSchemeHash {
    hash_alg: TpmiAlgHash,
}

impl inout::Tpm2StructOut for TpmsSchemeHash {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.hash_alg.pack(buff);
    }
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

pub type TpmsSigSchemeEcdsa = TpmsSchemeHash;
pub type TpmsSigSchemeRsassa = TpmsSchemeHash;
pub type TpmsSigSchemeEcdh = TpmsSchemeHash;
pub type TpmsSigSchemeEcmqv = TpmsSchemeHash;
pub type TpmsSigSchemeRsapss = TpmsSchemeHash;
pub type TpmsSigSchemeEcdaa = TpmsSchemeHash;
pub type TpmsSigSchemeSm2 = TpmsSchemeHash;
pub type TpmsSigSchemeEcschnorr = TpmsSchemeHash;
pub type TpmsSigSchemeRsaes = TpmsSchemeHash;
pub type TpmsSigSchemeOaep = TpmsSchemeHash;

// Types of TPMU_ASYM_SCHEME
#[derive(Copy, Clone)]
pub union TpmuAsymScheme {
    pub ecdsa: TpmsSigSchemeEcdsa,
    pub rsassa: TpmsSigSchemeRsassa,
    pub ecdh: TpmsSigSchemeEcdh,
    pub ecmqv: TpmsSigSchemeEcmqv,
    pub rsapss: TpmsSigSchemeRsapss,
    pub ecdaa: TpmsSigSchemeEcdaa,
    pub smc2: TpmsSigSchemeSm2,
    pub ecschnorr: TpmsSigSchemeEcschnorr,
    pub rsaes: TpmsSigSchemeRsaes,
    pub oaep: TpmsSigSchemeOaep,
}

impl TpmuAsymScheme {
    pub fn new_rsassa_tpmu_asym_scheme() -> Self {
        return TpmuAsymScheme {
            rsassa: TpmsSigSchemeRsassa {
                hash_alg: TPM_ALG_RSASSA,
            },
        };
    }
}

impl std::fmt::Debug for TpmuAsymScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Ok(())
    }
}

// TPMS_SCHEME_XOR
#[derive(Copy, Clone, Debug)]
pub struct TpmsSchemeXor {
    hash_alg: TpmiAlgHash,
    kdf: TpmiAlgKdf,
}

impl inout::Tpm2StructOut for TpmsSchemeXor {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.hash_alg.pack(buff);
        self.kdf.pack(buff);
    }
}

// TPMU_SCHEME_KEYEDHASH
#[derive(Copy, Clone, Debug)]
enum TpmuSchemeKeyedHash {
    Hmac(TpmsSchemeHmac),
    Xor(TpmsSchemeXor),
    Null,
}

impl inout::Tpm2StructOut for TpmuSchemeKeyedHash {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        match *self {
            TpmuSchemeKeyedHash::Hmac(value) => {
                value.pack(buff);
            }
            TpmuSchemeKeyedHash::Xor(value) => {
                value.pack(buff);
            }
            other => {}
        }
    }
}

// TPMT_KEYEDHASH_SCHEME
#[derive(Copy, Clone, Debug)]
pub struct TpmtKeyedHashScheme {
    scheme: TpmiAlgKeyedHashScheme,
    details: TpmuSchemeKeyedHash,
}

impl inout::Tpm2StructOut for TpmtKeyedHashScheme {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.scheme.pack(buff);
        self.details.pack(buff);
    }
}

impl TpmtKeyedHashScheme {
    pub fn new_keyed_hash_scheme() -> Self {
        TpmtKeyedHashScheme {
            scheme: TPM_ALG_NULL,
            // default `details` value, not relevant if scheme == TPM_ALG_NULL
            details: TpmuSchemeKeyedHash::Null,
        }
    }
}

// TPMS_KEYEDHASH_PARMS
#[derive(Copy, Clone, Debug)]
pub struct TpmsKeyedHashParms {
    scheme: TpmtKeyedHashScheme,
}

impl inout::Tpm2StructOut for TpmsKeyedHashParms {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.scheme.pack(buff);
    }
}

impl TpmsKeyedHashParms {
    pub fn new_keyed_hash_parms() -> Self {
        TpmsKeyedHashParms {
            scheme: TpmtKeyedHashScheme::new_keyed_hash_scheme(),
        }
    }
}

// TPMS_SYMCIPHER_PARMS
#[derive(Copy, Clone, Debug)]
pub struct TpmsSymcipherParms {}

// TPMS_ECC_PARMS
#[derive(Copy, Clone, Debug)]
pub struct TpmsEccParms {}

// TPMS_ASYM_PARMS
#[derive(Copy, Clone, Debug)]
pub struct TpmsAsymParms {}

// TPMU_SYM_KEY_BITS
#[derive(Copy, Clone, Debug)]
enum TpmuSymKeyBits {
    Sym(TpmKeyBits),
    Xor(TpmiAlgHash),
    Null,
}

impl inout::Tpm2StructOut for TpmuSymKeyBits {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        match self {
            TpmuSymKeyBits::Sym(value) | TpmuSymKeyBits::Xor(value) => {
                value.pack(buff);
            }
            TpmuSymKeyBits::Null => {}
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum TpmuSymMode {
    Sym(TpmiAlgSymMode),
    // TPM_ALG_XOR and TPM_ALG_NULL do not require a mode
    Xor,
    Null,
}

impl inout::Tpm2StructOut for TpmuSymMode {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        match self {
            TpmuSymMode::Sym(value) => {
                value.pack(buff);
            }
            TpmuSymMode::Xor | TpmuSymMode::Null => {}
        }
    }
}

// TPMU_SYM_DETAILS. The spec currently does not make any use of this
// structure
#[derive(Copy, Clone, Debug)]
enum TpmuSymDetails {
    Sym,
    Xor,
    Null,
}

impl inout::Tpm2StructOut for TpmuSymDetails {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {}
}

// TPMT_SYM_DEF_OBJECT
#[derive(Debug, Copy, Clone)]
pub struct TpmtSymDefObject {
    algorithm: TpmiAlgSymObject,
    key_bits: TpmuSymKeyBits,
    mode: TpmuSymMode,
    details: TpmuSymDetails,
}

impl TpmtSymDefObject {
    pub fn new_aes_128() -> Self {
        TpmtSymDefObject {
            algorithm: TPM_ALG_AES,
            key_bits: TpmuSymKeyBits::Sym(128),
            mode: TpmuSymMode::Sym(TPM_ALG_CFB),
            details: TpmuSymDetails::Sym,
        }
    }

    pub fn new_null() -> Self {
        TpmtSymDefObject {
            algorithm: TPM_ALG_NULL,
            key_bits: TpmuSymKeyBits::Null,
            mode: TpmuSymMode::Null,
            details: TpmuSymDetails::Null,
        }
    }
}

impl inout::Tpm2StructOut for TpmtSymDefObject {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        if self.algorithm == TPM_ALG_NULL {
            self.algorithm.pack(buff);
        } else {
            panic!("not supported");
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TpmtSymDef {
    algorithm: TpmiAlgSym,
    key_bits: TpmuSymKeyBits,
    mode: TpmuSymMode,
    details: TpmuSymDetails,
}

impl TpmtSymDef {
    pub fn new_null() -> Self {
        TpmtSymDef {
            algorithm: TPM_ALG_NULL,
            key_bits: TpmuSymKeyBits::Null,
            mode: TpmuSymMode::Null,
            details: TpmuSymDetails::Null,
        }
    }
}

impl inout::Tpm2StructOut for TpmtSymDef {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.algorithm.pack(buff);
        self.key_bits.pack(buff);
        self.mode.pack(buff);
        self.details.pack(buff);
    }
}

// TPMT_RSA_SCHEME
#[derive(Copy, Clone, Debug)]
pub struct TpmtRsaScheme {
    scheme: TpmiAlgRsaScheme,
    details: TpmuAsymScheme,
}

impl TpmtRsaScheme {
    pub fn new_tpmt_rsa_scheme() -> Self {
        TpmtRsaScheme {
            scheme: TPM_ALG_RSA,
            details: TpmuAsymScheme::new_rsassa_tpmu_asym_scheme(),
        }
    }
}

// TPMS_RSA_PARMS
#[derive(Copy, Clone, Debug)]
pub struct TpmsRsaParams {
    symmetric: TpmtSymDefObject,
    scheme: TpmtRsaScheme,
    key_bits: TpmiRsaKeyBits,
    exponent: u32,
}

impl TpmsRsaParams {
    pub fn new_tpms_rsa_params(key: &rsa::RsaPublicKey) -> Self {
        let exp_result = key.e().to_u32();
        match exp_result {
            Some(_) => (),
            None => panic!("exponent cannot be represented with 32 bytes"),
        }
        let key_len = key.n().to_bytes_le().len();
        if key_len != RSA_KEY_NUM_BYTES / 8 {
            panic!("only 2048 bits key supported, got {}", key_len);
        }
        TpmsRsaParams {
            symmetric: TpmtSymDefObject::new_aes_128(),
            scheme: TpmtRsaScheme::new_tpmt_rsa_scheme(),
            key_bits: (key_len * 8) as u16,
            exponent: exp_result.unwrap(),
        }
    }
}

// TPMS_ECC_PARMS
#[derive(Default, Debug)]
pub struct TpmsEccParams {}

// TPM2B_LABEL
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bLabel {
    size: u16,
    buffer: [u8; RSA_KEY_NAX_NUM_BYTES],
}

// TPM2B_ECC_PARAMETER
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bEccParameter {
    size: u16,
    buffer: [u8; 256usize],
}

// TPM2B_PUBLIC_KEY_RSA
// This sized buffer holds the largest RSA public key supported by the TPM.
// Buffer will contain the modulus of the RSA key.
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    buffer: [u8; RSA_KEY_NAX_NUM_BYTES],
}

impl inout::Tpm2StructOut for Tpm2bPublicKeyRsa {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.size.pack(buff);
        buff.write_bytes(&self.buffer[0..self.size as usize]);
    }
}

// TPMS_ECC_POINT
#[derive(Copy, Clone, Debug)]
pub struct TpmsEccPoint {
    x: Tpm2bEccParameter,
    y: Tpm2bEccParameter,
}

// TPMS_DERIVE
#[derive(Copy, Clone, Debug)]
pub struct TpmsDerive {
    label: Tpm2bLabel,
    //context: Tpm2bContext,
}

#[derive(Copy, Clone, Debug)]
enum TpmuPublicParms {
    KeyedHashDetail(TpmsKeyedHashParms),
    SymDetail(TpmsSymcipherParms),
    RsaDetail(TpmsRsaParams),
    EccDetail(TpmsEccParms),
    AsymDetail(TpmsAsymParms),
}

impl TpmuPublicParms {
    pub fn new_rsa_public_params(key: &rsa::RsaPublicKey) -> Self {
        return TpmuPublicParms::RsaDetail(TpmsRsaParams::new_tpms_rsa_params(key));
    }

    pub fn new_keyed_hash_parms() -> Self {
        return TpmuPublicParms::KeyedHashDetail(TpmsKeyedHashParms::new_keyed_hash_parms());
    }
}

impl inout::Tpm2StructOut for TpmuPublicParms {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        match *self {
            TpmuPublicParms::KeyedHashDetail(params) => {
                params.pack(buff);
            }
            other => {
                panic!("cannot serialize KeyedHashDetail");
            }
        }
    }
}

// TPMT_PUBLIC
#[derive(Copy, Clone, Debug)]
pub struct TpmtPublic {
    type_alg: TpmiAlgPublic,
    name_alg: TpmiAlgHash,
    object_attributes: TpmaObject,
    auth_policy: Tpm2bDigest,
    parameters: TpmuPublicParms,
    unique: TpmuPublicId,
}

pub fn newDefaultEkAttributes() -> TpmaObject {
    // This is FlagUserWithAuth in go-tpm implementation
    0x00000040
}

pub fn newDefaultEkAuthPolicy() -> Tpm2bDigest {
    Tpm2bDigest::new()
}

impl inout::Tpm2StructOut for TpmtPublic {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.type_alg.pack(buff);
        self.name_alg.pack(buff);
        self.object_attributes.pack(buff);
        self.auth_policy.pack(buff);
        self.parameters.pack(buff);
        self.unique.pack(buff);
    }
}

impl TpmtPublic {
    // Creates a TPMT_PUBLIC data structure for RSA key (type == TPM_ALG_RSA)
    pub fn new_rsa(key: &rsa::RsaPublicKey) -> Self {
        TpmtPublic {
            type_alg: TPM_ALG_RSA,
            name_alg: TPM_ALG_SHA256,
            object_attributes: newDefaultEkAttributes(),
            auth_policy: newDefaultEkAuthPolicy(),
            parameters: TpmuPublicParms::new_rsa_public_params(key),
            unique: TpmuPublicId::new_rsa(key),
        }
    }
    // Creates a TPMT_PUBLIC data structure for data object (type == TPM_ALG_KEYEDHASH).
    //
    // With type TPM_ALG_KEYEDHASH, sign and decrypt attributes should be clear.
    //
    // For Data object, the contents of unique should be of type TPM2B_DIGEST
    // and should be computed from components of the sensitive area of the object
    // as follows:
    //
    // unique := Hash(seedValue || sensitive)
    //
    pub fn new_data_object(sensitive: &TpmtSensitive) -> Self {
        let mut hasher = Sha256::new();

        hasher.update(&sensitive.seed_value.buffer[0..sensitive.seed_value.size as usize]);

        match sensitive.sensitive {
            TpmuSensitiveComposite::Bits(value) => {
                hasher.update(&value.buffer[0..value.size as usize]);
            }
            other => {
                panic!("cannot create new data object with this sensitive type");
            }
        }

        let unique = hasher.finalize();

        TpmtPublic {
            type_alg: TPM_ALG_KEYEDHASH,
            name_alg: TPM_ALG_SHA256,
            // Clear all attributes for Data object
            object_attributes: newDefaultEkAttributes(),
            // Empty auth policy
            auth_policy: newDefaultEkAuthPolicy(),
            // The TPMT_PUBLIC blob is of type TPM_ALG_KEYEDHASH and holds
            // a TPMS_KEYEDHASH_PARMS data structure
            parameters: TpmuPublicParms::new_keyed_hash_parms(),
            unique: TpmuPublicId::new_keyed_hash(&unique),
        }
    }
}

// TPM2B_PUBLIC
// An object description requires a TPM2B_PUBLIC structure and may require a TPMT_SENSITIVE
// structure. When the structure is stored off the TPM, the TPMT_SENSITIVE structure is
// encrypted within a TPM2B_PRIVATE structure
#[derive(Clone, Copy, Debug)]
pub struct Tpm2bPublic {
    pub size: u16,
    pub public: TpmtPublic,
}

impl Tpm2bPublic {
    pub fn new_rsa(key: &rsa::RsaPublicKey) -> Self {
        let public: TpmtPublic = TpmtPublic::new_rsa(key);
        Tpm2bPublic {
            size: 0,
            public: public,
        }
    }

    pub fn new_public_data_object(parent: &rsa::RsaPublicKey, sensitive: &TpmtSensitive) -> Self {
        Tpm2bPublic {
            size: 0,
            public: TpmtPublic::new_data_object(sensitive),
        }
    }
}

impl inout::Tpm2StructOut for Tpm2bPublic {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.size.pack(buff);
        self.public.pack(buff);
    }
}

// TPM2B_DATA
#[derive(Debug, Clone, Copy)]
pub struct Tpm2bData {
    pub size: u16,
    pub buffer: [u8; 1024],
}

impl inout::Tpm2StructOut for Tpm2bData {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.size.pack(buff);
        buff.write_bytes(&self.buffer[0..self.size as usize]);
    }
}

impl inout::Tpm2StructIn for Tpm2bData {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::DeserializationError> {
        self.size.unpack(buff)?
        self.buffer[0..self.size as usize].clone_from_slice(buff.read_bytes(self.size as usize));
        Ok(())
    }
}

// TPMS_AUTH_COMMAND structure
#[derive(Debug, Clone, Copy)]
pub struct TpmsAuthCommand {
    pub session_handle: TpmiShAuthSession,
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bAuth,
}

impl inout::Tpm2StructOut for TpmsAuthCommand {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.session_handle.pack(buff);
        self.nonce.pack(buff);
        self.session_attributes.pack(buff);
        self.hmac.pack(buff);
    }
}

// TPMS_AUTH_RESPONSE
pub struct TpmsAuthResponse {
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bAuth,
}
