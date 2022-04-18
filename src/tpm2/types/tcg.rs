use crate::tpm2::errors;
use std::mem;
use std::result;

use crate::tpm2::serialization::inout;
use sha2::{Digest, Sha256, Sha512};

use num_traits::ToPrimitive;
use rand;
use rand::Rng;

use rsa;
use rsa::PublicKeyParts;

// Types
pub type TpmiStCommandTag = u16;
pub type TpmCc = u32;
pub type TpmRc = u32;
pub type TpmAlgId = u16;
pub type TpmSu = u16;
pub type TpmaObject = u32;
pub type TpmKeyBits = u16;

// Derived types
pub type TpmiAlgPublic = TpmAlgId;
pub type TpmiAlgHash = TpmAlgId;
pub type TpmiAlgKdf = TpmAlgId;
pub type TpmiAlgRsaScheme = TpmAlgId;
pub type TpmiAlgSymObject = TpmAlgId;
pub type TpmiAlgSymMode = TpmAlgId;

pub type TpmiAlgKeyedHashScheme = TpmAlgId;

pub type TpmiRsaKeyBits = TpmKeyBits;

// TPM2 command codes
pub const TPM_CC_PCR_READ: TpmCc = 0x0000017E;
pub const TPM_CC_STARTUP: TpmCc = 0x00000144;

pub const TPM2_NUM_PCR_BANKS: usize = 16;
pub const TPM2_MAX_PCRS: usize = 24;
pub const HASH_SIZE: usize = 512;
pub const MAX_RSA_KEY_BYTES: usize = 512;
pub const TPM2_PCR_SELECT_MAX: usize = (TPM2_MAX_PCRS + 7) / 8;
pub const MAX_SYM_DATA: usize = 128;

// TPM2 startup types
pub const TPM_SU_CLEAR: TpmSu = 0x0000;
pub const TPM_SU_STATE: TpmSu = 0x0001;

// Command tags
pub const TPM_ST_NO_SESSION: TpmiStCommandTag = 0x8001;

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

// TPMU_HA union
pub union TpmuHa {
    pub sha1: [u8; 20usize],
    pub sha256: [u8; 32usize],
    pub sha384: [u8; 38usize],
    pub sha512: [u8; 64usize],
    pub sm3256: [u8; 32usize],
}

pub const MAX_HASH_SIZE: usize = mem::size_of::<TpmuHa>();

// TPM2B_DIGEST
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bDigest {
    size: u16,
    buffer: [u8; MAX_HASH_SIZE],
}

// TPM2B_AUTH is defined as TPM2B_DIGEST
pub type Tpm2bAuth = Tpm2bDigest;

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
        digest_buffer.clone_from_slice(buffer);
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
    pub fn get_digest(&self, num: u32) -> result::Result<&Tpm2bDigest, errors::TpmError> {
        if num >= self.count {
            return Err(errors::TpmError {
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
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.hash.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        match self.sizeof_select.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        self.pcr_select
            .clone_from_slice(buff.read_bytes(self.sizeof_select as usize));
        Ok(())
    }
}

impl inout::Tpm2StructIn for TpmlDigest {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.count.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        for _pcr_count in 0..self.count {
            let mut size: u16 = 0;
            match size.unpack(buff) {
                Err(err) => return Err(err),
                _ => (),
            }
            let buffer = buff.read_bytes(size as usize);
            self.digests[_pcr_count as usize] = Tpm2bDigest::from_vec(size, buffer);
        }
        Ok(())
    }
}

// TPML_PCR_SELECTION
#[derive(Default, Debug)]
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
        for pcr_selection in self.pcr_selections.iter() {
            pcr_selection.pack(buff);
        }
    }
}

impl inout::Tpm2StructIn for TpmlPcrSelection {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.count.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        for _pcr_count in 0..self.count {
            let mut pcr_selection: TpmsPcrSelection = Default::default();
            match pcr_selection.unpack(buff) {
                Err(err) => return Err(err),
                _ => {
                    self.pcr_selections[_pcr_count as usize] = pcr_selection;
                }
            }
        }

        Ok(())
    }
}

// TPMU_ENCRYPTED_SECRET
#[derive(Copy, Clone)]
pub union TpmuEncryptedSecret {
    ecc: [u8; mem::size_of::<TpmsEccPoint>()],
    rsa: [u8; MAX_RSA_KEY_BYTES],
    symmetric: [u8; mem::size_of::<Tpm2bDigest>()],
    keyed_hash: [u8; mem::size_of::<Tpm2bDigest>()],
}

// TPM2B_ENCRYPTED_SECRET
#[derive(Copy, Clone)]
pub struct Tpm2bEncryptedSecret {
    size: u16,
    // Secret size is defined as the mexium size held by a TpmuEncryptedSecret structure
    secret: [u8; mem::size_of::<TpmuEncryptedSecret>()],
}

// TPM2B_PRIVATE
#[derive(Copy, Clone)]
pub struct Tpm2bPrivate {
    size: u16,
    // buffer is sized based on _PRIVATE data structure, which is defined
    // as follows:
    // - integrityOuter: TPM2B_DIGEST
    // - integrityInner: TPM2B_DIGEST
    // - sensitive: TPM2B_SENSITIVE
    buffer: [u8; mem::size_of::<Tpm2bDigest>() * 2 + mem::size_of::<Tpm2bSensitive>()],
}

impl Tpm2bPrivate {
    // new_data_object creates a TPMT_SENSITIVE object
    // encrypted within a TPM2B_PRIVATE object with parent
    // object passed as argument
    // TODO: At the moment this supports only RSA public key,
    // should be extended to support everything else.
    // pub fn new_data_object(parent: &rsa::RsaPublicKey, sensitive: &TpmtSensitive) -> Self {
    // TODO: the correct signature is above
    pub fn new_data_object(parent: &rsa::RsaPublicKey) -> Self {
        // Algorithm for creating a TPM2B_PRIVATE structure is the following:
        // * Create seed for symmetric encryption of sensitive
        // * Encrypt seed with parent object
        // * Create duplicate object
        //
        // create RSA seed
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
        // Pag. 145 summarizes all encryption steps
        //
        // TODO: encode the sensitive area
        Tpm2bPrivate {
            size: 0,
            buffer: [0; mem::size_of::<Tpm2bDigest>() * 2 + mem::size_of::<Tpm2bSensitive>()],
        }
    }
}

#[derive(Copy, Clone)]
// TPM2B_SENSITIVE
pub struct Tpm2bSensitive {
    size: u16,
    sensitive_area: TpmtSensitive,
}

#[derive(Copy, Clone)]
// TPM2B_SENSITIVE_DATA
pub struct Tpm2bSensitiveData {
    size: u16,
    buffer: [u8; MAX_SYM_DATA],
}

#[derive(Copy, Clone)]
// TPMU_SENSITIVE_COMPOSITE
pub union TpmuSensitiveComposite {
    bits: Tpm2bSensitiveData,
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
    // new_sensitive_data_object creates a TPMT_SENSITIVE
    // object which holds sensitive data to be encrypted
    // within an TPM2B_PRIVATE structure
    pub fn new_sensitive_data_object(data: &[u8]) -> Self {
        if data.len() > MAX_SYM_DATA || data.len() > 65536 {
            panic!("data is too large");
        }
        let mut sensitive_buffer = [0; MAX_SYM_DATA];
        sensitive_buffer[0..data.len()].clone_from_slice(data);

        // The seed_value of a TPMT_SENSITIVE object
        // containing symmetric data object is used to calculate
        // `unique` within TPMT_PUBLIC as
        // unique := Hash(seed_value || sensitive)
        let mut seed_buffer: [u8; MAX_HASH_SIZE] = [0; MAX_HASH_SIZE];

        let rnd = rand::thread_rng().gen::<[u8; 32]>();
        let mut hasher = Sha256::new();
        hasher.update(rnd);
        let seed_result = hasher.finalize();

        seed_buffer[0..seed_result.len()].clone_from_slice(&seed_result);

        TpmtSensitive {
            sensitive_type: TPM_ALG_KEYEDHASH,
            // leave Auth empty for this sensitive area. TODO: why?
            auth_value: Tpm2bAuth {
                size: 0,
                buffer: [0; MAX_HASH_SIZE],
            },
            seed_value: Tpm2bDigest {
                size: seed_buffer.len() as u16,
                buffer: seed_buffer,
            },
            sensitive: TpmuSensitiveComposite {
                bits: Tpm2bSensitiveData {
                    size: sensitive_buffer.len() as u16,
                    buffer: sensitive_buffer,
                },
            },
        }
    }
}

// TPMU_PUBLIC_PARMS
#[derive(Copy, Clone)]
pub union TpmuPublicParms {
    keyed_hash_detail: TpmsKeyedHashParms,
    symDetail: TpmsSymcipherParms,
    rsaDetail: TpmsRsaParams,
    eccDetail: TpmsEccParms,
    asymDetail: TpmsAsymParms,
}

impl TpmuPublicParms {
    pub fn new_rsa_public_params(key: &rsa::RsaPublicKey) -> Self {
        TpmuPublicParms {
            rsaDetail: TpmsRsaParams::new_tpms_rsa_params(key),
        }
    }

    pub fn new_keyed_hash_parms() -> Self {
        TpmuPublicParms {
            keyed_hash_detail: TpmsKeyedHashParms::new_keyed_hash_parms(),
        }
    }
}

// TPMU_PUBLIC_ID
pub union TpmuPublicId {
    keyed_hash: Tpm2bDigest,
    sym: Tpm2bDigest,
    rsa: Tpm2bPublicKeyRsa,
    ecc: TpmsEccPoint,
    derive: TpmsDerive,
}

impl TpmuPublicId {
    // new_rsa creates a new TpmuPublicId for RSA keys
    pub fn new_rsa(key: &rsa::RsaPublicKey) -> Self {
        let mut modulus = [0; MAX_RSA_KEY_BYTES];
        modulus[0..key.size()].clone_from_slice(key.n().to_bytes_le().as_slice());
        let id = TpmuPublicId {
            rsa: Tpm2bPublicKeyRsa {
                // size of the buffer containing the modulus
                size: key.size() as u16,
                // The buffer
                buffer: modulus,
            },
        };
        id
    }

    pub fn new_keyed_hash() -> Self {
        TpmuPublicId {
            keyed_hash: Tpm2bDigest {
                size: 0,
                buffer: [0; MAX_HASH_SIZE],
            },
        }
    }
}

// TPMS_SCHEME_HASH
#[derive(Default, Copy, Clone, Debug)]
pub struct TpmsSchemeHash {
    hash_alg: TpmiAlgHash,
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

// TPMS_SCHEME_XOR
#[derive(Copy, Clone, Debug)]
pub struct TpmsSchemeXor {
    hash_alg: TpmiAlgHash,
    kdf: TpmiAlgKdf,
}

// TPMU_SCHEME_KEYEDHASH
#[derive(Copy, Clone, Debug)]
pub struct TpmuSchemeKeyedHash {
    hmac: TpmsSchemeHmac,
    xor: TpmsSchemeXor,
}

// TPMT_KEYEDHASH_SCHEME
#[derive(Copy, Clone, Debug)]
pub struct TpmtKeyedHashScheme {
    scheme: TpmiAlgKeyedHashScheme,
    details: Option<TpmuSchemeKeyedHash>,
}

impl TpmtKeyedHashScheme {
    pub fn new_keyed_hash_scheme() -> Self {
        TpmtKeyedHashScheme {
            scheme: TPM_ALG_NULL,
            details: None,
        }
    }
}

// TPMS_KEYEDHASH_PARMS
#[derive(Copy, Clone, Debug)]
pub struct TpmsKeyedHashParms {
    scheme: TpmtKeyedHashScheme,
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

// TPMT_SYM_DEF_OBJECT
#[derive(Debug, Copy, Clone)]
pub struct TpmtSymDefObject {
    algorithm: TpmiAlgSymObject,
    key_bits: u16,
    mode: TpmiAlgSymMode,
    // details can be omitted if none of the
    // selectors produces any data
    // details: TPMU_SYM_DETAILS,
}

impl TpmtSymDefObject {
    pub fn new_tpmt_sym_def_object() -> Self {
        TpmtSymDefObject {
            algorithm: TPM_ALG_AES,
            key_bits: 128,
            mode: TPM_ALG_CFB,
        }
    }
}

// TPMT_RSA_SCHEME
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
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
        if key_len != 256 {
            panic!("only 2048 bits key supported, got {}", key_len);
        }
        TpmsRsaParams {
            symmetric: TpmtSymDefObject::new_tpmt_sym_def_object(),
            scheme: TpmtRsaScheme::new_tpmt_rsa_scheme(),
            key_bits: 2048,
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
    buffer: [u8; MAX_RSA_KEY_BYTES],
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
    buffer: [u8; MAX_RSA_KEY_BYTES],
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

// TPMT_PUBLIC
pub struct TpmtPublic {
    type_alg: TpmiAlgPublic,
    name_alg: TpmiAlgHash,
    object_attributes: TpmaObject,
    auth_policy: Tpm2bDigest,
    parameters: TpmuPublicParms,
    unique: TpmuPublicId,
}

pub fn newDefaultEkAttributes() -> TpmaObject {
    0
}

pub fn newDefaultEkAuthPolicy() -> Tpm2bDigest {
    Tpm2bDigest::new()
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
    // With type TPM_ALG_KEYEDHASH, sign and decrypt attributes should be clear.
    //
    // For Data object, the contents of unique should be of type TPM2B_DIGEST
    // and should be computed from components of the sensitive area of the object
    // as follows:
    // unique := Hash(seedValue || sensitive)
    //
    // An object description requires a TPM2B_PUBLIC structure and may require a
    // TPMT_SENSITIVE structure. When the structure is stored off the TPM, the TPMT_SENSITIVE
    // structure is encrypted within a TPM2B_PRIVATE structure.
    pub fn new_data_object(sensitive: &[u8]) -> Self {
        TpmtPublic {
            type_alg: TPM_ALG_KEYEDHASH,
            name_alg: TPM_ALG_SHA256,
            // TODO: handle object attributes
            object_attributes: newDefaultEkAttributes(),
            // TODO: handle auth policy
            auth_policy: newDefaultEkAuthPolicy(),
            parameters: TpmuPublicParms::new_keyed_hash_parms(),

            // TODO: fix unique
            unique: TpmuPublicId::new_keyed_hash(),
        }
    }
}

// TPM2B_PUBLIC
// An object description requires a TPM2B_PUBLIC structure and may require a TPMT_SENSITIVE
// structure. When the structure is stored off the TPM, the TPMT_SENSITIVE structure is
// encrypted within a TPM2B_PRIVATE structure
pub struct Tpm2bPublic {
    size: u16,
    public: TpmtPublic,
}

impl Tpm2bPublic {
    pub fn new_rsa(key: &rsa::RsaPublicKey) -> Self {
        let public: TpmtPublic = TpmtPublic::new_rsa(key);
        Tpm2bPublic {
            size: 0,
            public: public,
        }
    }

    pub fn new_data_object(parent: &rsa::RsaPublicKey, sensitive: &[u8]) -> Self {
        Tpm2bPublic {
            size: 0,
            public: TpmtPublic::new_data_object(sensitive),
        }
    }
}

// TPM2B_DATA
#[derive(Default, Debug)]
pub struct Tpm2bData {
    size: u16,
    buffer: Vec<u8>,
}
