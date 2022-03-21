use crate::tpm2::errors;
use std::mem;
use std::result;

use crate::tpm2::serialization::inout;

// Types
pub type TpmiStCommandTag = u16;
pub type TpmCc = u32;
pub type TpmRc = u32;
pub type TpmAlgId = u16;
pub type TpmSu = u16;
pub type TpmaObject = u32;
pub type TpmKeyBits = u16;

// Derived types
// TODO: extend further these types

pub type TpmiAlgPublic = TpmAlgId;
pub type TpmiAlgHash = TpmAlgId;
pub type TpmiAlgKdf = TpmAlgId;
pub type TpmiAlgRsaScheme = TpmAlgId;

pub type TpmiAlgKeyedHashScheme = TpmAlgId;

pub type TpmiRsaKeyBits = TpmKeyBits;

// TPM2 command codes
pub const TPM_CC_PCR_READ: TpmCc = 0x0000017E;
pub const TPM_CC_STARTUP: TpmCc = 0x00000144;

pub const TPM2_NUM_PCR_BANKS: usize = 16;
pub const TPM2_MAX_PCRS: usize = 24;
pub const HASH_SIZE: usize = 512;
pub const TPM2_PCR_SELECT_MAX: usize = (TPM2_MAX_PCRS + 7) / 8;

// TPM2 startup types
pub const TPM_SU_CLEAR: TpmSu = 0x0000;
pub const TPM_SU_STATE: TpmSu = 0x0001;

// Command tags
pub const TPM_ST_NO_SESSION: TpmiStCommandTag = 0x8001;

// Algorithms
pub const TPM_ALG_SHA256: TpmAlgId = 0x000B;
pub const TPM_ALG_KEYEDHASH: TpmAlgId = 0x0008;
pub const TPM_ALG_SYMCIPHER: TpmAlgId = 0x0025;
pub const TPM_ALG_RSA: TpmAlgId = 0x0001;
pub const TPM_ALG_ECC: TpmAlgId = 0x0023;

// TPMU_HA union
pub union TpmuHa {
    pub sha1: [u8; 20usize],
    pub sha256: [u8; 32usize],
    pub sha384: [u8; 38usize],
    pub sha512: [u8; 64usize],
    pub sm3256: [u8; 32usize],
}

// TPM2B_DIGEST
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bDigest {
    size: u16,
    buffer: [u8; mem::size_of::<TpmuHa>()],
}

impl Tpm2bDigest {
    pub fn new() -> Self {
        Tpm2bDigest {
            size: 0,
            buffer: [0; mem::size_of::<TpmuHa>()],
        }
    }
    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer[..]
    }

    pub fn from_vec(size: u16, buffer: &[u8]) -> Self {
        let mut digest_buffer = [0; mem::size_of::<TpmuHa>()];
        digest_buffer.clone_from_slice(buffer);
        return Tpm2bDigest {
            size: size,
            buffer: digest_buffer,
        };
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

// TPMU_PUBLIC_PARMS
#[derive(Copy, Clone)]
pub union TpmuPublicParms {
    pub pubkeyed_hash_details: TpmsKeyedHashParms,
}

// TPMU_PUBLIC_ID
pub union TpmuPublicId {
    pub keyed_hash: Tpm2bDigest,
    pub sym: Tpm2bDigest,
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: TpmsEccPoint,
    pub derive: TpmsDerive,
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
    details: TpmuSchemeKeyedHash,
}

// TPMS_KEYEDHASH_PARMS
#[derive(Copy, Clone, Debug)]
pub struct TpmsKeyedHashParms {
    scheme: TpmtKeyedHashScheme,
}

// TPMS_SYMCIPHER_PARMS
#[derive(Default, Debug)]
pub struct TpmsSymcipherParms {}

// TPMS_ECC_PARMS
#[derive(Default, Debug)]
pub struct TpmsEccParms {}

// TPMS_ASYM_PARMS
#[derive(Default, Debug)]
pub struct TpmsAsymParms {}

// TPMT_SYM_DEF_OBJECT
#[derive(Default, Debug)]
pub struct TpmtSymDefObject {
    //algorithm: TPMI_ALG_SYM_OBJECT,
//key_bits: TPMU_SYM_KEY_BITS,
//mode: TPMU_SYM_MODE,
//details: TPMU_SYM_DETAILS,
}

// TPMT_RSA_SCHEME
pub struct TpmtRsaScheme {
    scheme: TpmiAlgRsaScheme,
    details: TpmuAsymScheme,
}

// TPMS_RSA_PARMS
pub struct TpmsRsaParams {
    symmetric: TpmtSymDefObject,
    scheme: TpmtRsaScheme,
    key_bits: TpmiRsaKeyBits,
    exponent: u32,
}

// TPMS_ECC_PARMS
#[derive(Default, Debug)]
pub struct TpmsEccParams {
    symmetric: TpmtSymDefObject,
    //scheme: TPMT_ECC_SCHEME,
    //curveID: TPMI_ECC_CURVE,
    //kdf: TPMT_KDF_SCHEME,
}

// TPM2B_LABEL
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bLabel {
    size: u16,
    buffer: [u8; 512usize],
}

// TPM2B_ECC_PARAMETER
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bEccParameter {
    size: u16,
    buffer: [u8; 256usize],
}

// TPM2B_PUBLIC_KEY_RSA
#[derive(Copy, Clone, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    buffer: [u8; 512usize],
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

// TPM2B_PUBLIC
pub struct Tpm2BPublic {
    size: u16,
    public: TpmtPublic,
}

// TPM2B_DATA
#[derive(Default, Debug)]
pub struct Tpm2BData {
    size: u16,
    buffer: Vec<u8>,
}
