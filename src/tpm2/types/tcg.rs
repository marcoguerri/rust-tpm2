use crate::tpm2::errors;
use bytebuffer::ByteBuffer;
use std::result;

use crate::tpm2::serialization::inout;

// Types
pub type TpmiStCommandTag = u16;
pub type TpmCc = u32;
pub type TpmAlgId = u16;

// TPM2 command codes
pub const TPM_CC_PCR_READ: TpmCc = 0x0000017E;

// Command tags
pub const TPM_ST_NO_SESSION: TpmiStCommandTag = 0x8001;

// Algorithms
pub const TPM_ALG_SHA256: TpmAlgId = 0x000B;
pub const TPM_ALG_SHA1: TpmAlgId = 0x0004;

// TPM2B_DIGEST
#[derive(Default, Debug)]
pub struct Tpm2bDigest<'a> {
    size: u16,
    buffer: &'a [u8],
}

// TPML_DIGEST
#[derive(Default, Debug)]
pub struct TpmlDigest<'a> {
    count: u32,
    digests: &'a [Tpm2bDigest<'a>],
}

// TPMS_PCR_SELECTION
#[derive(Default, Debug)]
pub struct TpmsPcrSelection<'a> {
    pub hash: TpmAlgId,
    pub sizeof_select: u8,
    pub pcr_select: &'a [u8],
}

impl inout::Tpm2StructOut for TpmsPcrSelection<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.hash.pack(buff);
        self.sizeof_select.pack(buff);
        buff.write_bytes(self.pcr_select);
    }
}

impl inout::Tpm2StructIn for TpmsPcrSelection<'_> {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.hash.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        match self.sizeof_select.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        Ok(())
    }
}

// TPML_PCR_SELECTION
#[derive(Default, Debug)]
pub struct TpmlPcrSelection<'a> {
    pub count: u32,
    pub pcr_selections: &'a [TpmsPcrSelection<'a>],
}

impl inout::Tpm2StructOut for TpmlPcrSelection<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.count.pack(buff);
        for pcr_selection in self.pcr_selections.iter() {
            pcr_selection.pack(buff);
        }
    }
}

impl inout::Tpm2StructIn for TpmlPcrSelection<'_> {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.count.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        Ok(())
    }
}
