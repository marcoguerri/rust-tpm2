use crate::tpm2::errors;
use bytebuffer::ByteBuffer;
use std::result;

use crate::tpm2::serialization::inout;

// Types
pub type TpmiStCommandTag = u16;
pub type TpmCc = u32;
pub type TpmRc = u32;
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
pub struct Tpm2bDigest {
    size: u16,
    buffer: Vec<u8>,
}

// TPML_DIGEST
#[derive(Default, Debug)]
pub struct TpmlDigest {
    count: u32,
    // digests can contain at most 8 entries. From TPM 2.0 Spec, Structures,
    // TPML_DIGEST is defined as digests[count]{:8}
    digests: Vec<Tpm2bDigest>,
}

// TPMS_PCR_SELECTION
#[derive(Default, Debug)]
pub struct TpmsPcrSelection {
    pub hash: TpmAlgId,
    pub sizeof_select: u8,
    pub pcr_select: Vec<u8>,
}

impl inout::Tpm2StructOut for TpmsPcrSelection {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.hash.pack(buff);
        self.sizeof_select.pack(buff);
        buff.write_bytes(self.pcr_select.as_slice());
    }
}

impl inout::Tpm2StructIn for TpmsPcrSelection {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.hash.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        match self.sizeof_select.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        self.pcr_select = buff.read_bytes(self.sizeof_select as usize);
        Ok(())
    }
}

impl inout::Tpm2StructIn for TpmlDigest {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.count.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        for count in 0..self.count {
            let mut size: u16 = 0;
            match size.unpack(buff) {
                Err(err) => return Err(err),
                _ => (),
            }
            let buffer = buff.read_bytes(size as usize);
            self.digests.push(Tpm2bDigest { size, buffer });
        }
        Ok(())
    }
}

// TPML_PCR_SELECTION
#[derive(Default, Debug)]
pub struct TpmlPcrSelection {
    pub count: u32,
    pub pcr_selections: Vec<TpmsPcrSelection>,
}

impl inout::Tpm2StructOut for TpmlPcrSelection {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.count.pack(buff);
        for pcr_selection in self.pcr_selections.iter() {
            pcr_selection.pack(buff);
        }
    }
}

impl inout::Tpm2StructIn for TpmlPcrSelection {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.count.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        for count in 0..self.count {
            let mut pcr_selection: TpmsPcrSelection = Default::default();
            match pcr_selection.unpack(buff) {
                Err(err) => return Err(err),
                _ => {
                    self.pcr_selections.push(pcr_selection);
                }
            }
        }

        Ok(())
    }
}
