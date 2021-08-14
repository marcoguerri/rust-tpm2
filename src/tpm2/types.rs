// Types
type TpmiStCommandTag = u16;
type TpmCc = u32;
type TpmAlgId = u16;

// TPM2 command codes
const TPM_CC_PCR_READ: TpmCc = 0x0000017E;

// Command tags
const TPM_ST_NO_SESSION: TpmiStCommandTag = 0x8001;

// Algorithms
const TPM_ALG_SHA256: TpmAlgId = 0x000B;
const TPM_ALG_SHA1: TpmAlgId = 0x0004;

#[derive(Debug, Clone)]
struct TpmError {
    msg: String,
}

impl Error for TpmError {}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TpmError: {}", self.msg)
    }
}

//
// TPM2B_DIGEST
//
struct Tpm2bDigest<'a> {
    size: u16,
    buffer: &'a [u8],
}

//
// TPML_DIGEST
//
struct TpmlDigest<'a> {
    count: u32,
    digests: &'a [Tpm2bDigest<'a>],
}

//
// TPMS_PCR_SELECTION
//

struct TpmsPcrSelection<'a> {
    hash: TpmAlgId,
    sizeof_select: u8,
    pcr_select: &'a [u8],
}

impl Tpm2StructOut for TpmsPcrSelection<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.hash.pack(buff);
        self.sizeof_select.pack(buff);
        buff.write_bytes(self.pcr_select);
    }
}

//
// TPML_PCR_SELECTION
//
struct TpmlPcrSelection<'a> {
    count: u32,
    pcr_selections: &'a [TpmsPcrSelection<'a>],
}

impl Tpm2StructOut for TpmlPcrSelection<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.count.pack(buff);
        for pcr_selection in self.pcr_selections.iter() {
            pcr_selection.pack(buff);
        }
    }
}
