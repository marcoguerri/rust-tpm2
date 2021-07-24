use bytebuffer::ByteBuffer;
use std::result;
use std::{error::Error, fmt};

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
// Tpm2BDigest
//
struct Tpm2BDigest {
    size: u16,
    buffer: Vec<u8>,
}

//
// TPMS_PCR_SELECTION
//

struct TpmsPcrSelection<'a> {
    hash: TpmAlgId,
    sizeof_select: u8,
    pcr_select: &'a [u8],
}

impl Tpm2Struct for TpmsPcrSelection<'_> {
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

impl Tpm2Struct for TpmlPcrSelection<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.count.pack(buff);
        for pcr_selection in self.pcr_selections.iter() {
            pcr_selection.pack(buff);
        }
    }
}

// tpm2_pcr_read command
struct PcrReadCommand<'a> {
    tag: TpmiStCommandTag,
    command_size: u32,
    command_code: TpmCc,
    pcr_selection_in: TpmlPcrSelection<'a>,
}

impl Tpm2Struct for PcrReadCommand<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.tag.pack(buff);
        self.command_size.pack(buff);
        self.command_code.pack(buff);
        self.pcr_selection_in.pack(buff);
    }
}

// tpm2_pcr_read response
struct PcrReadResponse {
    tag: TpmiStCommandTag,
    response_size: u32,
    response_code: TpmCc,
    random_bytes: Tpm2BDigest,
}

// Tpm2Struct is a trait for object which can serialize themselves in
// big endian stream for TPM operations
trait Tpm2Struct {
    fn pack(&self, buff: &mut ByteBuffer);
}

// Primitive types have copy semantics, everything else has move semantics
macro_rules! impl_tpm2_pack {
    ($T: ident) => {
        impl Tpm2Struct for $T {
            fn pack(&self, buff: &mut ByteBuffer) {
                buff.write_bytes(&self.to_be_bytes()[..]);
            }
        }
    };
}

impl_tpm2_pack! { u8 }
impl_tpm2_pack! { u16 }
impl_tpm2_pack! { u32 }
impl_tpm2_pack! { u64 }

// pack packs multiple fields that implement the Tpm2Struct trait. These fields
// normally belong to Command/Response structures
fn pack(fields: &[impl Tpm2Struct], buff: &mut ByteBuffer) {
    for field in fields.iter() {
        field.pack(buff)
    }
}

// tpm2_pcr_read calls tpm2_pcr_read function returning the content of all
// PCR Registers in SHA1 and SHA256 form.
fn tpm2_pcr_read() -> result::Result<u32, TpmError> {
    let pcr_selections_sha256 = TpmsPcrSelection {
        hash: TPM_ALG_SHA256,
        // select all 24 PCRs, 0-23
        sizeof_select: 3,
        pcr_select: &[0xFF, 0xFF, 0xFF],
    };

    let pcr_selections_sha1 = TpmsPcrSelection {
        hash: TPM_ALG_SHA1,
        // select all 24 PCRs, 0-23
        sizeof_select: 3,
        pcr_select: &[0xFF, 0xFF, 0xFF],
    };

    let pcr_selection = TpmlPcrSelection {
        count: 2,
        pcr_selections: &[pcr_selections_sha1, pcr_selections_sha256],
    };

    // calculate command size in octets as
    // tag + command code + command size + pcr_selection
    let mut buffer_pcr_selection = ByteBuffer::new();
    pcr_selection.pack(&mut buffer_pcr_selection);
    let pcr_selection_size = buffer_pcr_selection.to_bytes().len();
    if pcr_selection_size > u32::MAX as usize {
        TpmError {
            msg: String::from("pcr_selection size is too big"),
        };
    }

    let command_size: u32 = 10 + pcr_selection_size as u32;

    // create PcrReadCommand structure
    let cmd_pcr_read = PcrReadCommand {
        tag: TPM_ST_NO_SESSION,
        command_size: command_size,
        command_code: TPM_CC_PCR_READ,
        pcr_selection_in: pcr_selection,
    };

    let mut buffer = ByteBuffer::new();
    pack(&[cmd_pcr_read], &mut buffer);

    println!(
        "command serialization for cmd_pcr_read: {}",
        hex::encode(buffer.to_bytes())
    );
    Ok(0)
}

fn main() {
    let ret = match tpm2_pcr_read() {
        Ok(ret) => ret,
        Err(_) => 1,
    };
    println!("retcode {}", ret);
}
