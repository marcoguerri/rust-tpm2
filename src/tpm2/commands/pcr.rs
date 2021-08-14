use crate::device::rawtpm;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::Tpm2StructOut;
use crate::tpm2::types::tcg;
use bytebuffer::ByteBuffer;
use std::mem;
use std::result;

// tpm2_pcr_read calls tpm2_pcr_read function returning the content of all
// PCR Registers in SHA1 and SHA256 form.
pub fn tpm2_pcr_read() -> result::Result<u32, errors::TpmError> {
    let pcr_selections_sha256 = tcg::TpmsPcrSelection {
        hash: tcg::TPM_ALG_SHA256,
        // select all 24 PCRs, 0-23
        sizeof_select: 3,
        pcr_select: &[0xFF, 0xFF, 0xFF],
    };

    let pcr_selections_sha1 = tcg::TpmsPcrSelection {
        hash: tcg::TPM_ALG_SHA1,
        // select all 24 PCRs, 0-23
        sizeof_select: 3,
        pcr_select: &[0xFF, 0xFF, 0xFF],
    };

    let pcr_selection = tcg::TpmlPcrSelection {
        count: 2,
        pcr_selections: &[pcr_selections_sha1, pcr_selections_sha256],
    };

    let mut buffer_pcr_selection = ByteBuffer::new();
    pcr_selection.pack(&mut buffer_pcr_selection);

    // create PcrReadCommand structure, provisional command_size is 0, will
    // be updated later.
    let cmd_pcr_read = super::commands::PcrReadCommand {
        tag: tcg::TPM_ST_NO_SESSION,
        command_size: 0,
        command_code: tcg::TPM_CC_PCR_READ,
        pcr_selection_in: pcr_selection,
    };

    // calculate command size in octets as
    // tag + command code + command size + pcr_selection
    let pcr_selection_size = buffer_pcr_selection.to_bytes().len();
    if pcr_selection_size > u32::MAX as usize {
        errors::TpmError {
            msg: String::from("pcr_selection size is too big"),
        };
    }
    let cmd_pcr_read_partial_size = mem::size_of_val(&cmd_pcr_read.tag)
        + mem::size_of_val(&cmd_pcr_read.command_size)
        + mem::size_of_val(&cmd_pcr_read.command_code);

    println!("cmd_pcr_read_partial_size: {}", cmd_pcr_read_partial_size);
    let command_size: u32 = cmd_pcr_read_partial_size as u32 + pcr_selection_size as u32;

    let mut buffer = ByteBuffer::new();
    inout::pack(&[cmd_pcr_read], &mut buffer);

    // write buffer to TPM device and read back response
    let tpm_device: rawtpm::TpmDevice = rawtpm::TpmDevice {
        rw: &rawtpm::TpmRawIO {},
    };

    println!(
        "command serialization for cmd_pcr_read: {}",
        hex::encode(buffer.to_bytes())
    );
    Ok(0)
}
