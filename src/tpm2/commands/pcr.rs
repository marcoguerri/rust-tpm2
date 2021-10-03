use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
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
    // build PcrSelection structures, selecting all PCR Registers, for both SHA1 and SHA256
    let pcr_selections_sha256 = tcg::TpmsPcrSelection {
        hash: tcg::TPM_ALG_SHA256,
        sizeof_select: 3,
        pcr_select: &[0xFF, 0xFF, 0xFF],
    };

    let pcr_selections_sha1 = tcg::TpmsPcrSelection {
        hash: tcg::TPM_ALG_SHA1,
        sizeof_select: 3,
        pcr_select: &[0xFF, 0xFF, 0xFF],
    };

    let pcr_selection = tcg::TpmlPcrSelection {
        count: 2,
        pcr_selections: &[pcr_selections_sha1, pcr_selections_sha256],
    };

    let mut buffer_pcr_selection = ByteBuffer::new();
    pcr_selection.pack(&mut buffer_pcr_selection);

    let cmd_pcr_read =
        match super::commands::NewPcrReadCommand(tcg::TPM_ST_NO_SESSION, pcr_selection) {
            Ok(cmd_pcr_read) => cmd_pcr_read,
            Err(error) => return Err(error),
        };

    let mut buffer = ByteBuffer::new();
    inout::pack(&[cmd_pcr_read], &mut buffer);

    let mut tpm_device: raw::TpmDevice = raw::TpmDevice {
        rw: &mut tcp::TpmSwtpmIO::new(),
    };

    println!(
        "command serialization for cmd_pcr_read: {}",
        hex::encode(buffer.to_bytes())
    );

    let mut resp_buffer = ByteBuffer::new();
    match tpm_device.send_recv(&buffer, &mut resp_buffer) {
        Err(err) => println!("error during send_recv: {}", err),
        Ok(_) => println!("answer received correctly!"),
    }
    println!(
        "got response buffer as {}",
        hex::encode(resp_buffer.to_bytes())
    );
    Ok(0)
}
