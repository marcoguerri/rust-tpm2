use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
use crate::tpm2::commands::pcrs::PCRSelection;
use crate::tpm2::commands::pcrs::PCRValues;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::serialization::inout::Tpm2StructOut;
use crate::tpm2::types::tcg;
use bytebuffer::ByteBuffer;
use std::mem;
use std::result;

// TPM2_PCR_Read command
pub struct PcrReadCommand {
    header: CommandHeader,
    pcr_selection_in: tcg::TpmlPcrSelection,
}

impl PcrReadCommand {
    // new creates a new PcrReadCommand object based on tag and pcr selection
    pub fn new(
        tag: tcg::TpmiStCommandTag,
        pcr_selection: tcg::TpmlPcrSelection,
    ) -> result::Result<Self, errors::TpmError> {
        let mut buffer_pcr_selection = ByteBuffer::new();
        pcr_selection.pack(&mut buffer_pcr_selection);
        let pcr_selection_size = buffer_pcr_selection.to_bytes().len();

        if pcr_selection_size > u32::MAX as usize {
            errors::TpmError {
                msg: String::from("pcr_selection size is too big"),
            };
        }

        Ok(PcrReadCommand {
            header: CommandHeader::new(
                tag,
                mem::size_of::<tcg::TpmiStCommandTag>() as u32
                    + mem::size_of::<u32>() as u32
                    + mem::size_of::<tcg::TpmCc>() as u32
                    + pcr_selection_size as u32,
                tcg::TPM_CC_PCR_READ,
            ),
            pcr_selection_in: pcr_selection,
        })
    }
}

impl inout::Tpm2StructOut for PcrReadCommand {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.header.pack(buff);
        self.pcr_selection_in.pack(buff);
    }
}

// TPM2_PCR_Read response
#[derive(Default, Debug)]
pub struct PcrReadResponse {
    header: ResponseHeader,
    pcr_update_counter: u32,
    pcr_selection_in: tcg::TpmlPcrSelection,
    pcr_values: tcg::TpmlDigest,
}

impl inout::Tpm2StructIn for PcrReadResponse {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.header.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        match self.pcr_update_counter.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        match self.pcr_selection_in.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        match self.pcr_values.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        Ok(())
    }
}

impl PcrReadResponse {
    // new builds a PcrReadResponse structure from a a bytes buffer
    pub fn new(buff: &mut ByteBuffer) -> result::Result<Self, errors::TpmError> {
        let mut resp: PcrReadResponse = Default::default();
        let unpack_result = resp.unpack(buff);
        match unpack_result {
            Ok(_) => Ok(resp),
            Err(error) => Err(error),
        }
    }
}

// tpm2_pcr_read issues a TPM2_PCR_Read command with a PCR selection based on input PCRSelection
pub fn tpm2_pcr_read(selection: &[PCRSelection]) -> result::Result<PCRValues, errors::TpmError> {
    let pcr_selection = tcg::TpmlPcrSelection {
        count: 2,
        pcr_selections: vec![
            tcg::TpmsPcrSelection {
                hash: tcg::TPM_ALG_SHA1,
                sizeof_select: 3,
                pcr_select: vec![0xFF, 0xFF, 0xFF],
            },
            tcg::TpmsPcrSelection {
                hash: tcg::TPM_ALG_SHA256,
                sizeof_select: 3,
                pcr_select: vec![0xFF, 0xFF, 0xFF],
            },
        ],
    };

    let mut buffer_pcr_selection = ByteBuffer::new();
    pcr_selection.pack(&mut buffer_pcr_selection);

    let cmd_pcr_read = match PcrReadCommand::new(tcg::TPM_ST_NO_SESSION, pcr_selection) {
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
    let resp = PcrReadResponse::new(&mut resp_buffer);
    match resp {
        Ok(_) => Ok(PCRValues::new()),
        Err(err) => Err(err),
    }
}
