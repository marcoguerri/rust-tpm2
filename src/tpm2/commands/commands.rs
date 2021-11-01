use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::types::tcg;
use bytebuffer::ByteBuffer;
use std::mem;
use std::result;

use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::serialization::inout::Tpm2StructOut;

#[derive(Default, Debug)]
pub struct CommandHeader {
    tag: tcg::TpmiStCommandTag,
    command_size: u32,
    command_code: tcg::TpmCc,
}

#[derive(Default, Debug)]
pub struct ResponseHeader {
    tag: tcg::TpmiStCommandTag,
    response_size: u32,
    response_code: tcg::TpmRc,
}

impl inout::Tpm2StructOut for CommandHeader {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.tag.pack(buff);
        self.command_size.pack(buff);
        self.command_code.pack(buff);
    }
}

impl inout::Tpm2StructIn for ResponseHeader {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.tag.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        };
        match self.response_size.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        };
        match self.response_code.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        Ok(())
    }
}

// TPM2_PCR_Read command
pub struct PcrReadCommand {
    header: CommandHeader,
    pcr_selection_in: tcg::TpmlPcrSelection,
}

pub fn NewPcrReadCommand(
    tag: tcg::TpmiStCommandTag,
    pcr_selection: tcg::TpmlPcrSelection,
) -> result::Result<PcrReadCommand, errors::TpmError> {
    let mut buffer_pcr_selection = ByteBuffer::new();
    pcr_selection.pack(&mut buffer_pcr_selection);
    let pcr_selection_size = buffer_pcr_selection.to_bytes().len();

    if pcr_selection_size > u32::MAX as usize {
        errors::TpmError {
            msg: String::from("pcr_selection size is too big"),
        };
    }

    Ok(PcrReadCommand {
        header: CommandHeader {
            tag: tag,
            command_size: mem::size_of::<tcg::TpmiStCommandTag>() as u32
                + mem::size_of::<u32>() as u32
                + mem::size_of::<tcg::TpmCc>() as u32
                + pcr_selection_size as u32,
            command_code: tcg::TPM_CC_PCR_READ,
        },
        pcr_selection_in: pcr_selection,
    })
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

// NewPcrReadResponse builds a PcrReadResponse structure from a a bytes buffer
pub fn NewPcrReadResponse(
    buff: &mut ByteBuffer,
) -> result::Result<PcrReadResponse, errors::TpmError> {
    let mut resp: PcrReadResponse = Default::default();
    let unpack_result = resp.unpack(buff);
    match unpack_result {
        Ok(_) => Ok(resp),
        Err(error) => Err(error),
    }
}
