use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::types::tcg;
use bytebuffer::ByteBuffer;
use std::result;

// Size of the initial part of PcrReadCommand, not including PCR selection structure
// TODO: this should be hidden from outside.
pub const PCR_READ_PREAMBLE_SIZE: u32 = 10;

// tpm2_pcr_read command
pub struct PcrReadCommand<'a> {
    // TODO: Turn these fields into private
    pub tag: tcg::TpmiStCommandTag,
    pub command_size: u32,
    pub command_code: tcg::TpmCc,
    pub pcr_selection_in: tcg::TpmlPcrSelection<'a>,
}

impl inout::Tpm2StructOut for PcrReadCommand<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.tag.pack(buff);
        self.command_size.pack(buff);
        self.command_code.pack(buff);
        self.pcr_selection_in.pack(buff);
    }
}

// tpm2_pcr_read response
pub struct PcrReadResponse<'a> {
    tag: tcg::TpmiStCommandTag,
    response_size: u32,
    response_code: tcg::TpmCc,
    random_bytes: tcg::Tpm2bDigest<'a>,
    pcr_update_counter: u32,
    pcr_selection_in: tcg::TpmlPcrSelection<'a>,
    pcr_values: tcg::TpmlDigest<'a>,
}

impl inout::Tpm2StructIn for PcrReadResponse<'_> {
    fn unpack(&self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        Ok(())
    }
}
