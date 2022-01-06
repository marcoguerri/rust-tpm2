use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::types::tcg;
use bytebuffer::ByteBuffer;
use std::result;

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

impl CommandHeader {
    pub fn new(tag: tcg::TpmiStCommandTag, command_size: u32, command_code: tcg::TpmCc) -> Self {
        CommandHeader {
            tag: tag,
            command_size: command_size,
            command_code: command_code,
        }
    }
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
