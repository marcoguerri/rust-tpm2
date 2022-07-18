use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::types::tcg;
use std::result;

#[derive(Debug, Copy, Clone)]
pub struct CommandHeader {
    pub tag: tcg::TpmiStCommandTag,
    pub command_size: u32,
    pub command_code: tcg::TpmCc,
}

#[derive(Debug, Copy, Clone)]
pub struct ResponseHeader {
    pub tag: tcg::TpmiStCommandTag,
    pub response_size: u32,
    pub response_code: tcg::TpmRc,
}

impl ResponseHeader {
    pub fn new() -> Self {
        ResponseHeader {
            tag: 0,
            response_size: 0,
            response_code: 0,
        }
    }
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
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.tag.pack(buff);
        self.command_size.pack(buff);
        self.command_code.pack(buff);
    }
}

impl inout::Tpm2StructIn for ResponseHeader {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
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
