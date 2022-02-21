use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::types::tcg;
use bytebuffer::ByteBuffer;
use std::mem;
use std::result;

pub struct StartupCommand {
    header: CommandHeader,
    startup_type: tcg::TpmSu,
}

impl StartupCommand {
    // new creates a new StartupCommand object based on tag and startup_type
    pub fn new(
        tag: tcg::TpmiStCommandTag,
        startup_type: tcg::TpmSu,
    ) -> result::Result<Self, errors::TpmError> {
        Ok(StartupCommand {
            header: CommandHeader::new(
                tag,
                mem::size_of::<tcg::TpmiStCommandTag>() as u32
                    + mem::size_of::<u32>() as u32
                    + mem::size_of::<tcg::TpmCc>() as u32
                    + mem::size_of::<tcg::TpmSu>() as u32,
                tcg::TPM_CC_STARTUP,
            ),

            startup_type: startup_type,
        })
    }
}

impl inout::Tpm2StructOut for StartupCommand {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.header.pack(buff);
        self.startup_type.pack(buff);
    }
}

// TPM2_Startup response
#[derive(Default, Debug)]
pub struct StartupResponse {
    header: ResponseHeader,
}

impl inout::Tpm2StructIn for StartupResponse {
    fn unpack(&mut self, buff: &mut ByteBuffer) -> result::Result<(), errors::TpmError> {
        match self.header.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        Ok(())
    }
}

impl StartupResponse {
    // new builds a StartupResponse structure from a a bytes buffer
    pub fn new(buff: &mut ByteBuffer) -> result::Result<Self, errors::TpmError> {
        let mut resp: StartupResponse = Default::default();
        let unpack_result = resp.unpack(buff);
        match unpack_result {
            Ok(_) => Ok(resp),
            Err(error) => Err(error),
        }
    }
}

pub fn tpm2_startup(startup_type: tcg::TpmSu) -> result::Result<(), errors::TpmError> {
    let mut tpm_device: raw::TpmDevice = raw::TpmDevice {
        rw: &mut tcp::TpmSwtpmIO::new(),
    };

    let cmd_startup = match StartupCommand::new(tcg::TPM_ST_NO_SESSION, startup_type) {
        Ok(cmd_startup) => cmd_startup,
        Err(error) => return Err(error),
    };

    let mut buffer = ByteBuffer::new();
    inout::pack(&[cmd_startup], &mut buffer);

    let mut resp_buffer = ByteBuffer::new();
    match tpm_device.send_recv(&buffer, &mut resp_buffer) {
        Err(err) => {
            return Err(errors::TpmError {
                msg: err.to_string(),
            })
        }
        _ => (),
    }
    let resp = StartupResponse::new(&mut resp_buffer);
    match resp {
        _ => Ok(()),
        Err(error) => Err(error),
    }
}
