use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::types::tcg;
use std::mem;
use std::result;

pub struct StartupCommand {
    header: CommandHeader,
    startup_type: tcg::TpmSu,
}

impl StartupCommand {
    // new creates a new StartupCommand object based on tag and startup_type
    pub fn new(tag: tcg::TpmiStCommandTag, startup_type: tcg::TpmSu) -> Self {
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
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.header.pack(buff);
        self.startup_type.pack(buff);
    }
}

// TPM2_Startup response
pub struct StartupResponse {
    header: ResponseHeader,
}

impl inout::Tpm2StructIn for StartupResponse {
    fn unpack(
        &mut self,
        buff: &mut dyn inout::RwBytes,
    ) -> result::Result<(), errors::DeserializationError> {
        self.header.unpack(buff)?
        Ok(())
    }
}

impl StartupResponse {
    // new builds a StartupResponse structure from a a bytes buffer
    pub fn new(buff: &mut dyn inout::RwBytes) -> result::Result<Self, errors::DeserializationError> {
        let mut resp = StartupResponse {
            header: ResponseHeader::new(),
        };
        resp.unpack(buff)?;
    }
}

pub fn tpm2_startup(startup_type: tcg::TpmSu) -> result::Result<(), errors::TpmError> {
    let mut tpm_device: raw::TpmDevice = raw::TpmDevice {
        rw: &mut tcp::TpmSwtpmIO::new(),
    };

    let cmd_startup = StartupCommand::new(tcg::TPM_ST_NO_SESSION, startup_type);

    let mut buffer = inout::StaticByteBuffer::new();
    inout::pack(&[cmd_startup], &mut buffer);

    let mut resp_buffer = inout::StaticByteBuffer::new();
    match tpm_device.send_recv(&mut buffer, &mut resp_buffer) {
        Err(err) => {
            return Err(errors::TpmError {
                msg: err.to_string(),
            })
        }
        _ => (),
    }
    Ok(())
}
