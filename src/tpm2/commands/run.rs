use crate::device;
use crate::tcg;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;

use crate::tpm2::serialization::inout::RwBytes;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::serialization::inout::Tpm2StructOut;

use std::mem;
use std::result;

pub fn run_command(
    tpm: &mut device::raw::TpmDeviceOps,
    command_code: tcg::TpmCc,
    handles: &[tcg::Handle],
    auths: &[tcg::TpmsAuthCommand],
    params: &[&inout::Tpm2StructOut],
    response: &mut dyn inout::RwBytes,
) -> result::Result<(), errors::CommandError> {
    //
    // Assemble the body of the command, including handle area,
    // auth area, params area
    //
    let mut body_buff = inout::StaticByteBuffer::new();
    for handle in handles.iter() {
        handle.pack(&mut body_buff);
    }
    for auth in auths.iter() {
        let mut auth_buff = inout::StaticByteBuffer::new();
        auth.pack(&mut auth_buff);
        let size_auth: u32 = auth_buff.to_bytes().len() as u32;
        size_auth.pack(&mut body_buff);
        body_buff.write_bytes(auth_buff.to_bytes());
    }
    for param in params.iter() {
        let mut param_buff = inout::StaticByteBuffer::new();
        param.pack(&mut body_buff);
        param.pack(&mut param_buff);
    }

    //
    // Assemble the header, including tag, command code and command size
    //
    let mut header_buff = inout::StaticByteBuffer::new();
    if auths.len() > 0 {
        tcg::TPM_ST_SESSIONS.pack(&mut header_buff);
    } else {
        tcg::TPM_ST_NO_SESSION.pack(&mut header_buff);
    }
    let header_size: u32 = mem::size_of::<tcg::TpmiStCommandTag>() as u32
        + mem::size_of::<u32>() as u32
        + mem::size_of::<tcg::TpmCc>() as u32;
    let command_size: u32 = header_size + body_buff.to_bytes().len() as u32;
    command_size.pack(&mut header_buff);
    command_code.pack(&mut header_buff);

    //
    // Assemble the final command, packing header and body together
    //
    let mut command_buff = inout::StaticByteBuffer::new();
    command_buff.write_bytes(header_buff.to_bytes());
    command_buff.write_bytes(body_buff.to_bytes());

    let mut resp_buff = inout::StaticByteBuffer::new();
    let mut response_code: u32 = 0;

    match tpm.send_recv(&mut command_buff, &mut resp_buff) {
        Err(err) => {
            return Err(errors::CommandError::IoError(errors::IoError {
                msg: err.to_string(),
            }))
        }
        _ => {
            let mut tag: tcg::TpmiStCommandTag = 0;
            let mut response_size: u32 = 0;
            tag.unpack(&mut resp_buff)?;
            response_size.unpack(&mut resp_buff)?;
            response_code.unpack(&mut resp_buff)?;
            if response_code != 0 {
                return Err(errors::CommandError::ResponseError(errors::ResponseError {
                    error_code: response_code,
                }));
            }
            response
                .write_bytes(resp_buff.read_bytes(response_size as usize - header_size as usize));
        }
    }
    return Ok(());
}
