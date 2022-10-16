use crate::device;
use crate::tcg;
use std::mem;

pub fn runCommand(
    tpm: device::TpmDeviceOps,
    command_code: tcg::TpmCc,
    handles: &[tcg::Handle],
    auths: &[TpmsAuthCommand],
    params: &[impl Tpm2StructOut],
) (u32, [u8]) {
    let mut command_buff = inout::StaticByteBuffer::new();

    for handle in handles.iter() {
        handle.pack(&mut command_buff);
    }
    for auth in auths.iter() {
        auth.pack(&mut command_buff);
    }
    for param in params.iter() {
        param.pack(&mut command_buff);
    }

    let mut header_buff = inout::StaticByteBuffer::new();

    if auth.len() > 0 {
        tcg::TPM_ST_SESSIONS.pack(&mut header_buff);
    } else {
        tcg::TPM_ST_NO_SESSIONS.pack(&mut header_buff);
    }

    let command_size: u32 = mem::size_of::<tcg::TpmiStCommandTag>() as u32
        + mem::size_of::<u32>() as u32
        + mem::size_of::<tcg::TpmCc>() as u32;

    command_size.pack(&mut header_buff);
    command_code.pack(&mut header_buff);

    let mut resp_buff = inout::StaticByteBuffer::new();
    match tpm.send_recv(&mut buffer, &mut resp_buff) {
        Err(err) => {
            return Err(errors::TpmError {
                msg: err.to_string(),
            })
        }
        _ => {
            let mut tag: tcg::TpmiStCommandTag = 0; 
            let mut response_size: u32 = 0;
            let mut response_code: u32 = 0;
            tag.unpack(resp_buff)?;
            response_size.unpack(buff)?;
            response_code.unpck(buff)?;
        }
    }
}
