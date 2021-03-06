use crate::tpm2::serialization::inout;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::{Error, ErrorKind};

// Define a combined ReadWrite trait.
pub trait ReadWrite: io::Read + io::Write {}
impl<T: io::Read + io::Write> ReadWrite for T {}

// TpmRawIO implements communication with the TPM via /dev/tpm[0-9] device file
pub struct TpmRawIO {
    device_file: Option<File>,
}

// Implementation of ReadWrite trait for TpmRawIO
impl io::Read for TpmRawIO {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.device_file {
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "device file not open for reading",
                ))
            }
            Some(f) => match f.read(buf) {
                Err(err) => return Err(err),
                Ok(n) => Ok(n),
            },
        }
    }
}

impl io::Write for TpmRawIO {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.device_file {
            None => match OpenOptions::new().read(true).write(true).open("/dev/tpm0") {
                Err(err) => {
                    return Err(Error::new(
                        err.kind(),
                        format!("could not open /dev/tpm0: {}", err),
                    ))
                }
                Ok(f) => {
                    self.device_file = Some(f);
                }
            },
            Some(_) => (),
        }

        match &mut self.device_file {
            None => Err(Error::new(
                ErrorKind::Other,
                "device file is not set, cannot write input buffer",
            )),
            Some(f) => match f.write_all(buf) {
                Err(err) => Err(Error::new(
                    err.kind(),
                    format!("could not write buffer to TPM device {}", err),
                )),
                Ok(_) => Ok(buf.len()),
            },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "flush is not supported on TpmRawIO",
        ))
    }
}

// TpmDevice represents a TPM device implementing I/O operation
// via internal rw object
pub struct TpmDevice<'a> {
    pub rw: &'a mut dyn ReadWrite,
}

// TpmDeviceOps is a trait defining operations supported by TpmDevice objects
pub trait TpmDeviceOps {
    fn send_recv(
        &mut self,
        buff_command: &mut dyn inout::RwBytes,
        buff_answer: &mut dyn inout::RwBytes,
    ) -> io::Result<()>;
}

impl TpmDeviceOps for TpmDevice<'_> {
    fn send_recv(
        &mut self,
        buff_command: &mut dyn inout::RwBytes,
        buff_answer: &mut dyn inout::RwBytes,
    ) -> io::Result<()> {
        // send output buffer and read answer back
        match self.rw.write(&buff_command.to_bytes()) {
            Err(err) => {
                return Err(Error::new(
                    err.kind(),
                    format!("could not write output buffer to TPM: {}", err),
                ))
            }
            Ok(_) => (),
        }
        let mut buff_in = [0; 4096];
        match self.rw.read(&mut buff_in) {
            Err(err) => {
                return Err(Error::new(
                    err.kind(),
                    format!("could not read answer from TPM: {}", err),
                ))
            }
            _ => (),
        };
        buff_answer.write_bytes(&buff_in);
        Ok(())
    }
}
