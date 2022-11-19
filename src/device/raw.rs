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
    fn read(&mut self, buf: &mut [u8]) -> result::Result<usize, errors::DeviceIoError> {
        match &mut self.device_file {
            None => {
                return Err(errors::DeviceIoError {
                    msg: "device file not open for reading",
                });
            }
            Some(f) => {
                let n = f.read(buf)?;
                Ok(n)
            }
        }
    }
}

impl io::Write for TpmRawIO {
    fn write(&mut self, buf: &[u8]) -> result::Result<usize, errors::DeviceIoError> {
        match self.device_file {
            None => match OpenOptions::new().read(true).write(true).open("/dev/tpm0") {
                Err(err) => {
                    return Err(errors::DeviceIoError {
                        msg: format!("could not open /dev/tpm0: {}", err),
                    });
                }
                Ok(f) => {
                    self.device_file = Some(f);
                }
            },
            Some(_) => (),
        }

        match &mut self.device_file {
            None => Err(errors::DeviceIoError {
                msg: "device file is not set, cannot write input buffer",
            }),
            Some(f) => {
                let n = f.write_all(buf)?;
                Ok(n)
            }
        }
    }

    fn flush(&mut self) -> result::Result<(), errors::DeviceIoError> {
        Err(errors::DeviceIoError {
            msg: "flush is not supported on TpmRawIO",
        })
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
    ) -> result::Result<(), errors::DeviceIoError>;
}

impl TpmDeviceOps for TpmDevice<'_> {
    fn send_recv(
        &mut self,
        buff_command: &mut dyn inout::RwBytes,
        buff_answer: &mut dyn inout::RwBytes,
    ) -> result::Result<(), errors::DeviceIoError> {
        self.rw.write(&buff_command.to_bytes())?;
        let mut buff_in = [0; 4096];
        self.rw.read(&mut buff_in)?;
        buff_answer.write_bytes(&buff_in);
        Ok(())
    }
}
