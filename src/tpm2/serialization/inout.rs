use crate::tpm2::errors;
use std::convert::TryFrom;
use std::result;

const MAX_TPM2_IO_BUF_SIZE: usize = 4096;

// RwBytes is a generic interface for reading and writing bytes.
// It might be backed by a statically or dynamicall allocated
// buffer
pub trait RwBytes {
    // write_bytes writes a certain amount of bytes
    // to the underlying buffer, changing the
    // underlying write pointer
    fn write_bytes(&mut self, bytes: &[u8]);
    // read_bytes reads a certain amount of bytes
    // from the underlying buffer, changing the
    // underlying read pointer
    fn read_bytes(&mut self, size: usize) -> &[u8];
    // to_bytes returs a slice representation of the whole
    // buffer
    fn to_bytes(&self) -> &[u8];
}

// StaticByteBuffer implements a bytes buffer with static allocation
pub struct StaticByteBuffer {
    wrptr: usize,
    rdptr: usize,
    buf: [u8; MAX_TPM2_IO_BUF_SIZE],
}

impl RwBytes for StaticByteBuffer {
    fn write_bytes(&mut self, bytes: &[u8]) {
        if self.wrptr + bytes.len() > self.buf.len() {
            panic!(
                "buffer lenght not sufficient for write_bytes: {} > {}",
                self.wrptr + bytes.len(),
                self.buf.len(),
            );
        }
        self.buf[self.wrptr..self.wrptr + bytes.len()].clone_from_slice(bytes);
        self.wrptr += bytes.len();
    }

    fn read_bytes(&mut self, size: usize) -> &[u8] {
        if self.rdptr + size > self.wrptr {
            panic!(
                "buffer lenght not sufficient for read_bytes: {} > {}",
                self.rdptr + size,
                self.wrptr,
            );
        }
        self.rdptr += size;
        return &self.buf[self.rdptr - size..self.rdptr];
    }

    fn to_bytes(&self) -> &[u8] {
        return &self.buf[0..self.wrptr];
    }
}

impl StaticByteBuffer {
    pub fn new() -> Self {
        StaticByteBuffer {
            wrptr: 0,
            rdptr: 0,
            buf: [0; MAX_TPM2_IO_BUF_SIZE],
        }
    }
}

// Tpm2StructOut is a trait for TPM objects which can be serialized in
// big endian byte stream for TPM operations
pub trait Tpm2StructOut {
    fn pack(&self, buff: &mut dyn RwBytes);
}

// Tpm2StructIn is a trait for TPM objects which can be deserialized from
// a byte stream
pub trait Tpm2StructIn {
    fn unpack(&mut self, buff: &mut dyn RwBytes) -> result::Result<(), errors::TpmError>;
}

// impl_tpm2_io is a macro which implments Tpm2StructIn and Tpm2StructOut for
// primitive types.
macro_rules! impl_tpm2_io {
    ($T: ident) => {
        impl Tpm2StructOut for $T {
            fn pack(&self, buff: &mut dyn RwBytes) {
                buff.write_bytes(&self.to_be_bytes()[..]);
            }
        }

        impl Tpm2StructIn for $T {
            fn unpack(&mut self, buff: &mut dyn RwBytes) -> result::Result<(), errors::TpmError> {
                let byte_array = <[u8; size_of!($T)]>::try_from(&buff.read_bytes(size_of!($T))[..]);
                match byte_array {
                    Ok(byte_array) => {
                        *self = $T::from_be_bytes(byte_array);
                        Ok(())
                    }
                    Err(_) => Err(errors::TpmError {
                        msg: String::from("could not prepare byteArray"),
                    }),
                }
            }
        }
    };
}

impl_tpm2_io! { u8 }
impl_tpm2_io! { u16 }
impl_tpm2_io! { u32 }
impl_tpm2_io! { u64 }

// normally belong to Command/Response structures
pub fn pack(fields: &[impl Tpm2StructOut], buff: &mut dyn RwBytes) {
    for field in fields.iter() {
        field.pack(buff)
    }
}
