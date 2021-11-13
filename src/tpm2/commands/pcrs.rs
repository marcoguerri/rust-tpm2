use crate::tpm2::types::tcg;

// PCRValues represents a set of PCR registers values
#[derive(Debug)]
pub struct PCRValues {
    algorithm: tcg::TpmAlgId,
    pcrs: Vec<Vec<u8>>,
}

impl PCRValues {
    pub fn new() -> Self {
        PCRValues {
            algorithm: tcg::TPM_ALG_SHA256,
            pcrs: Vec::new(),
        }
    }
}

// PCRSelection represents a selection of PCR registers
#[derive(Debug)]
pub struct PCRSelection {
    algorithm: tcg::TpmAlgId,
    pcrs: Vec<u8>,
}

impl PCRSelection {
    pub fn new() -> Self {
        PCRSelection {
            algorithm: tcg::TPM_ALG_SHA256,
            pcrs: Vec::new(),
        }
    }
}
