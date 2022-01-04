use crate::tpm2::types::tcg;
use std::collections::HashMap;

// PCRValues represents a set of PCR registers values
#[derive(Debug)]
pub struct PCRValues {
    pcrs: HashMap<u32, Vec<u8>>,
}

impl PCRValues {
    pub fn new() -> Self {
        PCRValues {
            pcrs: HashMap::new(),
        }
    }

    pub fn add(&mut self, pcr_num: u32, hash: Vec<u8>) {
        self.pcrs.insert(pcr_num, hash);
    }
}

impl std::fmt::Display for PCRValues {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for pcr in 0..25 as u32 {
            if self.pcrs.contains_key(&pcr) {
                match self.pcrs.get(&pcr) {
                    Some(digest) => {
                        write!(f, "{} / {}\n", pcr, hex::encode(digest));
                    }
                    None => {
                        write!(f, "N/A\n");
                    }
                }
            }
        }
        Ok(())
    }
}

// PCRs represents a set of multi-algorithm PCR values
#[derive(Debug)]
pub struct PCRs {
    pcrs: HashMap<tcg::TpmAlgId, PCRValues>,
}

// PCRs represents a set of multi-algorithm PCR values
impl PCRs {
    pub fn new() -> Self {
        PCRs {
            pcrs: HashMap::new(),
        }
    }

    pub fn add(&mut self, algo: tcg::TpmAlgId, pcr_num: u32, value: Vec<u8>) {
        if !self.pcrs.contains_key(&algo) {
            self.pcrs.insert(algo, PCRValues::new());
        }

        match self.pcrs.get_mut(&algo) {
            Some(pcr_values) => {
                pcr_values.add(pcr_num, value);
            }

            None => {}
        }
    }
}

impl std::fmt::Display for PCRs {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (key, value) in &self.pcrs {
            write!(f, "Algo: {}\n", key);
            write!(f, "{}", value);
            write!(f, "\n");
        }
        Ok(())
    }
}

// PCRSelection represents a selection of PCR registers
#[derive(Debug)]
pub struct PCRSelection {
    algorithm: tcg::TpmAlgId,
    pcrs: Vec<u8>,
}

impl PCRSelection {
    pub fn new(pcrs: Vec<u8>) -> Self {
        PCRSelection {
            algorithm: tcg::TPM_ALG_SHA256,
            pcrs: pcrs,
        }
    }

    pub fn get_pcrs(&self) -> &Vec<u8> {
        &self.pcrs
    }

    pub fn get_algo(&self) -> tcg::TpmAlgId {
        self.algorithm
    }
}
