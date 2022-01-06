use crate::tpm2::types::tcg;
use std::collections::HashMap;
use std::ops::Index;

pub const MAX_PCR: u32 = 23;

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

    pub fn get_map(&self) -> &HashMap<u32, Vec<u8>> {
        return &self.pcrs;
    }

    pub fn merge(&mut self, map: &HashMap<u32, Vec<u8>>) {
        self.pcrs
            .extend(map.into_iter().map(|(k, v)| (k.clone(), v.clone())));
    }
}

impl std::fmt::Display for PCRValues {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for pcr in 0..MAX_PCR + 1 as u32 {
            if self.pcrs.contains_key(&pcr) {
                match self.pcrs.get(&pcr) {
                    Some(digest) => {
                        let _ = write!(f, "{} / {}\n", pcr, hex::encode(digest));
                    }
                    None => {
                        let _ = write!(f, "N/A\n");
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

    pub fn get_map(&self) -> &HashMap<tcg::TpmAlgId, PCRValues> {
        &self.pcrs
    }

    pub fn merge(&mut self, map: &HashMap<tcg::TpmAlgId, PCRValues>) {
        for algo in map.keys() {
            if self.pcrs.contains_key(algo) {
                if let Some(pcr_values) = self.pcrs.get_mut(algo) {
                    pcr_values.merge(map.index(algo).get_map());
                } else {
                    panic!("cannot mutate pcr values");
                }
            } else {
                let mut pcr_values: PCRValues = PCRValues::new();
                pcr_values.merge(map.index(algo).get_map());
                self.pcrs.insert(*algo, pcr_values);
            }
        }
    }
}

impl std::fmt::Display for PCRs {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (key, value) in &self.pcrs {
            let _ = write!(f, "Algo: {}\n", key);
            let _ = write!(f, "{}", value);
            let _ = write!(f, "\n");
        }
        Ok(())
    }
}

// PCRSelection represents a selection of PCR registers to manipulate with TPM commands
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
