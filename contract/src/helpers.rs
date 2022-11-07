use sha2::{Sha256, Digest};
use zeropool_bn::{arith, Fq, G1};

use crate::VerifySignature;

// This is 0xf1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263, the last mulitple of the modulus before 2^256
const LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256: arith::U256 = arith::U256([
    0xf587_14d7_0a38_f4c2_2ca2_bc72_3a70_f263,
    0xf1f5_883e_65f8_20d0_9991_5c90_8786_b9d3,
]);


impl VerifySignature {


    fn mod_u256(&self, num: arith::U256, modulus: arith::U256) -> arith::U256 {
        let mut reduced = num;
        // the library does not provide a function to do a modulo reduction
        // we use the provided add function adding a 0
        // we also need to iterate here as the library does the modulus only once
        while reduced > modulus {
            reduced.add(&arith::U256::zero(), &modulus);
        }

        reduced
    }


    pub fn hash_to_try_and_increment(&self, message: &[u8]) -> Option<G1> {
        let mut c = 0..255;

        // Add counter suffix
        // This message should be: ciphersuite || 0x01 || message || ctr
        // For the moment we work with message || ctr until a tag is decided
        let mut v = [&message[..], &[0x00]].concat();
        let position = v.len() - 1;

        // `Hash(data||ctr)`
        // The modulus of bn256 is low enough to trigger several iterations of this loop
        // We instead compute attempted_hash = `Hash(data||ctr)` mod Fq::modulus
        // This should trigger less iterations of the loop
        let point = c.find_map(|ctr| {
            v[position] = ctr;
            let hash = &self.calculate_sha256(&v)[0..32];
            // this should never fail as the length of sha256 is max 256
            let attempted_hash = arith::U256::from_slice(hash).unwrap();

            // Reducing the hash modulo the field modulus biases point odds
            // As a prevention, we should discard hashes above the highest multiple of the modulo
            if attempted_hash >= LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256 {
                return None;
            }

            let module_hash = &self.mod_u256(attempted_hash, Fq::modulus());
            let mut s = [0u8; 32];
            module_hash
                .to_big_endian(&mut s)
                .ok()
                .and_then(|_| self.arbitrary_string_to_g1(&s).or(None))
        });
        // Return error if no valid point was found
        point
    }

    fn calculate_sha256(&self, bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let mut hash = [0; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }


    fn arbitrary_string_to_g1(&self, data: &[u8]) -> Option<G1> {
        let mut v = vec![0x02];
        v.extend(data);

        let point = G1::from_compressed(&v).unwrap();
        Some(point)

        // Ok(point)
    }


}


