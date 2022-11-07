
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;
use near_sys::alt_bn128_pairing_check;
use zeropool_bn::{G2, Group, G1};
mod helpers;


#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct VerifySignature;
#[near_bindgen]
impl VerifySignature {

    // e(H(m)_G1, pk_G2) =? e(sig_G1, G2)
    // (hash_g1, pk_g2) (sig_g1, -G2) =? 1
    #[payable]
    pub fn verify_sig(&mut self, message_hash: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
        let hash_g1: [u8; 64] = message_hash.try_into().unwrap();
        let pk_g2: [u8; 128] = public_key.try_into().unwrap();
        let sig_g1: [u8; 64] = signature.try_into().unwrap();
        let n_g2: [u8; 128] = (-G2::one()).try_to_vec().unwrap().try_into().unwrap();
        

        let buf = [(hash_g1, pk_g2), (sig_g1, n_g2)];
   
        let mut res = 0;
       
        unsafe {
                res = alt_bn128_pairing_check(
                    core::mem::size_of_val(&buf) as u64,
                    buf.as_ptr() as *const u64 as u64,
                );
            }
        res == 1

    }


    #[payable]
    pub fn verify_sig2(&mut self, message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
        let msg_hash: G1 = self.hash_to_try_and_increment(&message).expect("couldn't hash msg to G1");
        let hash_g1: [u8; 64] = msg_hash.try_to_vec().expect("couldn't unwrap hash_g1").try_into().expect("**couldn't unwrap hash_g1");
        let pk_g2: [u8; 128] = public_key.try_into().expect("couldn't unwrap pk_g2");
        let sig_g1: [u8; 64] = signature.try_into().expect("couldn't unwrap sig_g1");
        let n_g2: [u8; 128] = (-G2::one()).try_to_vec().expect("couldn't unwrap n_g2").try_into().expect("**couldn't unwrap n_g2");
        

        let buf = [(hash_g1, pk_g2), (sig_g1, n_g2)];
   
        let mut res = 0;
       
        unsafe {
                res = alt_bn128_pairing_check(
                    core::mem::size_of_val(&buf) as u64,
                    buf.as_ptr() as *const u64 as u64,
                );
            }
        res == 1

    }

}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {

    use std::ops::Mul;

    use super::*;
    use bls_signatures_rs::MultiSignature;
    use bls_signatures_rs::bn256::Bn256;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, VMContext};
    use zeropool_bn::Fr;    
    fn get_context(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .signer_account_id("bob_near".parse().unwrap())
            .is_view(is_view)
            .build()
    }

    #[test]
    fn verify_msg() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = VerifySignature::default();

       

        let rng = &mut rand::thread_rng();

        let sk: Fr = Fr::random(rng);
        let pk_g2_vec = (G2::one().mul(sk)).try_to_vec().expect("pk");
        let msg = "hello".as_bytes();
        let msg_hash_g1 = Bn256.hash_to_try_and_increment2(msg).unwrap();
        let msg_hash_g1_vec = msg_hash_g1.try_to_vec().unwrap();
        
        let sig_g1 = msg_hash_g1.mul(sk);
        let sig_g1_vec = sig_g1.try_to_vec().unwrap();

        println!("pk_g2_vec len: {:?}", pk_g2_vec.len()); // 128
        println!("msg_hash_g1_vec len: {:?}", msg_hash_g1_vec.len()); // 64
        println!("sig_g1_vec len: {:?}", sig_g1_vec.len()); // 64

        let verified = contract.verify_sig(msg_hash_g1_vec.clone(), sig_g1_vec.clone(), pk_g2_vec.clone());

        println!("1-VERIFIED? {:?}", verified);


        let verified = contract.verify_sig2(msg.to_vec(), sig_g1_vec, pk_g2_vec);

        println!("2-VERIFIED? {:?}", verified);


    }

}