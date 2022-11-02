
use bls_signatures::{Signature, PublicKey, Serialize};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;

#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct VerifySignature;
// deployment storage ~ 22 NEAR
#[near_bindgen]
impl VerifySignature {
    #[payable]
    pub fn verify_sig(&mut self, message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
        let sig = Signature::from_bytes(&signature[..]).expect("couldn't read signature");
        let pk = PublicKey::from_bytes(&public_key[..]).expect("couldn't read pk");
        pk.verify(sig, message)
        
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, VMContext};

    use bls_signatures::{PrivateKey, Serialize};
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;



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



        let mut rng = ChaCha8Rng::seed_from_u64(12);

        let sk = PrivateKey::generate(&mut rng);

        let pk = sk.public_key();

        let message = "hello".try_to_vec().unwrap();

        
        let sig = sk.sign(message.clone());
        
        println!("sk: {:?}", sk);
        println!("pk: {:?}", pk);
        println!("sig: {:?}", sig);

        println!("pk_bytes: {:?}", pk.as_bytes());
        println!("sig_bytes: {:?}", sig.as_bytes());
        println!("sig_bytes: {:?}", sig.as_bytes());


        let sig_bytes = sig.as_bytes();

        let pk_bytes= pk.as_bytes();
        let verified = contract.verify_sig(message, sig_bytes, pk_bytes);


        println!("verified: {:?}", verified);


    }

}