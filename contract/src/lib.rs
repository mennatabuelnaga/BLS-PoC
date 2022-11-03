
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;
use blsttc::{Signature, PublicKey};

#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct VerifySignature;
#[near_bindgen]
impl VerifySignature {
    #[payable]
    pub fn verify_sig(&mut self, message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {   
        let signature: [u8; 96] = signature.try_into().expect("invalid signature");
        let public_key: [u8; 48] = public_key.try_into().expect("invalid pk");
        let sig = Signature::from_bytes(signature).expect("couldn't read signature");
        let pk = PublicKey::from_bytes(public_key).expect("couldn't read pk");
        pk.verify(&sig, message)
        
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, VMContext};

    use blsttc::{PublicKey, SecretKey};


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




        let sk = SecretKey::random();

        let pk = sk.public_key();

        let message = "hello".try_to_vec().unwrap();

        
        let sig = sk.sign(message.clone());
        
        println!("sk: {:?}", sk);
        println!("pk: {:?}", pk);
        println!("sig: {:?}", sig);

        println!("pk_bytes: {:?}", pk.as_bytes());
        println!("sig_bytes: {:?}", sig.as_bytes());
        println!("sig_bytes: {:?}", sig.as_bytes());


        let sig_bytes = sig.to_bytes().to_vec();

        let pk_bytes= pk.to_bytes().to_vec();
        let verified = contract.verify_sig(message, sig_bytes, pk_bytes);


        println!("verified: {:?}", verified);


    }

}