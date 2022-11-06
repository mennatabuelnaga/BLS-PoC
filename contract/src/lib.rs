
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;
use near_sys::alt_bn128_pairing_check;
use zeropool_bn::{G2, Group};

#[repr(C)]
struct PairingElem([u8; 64], [u8; 128]); // (G1, G2) uncompressed


#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct VerifySignature;
#[near_bindgen]
impl VerifySignature {
    // e(H(m)_G1, pk_G2) = e(sig_G1, G2)
    // e(sig_G1, nG2) e(H(m)_G1, pk_G2) =? 1

    // e(nG1, sig_G2) e(pk_G1, H(m)_G2)

    // (hash_g1, pk_g2)  (sig_g1, -G2)
   

    #[payable]
    pub fn verify_sig(&mut self, message_hash: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
        let hash_g1: [u8; 64] = message_hash.try_into().unwrap();
        let pk_g2: [u8; 128] = public_key.try_into().unwrap();
        let sig_g1: [u8; 64] = signature.try_into().unwrap();
        let n_g2: [u8; 128] = (-G2::one()).try_to_vec().unwrap().try_into().unwrap();
        println!("*******************************************");

        println!("hash_g1 = : {:?}", hash_g1);
        println!("*******************************************");
        println!("pk_g2 = : {:?}", pk_g2);
        println!("*******************************************");


        println!("sig_g1 = : {:?}", sig_g1);
        println!("*******************************************");

        println!("n_g2 = : {:?}", n_g2);
        println!("*******************************************");



        let buf = [(hash_g1, pk_g2), (sig_g1, n_g2)];

        // let g1: [u8; 64] = [80, 12, 4, 181, 61, 254, 153, 52, 127, 228, 174, 24, 144, 95, 235, 26, 197, 188, 219, 91, 4, 47, 98, 98, 202, 199, 94, 67, 211, 223, 197, 21, 65, 221, 184, 75, 69, 202, 13, 56, 6, 233, 217, 146, 159, 141, 116, 208, 81, 224, 146, 124, 150, 114, 218, 196, 192, 233, 253, 31, 130, 152, 144, 29];
        // let g2: [u8; 128] = [34, 54, 229, 82, 80, 13, 200, 53, 254, 193, 250, 1, 205, 60, 38, 172, 237, 29, 18, 82, 187, 98, 113, 152, 184, 251, 223, 42, 104, 148, 253, 25, 79, 39, 165, 18, 195, 165, 215, 155, 168, 251, 250, 2, 215, 214, 193, 172, 187, 84, 54, 168, 27, 100, 161, 155, 144, 95, 199, 238, 88, 238, 202, 46, 247, 97, 33, 56, 78, 174, 171, 15, 245, 5, 121, 144, 88, 81, 102, 133, 118, 222, 81, 214, 74, 169, 27, 91, 27, 23, 80, 55, 43, 97, 101, 24, 168, 29, 75, 136, 229, 2, 55, 77, 60, 200, 227, 210, 172, 194, 232, 45, 151, 46, 248, 206, 193, 250, 145, 84, 78, 176, 74, 210, 0, 106, 168, 30];
        
        // let buf: [PairingElem; 2] = [PairingElem(g1, g2), PairingElem(g1, g2)];
        
       


        let mut res = 0;
       
        unsafe {
                res = alt_bn128_pairing_check(
                    core::mem::size_of_val(&buf) as u64,
                    buf.as_ptr() as *const u64 as u64,
                );
            }
            println!("{:?}", res);
            res == 1


        
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {

    use super::*;
    use bls_signatures_rs::MultiSignature;
    use bls_signatures_rs::bn256::{Bn256, PublicKey};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, VMContext};
    use zeropool_bn::G1;
    // use near_sys::alt_bn128_pairing_check;
    
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

        // let rng = &mut rand::thread_rng();

        let sk = hex::decode("a55e93edb1350916bf5beea1b13d8f198ef410033445bcb645b65be5432722f1").unwrap();


        let pk = Bn256.derive_public_key(&sk).unwrap();

        let message: &[u8] = b"sample";

        let sig = Bn256.sign(&sk, &message).unwrap();

        // println!("sk: {:?}", sk);
        // println!("pk: {:?}", pk);
        // println!("sig: {:?}", sig);

        println!("sk_bytes len: {:?}", sk.len()); // 32

        println!("pk_bytes len: {:?}", pk.len()); // 65

        println!("sig_bytes len: {:?}", sig.len()); //33
        let pk_2 = PublicKey::from_compressed(pk.as_ref()).expect("pk error");
        

        println!("pk2 len: {:?}", pk_2.to_uncompressed().unwrap().len()); // 128

        
        let x = G1::from_compressed(sig.as_ref()).unwrap();
        let y = x.try_to_vec().unwrap();

        println!("sig2 len: {:?}", y.len()); // 64

        let hash = Bn256.hash_to_try_and_increment2(message).unwrap();
        let hash_bytes = hash.try_to_vec().unwrap();
        println!("hash_bytes len: {:?}", hash_bytes.len()); //64

        // Check whether the aggregated signature corresponds to the aggregated public key
        Bn256.verify(&sig, &message, &pk).unwrap();
        let verified = contract.verify_sig(hash_bytes, y, pk_2.to_uncompressed().unwrap(), );
        println!("YES?????? {:?}", verified);






    }

}