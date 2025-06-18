#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        digest::{self, Context},
        rand::SystemRandom,
        signature::{
            EcdsaKeyPair, KeyPair, UnparsedPublicKey, VerificationAlgorithm,
            ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
        },
    };

    #[test]
    fn test_sign_verify_digest_basic() {
        // Generate a key pair
        let key_pair = match EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING) {
            Ok(kp) => kp,
            Err(e) => {
                panic!("Failed to generate key pair: {:?}", e);
            }
        };

        // Create a message and digest it
        let message = b"Hello, world!";
        let mut digest_ctx = Context::new(&digest::SHA256);
        digest_ctx.update(message);
        let digest = digest_ctx.finish();

        // Sign the digest
        let signature = match key_pair.sign_digest(&digest) {
            Ok(sig) => sig,
            Err(e) => {
                panic!("Failed to sign digest: {:?}", e);
            }
        };

        // Verify using the public key
        let public_key =
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key_pair.public_key().as_ref());

        // Verify the signature using verify_digest_sig
        let verify_result = ECDSA_P256_SHA256_FIXED.verify_digest_sig(
            public_key.as_ref(),
            &digest,
            signature.as_ref(),
        );

        match verify_result {
            Ok(_) => println!("✓ Digest verification successful"),
            Err(e) => panic!("✗ Digest verification failed: {:?}", e),
        }

        // Also test regular sign/verify for comparison
        let rng = SystemRandom::new();
        let regular_signature = match key_pair.sign(&rng, message) {
            Ok(sig) => sig,
            Err(e) => {
                panic!("Failed to sign message: {:?}", e);
            }
        };

        let regular_verify_result = public_key.verify(message, regular_signature.as_ref());
        match regular_verify_result {
            Ok(_) => println!("✓ Regular verification successful"),
            Err(e) => panic!("✗ Regular verification failed: {:?}", e),
        }
    }
}
