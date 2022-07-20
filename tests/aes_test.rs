
macro_rules! test_aead
{( $pkg:ident ) =>
{
mod $pkg {
    use $pkg::aead;
    use $pkg::aead::{AES_128_GCM, Algorithm, NonceSequence, OpeningKey, UnboundKey, BoundKey, SealingKey, Nonce, Aad};
    use $pkg::error::Unspecified;

    const AES_128_TEST_KEY: [u8; 16] = [12, 124, 200, 31, 226, 11, 135, 192, 12, 124, 200, 31, 226, 11, 135, 192 ];
    const TEST_NONCE: [u8; aead::NONCE_LEN] = [ 12, 124, 200, 31, 226, 11, 135, 192, 12, 124, 200, 31 ];
    const PLAINTEXT: &[u8] = "plaintext to be encrypted".as_bytes();

    struct NotANonce(Vec<u8>);

    impl NotANonce {
        fn from(value: Vec<u8>) -> Self {
            NotANonce(value)
        }
    }

    impl NonceSequence for NotANonce {
        fn advance(&mut self) -> Result<Nonce, Unspecified> {
            let mut nonce = [0u8; aead::NONCE_LEN];
            nonce.copy_from_slice(&self.0[0..aead::NONCE_LEN]);
            Ok(Nonce::assume_unique_for_key(nonce))
        }
    }

    struct AeadConfig {
        algorithm: &'static Algorithm,
        key: Vec<u8>,
        nonce: Vec<u8>,
        aad: String
    }

    impl AeadConfig {
        fn new(algorithm: &'static Algorithm, key: &[u8], nonce: &[u8], aad: &str) -> AeadConfig {
            AeadConfig {
                algorithm: algorithm,
                key: Vec::from(key),
                nonce: Vec::from(nonce),
                aad: String::from(aad)
            }
        }

        fn key(&self) -> UnboundKey {
            UnboundKey::new(self.algorithm, &self.key).unwrap()
        }
        fn aad(&self) -> Aad<String> {
            Aad::from(self.aad.clone())
        }
        fn nonce(&self) -> impl NonceSequence {
            //RngNonce{}
            //NotANonce::new()
            NotANonce::from( self.nonce.clone())
        }
    }

    #[test]
    fn test_aes_128_gcm() -> Result<(), String> {
        let config = AeadConfig::new(&AES_128_GCM, &AES_128_TEST_KEY, &TEST_NONCE, "test");
        let mut in_out = Vec::from(PLAINTEXT);

        test_aead(config, &mut in_out)?;


        Ok(())
    }

    fn  test_aead(config: AeadConfig, in_out: &mut Vec<u8>) -> Result<Vec<u8>, String> {
        let mut sealing_key = SealingKey::new(config.key(), config.nonce());
        let mut opening_key = OpeningKey::new(config.key(), config.nonce());

        let plaintext = in_out.clone();
        println!("Plaintext: {:?}", plaintext);

        let tag = sealing_key.seal_in_place_separate_tag(config.aad(), in_out.as_mut_slice()).map_err(|x| x.to_string() )?;
        let cipher_text = in_out.clone();
        println!("Ciphertext: {:?}", cipher_text);
        assert_ne!(plaintext, cipher_text);

        in_out.extend(tag.as_ref());

        let result_plaintext = opening_key.open_in_place(config.aad(), in_out).map_err(|x| x.to_string() )?;
        assert_eq!(plaintext, result_plaintext);

        println!("Roundtrip: {:?}", result_plaintext);


        Ok(Vec::from(result_plaintext))
    }
}}}

mod test_aead {
    test_aead!(ring);
}