/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 */

use crate::ec::PKCS8_DOCUMENT_MAX_LEN;
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::Document;
use crate::ptr::{LcPtr, NonNullPtr};
use crate::rand::SecureRandom;
use crate::signature::{KeyPair, Signature, VerificationAlgorithm};
use crate::{cbb, cbs, constant_time, sealed, test};
use aws_lc_sys::{
    EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key, EVP_PKEY_new_raw_private_key,
    EVP_parse_private_key, EVP_PKEY,
};
use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::os::raw::{c_int, c_uint};
use std::ptr::null_mut;
use untrusted::Input;

pub(crate) const ED25519_PRIVATE_KEY_LEN: usize = aws_lc_sys::ED25519_PRIVATE_KEY_LEN as usize;
pub(crate) const ED25519_PRIVATE_KEY_PREFIX_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = aws_lc_sys::ED25519_PUBLIC_KEY_LEN as usize;
const ED25519_SIGNATURE_LEN: usize = aws_lc_sys::ED25519_SIGNATURE_LEN as usize;
const ED25519_SEED_LEN: usize = 32;

#[derive(Debug)]
pub struct EdDSAParameters;

impl sealed::Sealed for EdDSAParameters {}

impl VerificationAlgorithm for EdDSAParameters {
    #[inline]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        unsafe {
            if 1 != aws_lc_sys::ED25519_verify(
                msg.as_slice_less_safe().as_ptr(),
                msg.len(),
                signature.as_slice_less_safe().as_ptr(),
                public_key.as_slice_less_safe().as_ptr(),
            ) {
                return Err(Unspecified);
            }
            Ok(())
        }
    }
}

pub struct Ed25519KeyPair {
    private_key: [u8; ED25519_PRIVATE_KEY_LEN],
    public_key: Ed25519PublicKey,
}

impl Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Ed25519KeyPair {{ public_key: PublicKey(\"{}\") }}",
            test::to_hex(&self.public_key)
        ))
    }
}

#[derive(Clone)]
pub struct Ed25519PublicKey {
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl AsRef<[u8]> for Ed25519PublicKey {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.public_key
    }
}

impl Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "PublicKey(\"{}\")",
            test::to_hex(&self.public_key)
        ))
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;
    #[inline(always)]
    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

pub(crate) unsafe fn generate_key(rng: &dyn SecureRandom) -> Result<LcPtr<*mut EVP_PKEY>, ()> {
    let mut seed = [0u8; ED25519_SEED_LEN];
    rng.fill(&mut seed)?;

    let mut public_key = MaybeUninit::<[u8; ED25519_PUBLIC_KEY_LEN]>::uninit();
    let mut private_key = MaybeUninit::<[u8; ED25519_PRIVATE_KEY_LEN]>::uninit();
    aws_lc_sys::ED25519_keypair_from_seed(
        public_key.as_mut_ptr().cast(),
        private_key.as_mut_ptr().cast(),
        seed.as_ptr(),
    );

    LcPtr::new(EVP_PKEY_new_raw_private_key(
        aws_lc_sys::EVP_PKEY_ED25519,
        null_mut(),
        private_key.assume_init().as_ptr(),
        ED25519_PRIVATE_KEY_PREFIX_LEN,
    ))
}

impl Ed25519KeyPair {
    pub fn generate_pkcs8(rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = generate_key(rng)?;

            let mut cbb = cbb::build_CBB(PKCS8_DOCUMENT_MAX_LEN);
            if 1 != aws_lc_sys::EVP_marshal_private_key(&mut cbb, *evp_pkey) {
                aws_lc_sys::CBB_cleanup(&mut cbb);
                return Err(Unspecified);
            }

            let mut pkcs8_bytes_ptr = MaybeUninit::<*mut u8>::uninit();
            let mut out_len = MaybeUninit::<usize>::uninit();
            if 1 != aws_lc_sys::CBB_finish(
                &mut cbb,
                pkcs8_bytes_ptr.as_mut_ptr(),
                out_len.as_mut_ptr(),
            ) {
                aws_lc_sys::CBB_cleanup(&mut cbb);
                return Err(Unspecified);
            }
            let pkcs8_bytes_ptr = LcPtr::new(pkcs8_bytes_ptr.assume_init())?;
            let out_len = out_len.assume_init();

            let bytes_slice = std::slice::from_raw_parts(*pkcs8_bytes_ptr, out_len);
            let mut pkcs8_bytes = [0u8; PKCS8_DOCUMENT_MAX_LEN];
            pkcs8_bytes[0..out_len].copy_from_slice(bytes_slice);

            Ok(Document {
                bytes: pkcs8_bytes,
                len: out_len,
            })
        }
    }

    pub fn from_seed_and_public_key(
        seed: &[u8],
        expected_public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        if seed.len() < ED25519_SEED_LEN {
            return Err(KeyRejected::inconsistent_components());
        }

        unsafe {
            let mut public_key = MaybeUninit::<[u8; ED25519_PUBLIC_KEY_LEN]>::uninit();
            let mut private_key = MaybeUninit::<[u8; ED25519_PRIVATE_KEY_LEN]>::uninit();
            aws_lc_sys::ED25519_keypair_from_seed(
                public_key.as_mut_ptr().cast(),
                private_key.as_mut_ptr().cast(),
                seed.as_ptr(),
            );
            let public_key = public_key.assume_init();
            let private_key = private_key.assume_init();

            constant_time::verify_slices_are_equal(expected_public_key, &public_key)
                .map_err(|_| KeyRejected::inconsistent_components())?;

            Ok(Self {
                private_key,
                public_key: Ed25519PublicKey { public_key },
            })
        }
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let mut cbs = cbs::build_CBS(pkcs8);

            let evp_pkey = LcPtr::new(EVP_parse_private_key(&mut cbs))
                .map_err(|_| KeyRejected::invalid_encoding())?;

            validate_ed25519_evp_pkey(evp_pkey.as_non_null())?;

            let mut private_key = [0u8; ED25519_PRIVATE_KEY_LEN];
            let mut out_len: usize = ED25519_PRIVATE_KEY_LEN;
            if 1 != EVP_PKEY_get_raw_private_key(*evp_pkey, private_key.as_mut_ptr(), &mut out_len)
            {
                return Err(KeyRejected::wrong_algorithm());
            }

            let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
            let mut out_len: usize = ED25519_PUBLIC_KEY_LEN;
            if 1 != EVP_PKEY_get_raw_public_key(*evp_pkey, public_key.as_mut_ptr(), &mut out_len) {
                return Err(KeyRejected::wrong_algorithm());
            }
            private_key[ED25519_PUBLIC_KEY_LEN..].copy_from_slice(&public_key);

            let key_pair = Self {
                private_key,
                public_key: Ed25519PublicKey { public_key },
            };

            Ok(key_pair)
        }
    }

    pub fn from_pkcs8_maybe_unchecked(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        Self::from_pkcs8(pkcs8)
    }

    #[inline]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Self::try_sign(self, msg).expect("ED25519 signing failed")
    }

    #[inline]
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Unspecified> {
        unsafe {
            let mut sig_bytes = MaybeUninit::<[u8; ED25519_SIGNATURE_LEN]>::uninit();
            if 1 != aws_lc_sys::ED25519_sign(
                sig_bytes.as_mut_ptr().cast(),
                msg.as_ptr(),
                msg.len(),
                self.private_key.as_ptr(),
            ) {
                return Err(Unspecified);
            }
            let sig_bytes = sig_bytes.assume_init();

            Ok(Signature::new(|slice| {
                slice[0..ED25519_SIGNATURE_LEN].copy_from_slice(&sig_bytes);
                ED25519_SIGNATURE_LEN
            }))
        }
    }
}

#[inline]
pub(crate) unsafe fn validate_ed25519_evp_pkey(
    evp_pkey: NonNullPtr<*mut EVP_PKEY>,
) -> Result<(), KeyRejected> {
    const ED25519_KEY_TYPE: c_int = aws_lc_sys::EVP_PKEY_ED25519;
    const ED25519_MIN_BITS: c_uint = 253;
    const ED25519_MAX_BITS: c_uint = 256;

    let key_type = aws_lc_sys::EVP_PKEY_id(*evp_pkey);
    if key_type != ED25519_KEY_TYPE {
        return Err(KeyRejected::wrong_algorithm());
    }

    let bits = aws_lc_sys::EVP_PKEY_bits(*evp_pkey);
    let bits = bits as c_uint;
    if bits < ED25519_MIN_BITS {
        return Err(KeyRejected::too_small());
    }

    if bits > ED25519_MAX_BITS {
        return Err(KeyRejected::too_large());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ed25519::Ed25519KeyPair;
    use crate::test;

    #[test]
    fn test_generate_pkcs8() {
        let document = Ed25519KeyPair::generate_pkcs8(&crate::rand::SystemRandom::new()).unwrap();

        let _key_pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    }

    #[test]
    fn test_from_pkcs8() {
        let key = test::from_dirty_hex(
            r#"302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"#,
        );

        let key_pair = Ed25519KeyPair::from_pkcs8(&key).unwrap();

        assert_eq!("Ed25519KeyPair { public_key: PublicKey(\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\") }", 
                   format!("{:?}", key_pair));
    }
}
