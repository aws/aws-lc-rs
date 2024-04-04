// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

/// PKCS#8 Encoding Functions
pub(in crate::rsa) mod pkcs8 {
    use crate::{
        cbb::LcCBB,
        error::{KeyRejected, Unspecified},
        ptr::LcPtr,
    };
    use aws_lc::{EVP_marshal_private_key, EVP_PKEY};

    // Based on a measurement of a PKCS#8 v1 document containing an RSA-8192 key with an additional 1% capacity buffer
    // rounded to an even 64-bit words (4678 + 1% + padding ≈ 4728).
    const PKCS8_FIXED_CAPACITY_BUFFER: usize = 4728;

    pub(in crate::rsa) fn encode_v1_der(key: &LcPtr<EVP_PKEY>) -> Result<Vec<u8>, Unspecified> {
        let mut buffer = vec![0u8; PKCS8_FIXED_CAPACITY_BUFFER];
        let out_len = {
            let mut cbb = LcCBB::new_fixed(<&mut [u8; PKCS8_FIXED_CAPACITY_BUFFER]>::try_from(
                buffer.as_mut_slice(),
            )?);

            if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), *key.as_const()) } {
                return Err(Unspecified);
            }
            cbb.finish()?
        };

        buffer.truncate(out_len);

        Ok(buffer)
    }

    // Supports v1 and v2 encodings through a single API entry-point.
    pub(in crate::rsa) fn decode_der(pkcs8: &[u8]) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        LcPtr::try_from(pkcs8)
    }
}

/// [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)
///
/// PKCS #1: RSA Cryptography Specifications Version 2.2
pub(in crate::rsa) mod rfc8017 {
    use crate::{
        cbs,
        error::{KeyRejected, Unspecified},
        ptr::{DetachableLcPtr, LcPtr},
    };
    use aws_lc::{
        EVP_PKEY_assign_RSA, EVP_PKEY_new, RSA_parse_private_key, RSA_parse_public_key,
        RSA_public_key_to_bytes, EVP_PKEY,
    };
    use std::ptr::null_mut;

    /// DER encode a RSA public key to `RSAPublicKey` structure.
    pub(in crate::rsa) unsafe fn encode_public_key_der(
        pubkey: &LcPtr<EVP_PKEY>,
    ) -> Result<Box<[u8]>, ()> {
        let mut pubkey_bytes = null_mut::<u8>();
        let mut outlen: usize = 0;
        if 1 != RSA_public_key_to_bytes(
            &mut pubkey_bytes,
            &mut outlen,
            *pubkey.get_rsa().map_err(|_| Unspecified)?.as_const(),
        ) {
            return Err(());
        }
        let pubkey_bytes = LcPtr::new(pubkey_bytes)?;
        let pubkey_slice = pubkey_bytes.as_slice(outlen);
        let pubkey_vec = Vec::from(pubkey_slice);
        Ok(pubkey_vec.into_boxed_slice())
    }

    /// Decode a DER encoded `RSAPublicKey` structure.
    #[inline]
    pub(in crate::rsa) fn decode_public_key_der(
        public_key: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let mut cbs = unsafe { cbs::build_CBS(public_key) };

        let rsa = DetachableLcPtr::new(unsafe { RSA_parse_public_key(&mut cbs) })?;

        let pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_RSA(*pkey, *rsa) } {
            return Err(KeyRejected::unspecified());
        }

        rsa.detach();

        Ok(pkey)
    }

    /// Decodes a DER encoded `RSAPrivateKey` structure.
    #[inline]
    pub(in crate::rsa) fn decode_private_key_der(
        private_key: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
        let mut cbs = unsafe { cbs::build_CBS(private_key) };

        let rsa = DetachableLcPtr::new(unsafe { RSA_parse_private_key(&mut cbs) })?;

        let pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_RSA(*pkey, *rsa) } {
            return Err(Unspecified);
        }

        rsa.detach();

        Ok(pkey)
    }
}

/// [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)
///
/// Encodings that use the `SubjectPublicKeyInfo` structure.
pub(in crate::rsa) mod rfc5280 {
    use crate::{
        cbb::LcCBB,
        cbs,
        encoding::PublicKeyX509Der,
        error::{KeyRejected, Unspecified},
        ptr::LcPtr,
    };
    use aws_lc::{EVP_marshal_public_key, EVP_parse_public_key, EVP_PKEY};

    pub(in crate::rsa) fn encode_public_key_der(
        key: &LcPtr<EVP_PKEY>,
    ) -> Result<PublicKeyX509Der<'static>, Unspecified> {
        let mut der = LcCBB::new(1024);

        if 1 != unsafe { EVP_marshal_public_key(der.as_mut_ptr(), **key) } {
            return Err(Unspecified);
        };

        Ok(PublicKeyX509Der::from(der.into_buffer()?))
    }

    pub(in crate::rsa) fn decode_public_key_der(
        value: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let mut der = unsafe { cbs::build_CBS(value) };
        Ok(LcPtr::new(unsafe { EVP_parse_public_key(&mut der) })?)
    }
}
