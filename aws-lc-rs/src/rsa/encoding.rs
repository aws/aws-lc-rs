// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

/// PKCS#8 Encoding Functions
pub(in super::super) mod pkcs8 {
    use crate::{
        cbb::LcCBB,
        error::{KeyRejected, Unspecified},
        ptr::LcPtr,
    };
    use aws_lc::{EVP_marshal_private_key, EVP_PKEY};

    // Based on a measurement of a PKCS#8 v1 document containing an RSA-8192 key with an additional 1% capacity buffer
    // rounded to an even 64-bit words (4678 + 1% + padding ≈ 4728).
    const PKCS8_FIXED_CAPACITY_BUFFER: usize = 4728;

    pub(in super::super) fn encode_v1_der(key: &LcPtr<EVP_PKEY>) -> Result<Vec<u8>, Unspecified> {
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
    pub(in super::super) fn decode_der(pkcs8: &[u8]) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        LcPtr::try_from(pkcs8)
    }
}
