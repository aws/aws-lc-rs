// Copyright 2015-2016 Hanson Char.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Public key common construts, such as the encoding used in an `UnparsedPublicKey`.

use std::ptr::null_mut;

use aws_lc::{d2i_PUBKEY_bio, BIO_new, BIO_s_mem, BIO_write, EVP_PKEY};

use crate::{error::Unspecified, ptr::LcPtr};

/// Encoding ID.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EncodingID {
    /// A sequence of 8-bit bytes
    OctetString,
    /// X509 DER encoding
    X509,
}

/// Encoding of bytes
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Encoding {
    /// Encoding ID
    pub(crate) id: EncodingID,
}

/// Octet String encoding
pub(crate) static OCTET_STRING: Encoding = Encoding {
    id: EncodingID::OctetString,
};

/// X509 DER encoding
pub(crate) static X509: Encoding = Encoding {
    id: EncodingID::X509,
};

#[inline]
pub(crate) fn evp_pkey_from_x509_pubkey(
    pubkey_data: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    // Create a memory BIO and write the public key data to it
    let mem_bio = LcPtr::new(unsafe { BIO_new(BIO_s_mem()) })?;
    let len = match std::os::raw::c_int::try_from(pubkey_data.len()) {
        Ok(len) => len,
        Err(_) => return Err(Unspecified),
    };
    if unsafe {
        BIO_write(
            *mem_bio,
            pubkey_data.as_ptr().cast::<std::os::raw::c_void>(),
            len,
        )
    } <= 0
    {
        return Err(Unspecified);
    }
    // Use d2i_PUBKEY_bio to read the public key from the memory BIO
    Ok(LcPtr::new(unsafe { d2i_PUBKEY_bio(*mem_bio, null_mut()) })?)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose;
    use base64::Engine;

    use crate::public_key::evp_pkey_from_x509_pubkey;

    #[test]
    fn test_evp_pkey_from_x509_pubkey() {
        // Generated using "SHA384withRSA" from BC-FIPS
        let b64_x509_pubkey = concat!(
            "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA28pm7EDzXRvFmgK2/UNriVNWF4slKNDKtY",
            "q6hEZsJstfVU/J7zOAJKjUjR/abgnLYAd6I8M9aiYNaAh/GfnIfOXhymjSqfiimCu14dJsQQLP/Thd",
            "yR6jSKvQCkyWPWpo1S5H7qkmPpjxU6CeyYAkaNc+B1TnAblyLQ90wwY5OmAzQD0A6k1UX6NoHB/W5P",
            "G731y16QTv34xVycXYFfp+pSyKHm5Q7YXPQLKrWPTIFoOvVHi94s+c7nqmYxfXhtzBf9WSr9so6Dgz",
            "vlsFK4FhyOq4zKN7XQkOwAVyZ5X//bMwfzVmm7TJTvfGyMNU0YaCPLgRSWn2bDeiY9hbfERurAkBIN",
            "/piGXl/12xv8tZGa5lAQe4fcj+O1Uc9b9tDbuba9HiYxS1OAfeAO25kqBa24qqvEMxTgDf0G6AnCzj",
            "dQFsP4pVfRBmMVjo6Zikq+TStr0+UID2u21N3MrcLue7BzbujU/9buFtSES5QWYUdQoYb3pzYEgojJ",
            "HriYBA1yiJAgMBAAE="
        );
        let x509_pubkey = general_purpose::STANDARD
            .decode(b64_x509_pubkey)
            .expect("Invalid base64 encoding");
        evp_pkey_from_x509_pubkey(x509_pubkey.as_slice())
            .expect("Failed evp_pkey_from_x509_pubkey");
    }
}
