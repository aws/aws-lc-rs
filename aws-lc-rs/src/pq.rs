// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
#![allow(unused)]

use std::{ffi::c_int, ptr::null_mut};

use crate::cbb::LcCBB;
use crate::cbs::build_CBS;
use aws_lc::{
    d2i_PrivateKey, CBB_init, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_pqdsa_set_params,
    EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key, EVP_PKEY_keygen,
    EVP_PKEY_keygen_init, EVP_PKEY_new, EVP_PKEY_pqdsa_new_raw_private_key,
    EVP_PKEY_pqdsa_new_raw_public_key, EVP_marshal_private_key, EVP_marshal_public_key,
    EVP_parse_public_key, CBB, EVP_PKEY, EVP_PKEY_PQDSA,
};

use crate::ed25519::ED25519_PRIVATE_KEY_SEED_LEN;
use crate::error::KeyRejected;
use crate::{error::Unspecified, fips::indicator_check, ptr::LcPtr};

pub(crate) fn evp_key_pqdsa_generate(nid: c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let mut pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx.as_mut()) } {
        return Err(Unspecified);
    }

    if 1 != unsafe { EVP_PKEY_CTX_pqdsa_set_params(*pkey_ctx.as_mut(), nid) } {
        return Err(Unspecified);
    }

    let mut pkey = null_mut::<EVP_PKEY>();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*pkey_ctx.as_mut(), &mut pkey) }) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

pub(crate) fn evp_pkey_from_private(bytes: &[u8]) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let mut data_ptr = bytes.as_ptr();
    let len = bytes.len().try_into()?;
    let evp_pkey = unsafe { d2i_PrivateKey(EVP_PKEY_PQDSA, null_mut(), &mut data_ptr, len) };
    Ok(LcPtr::new(evp_pkey)?)
}

pub(crate) fn evp_pkey_from_public(bytes: &[u8]) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let mut cbs = build_CBS(bytes);
    let evp_pkey = unsafe { EVP_parse_public_key(&mut cbs) };

    Ok(LcPtr::new(evp_pkey)?)
}

pub(crate) fn evp_pkey_to_public_raw(
    buffer: &mut [u8],
    evp_pkey: &LcPtr<EVP_PKEY>,
) -> Result<usize, Unspecified> {
    let mut key_len = buffer.len();
    if 1 != unsafe {
        EVP_PKEY_get_raw_public_key(*evp_pkey.as_const(), buffer.as_mut_ptr(), &mut key_len)
    } {
        Err(Unspecified)
    } else {
        Ok(key_len)
    }
}

pub(crate) fn evp_pkey_to_private_raw(
    buffer: &mut [u8],
    evp_pkey: &LcPtr<EVP_PKEY>,
) -> Result<usize, Unspecified> {
    let mut key_len = buffer.len();
    if 1 != unsafe {
        EVP_PKEY_get_raw_private_key(*evp_pkey.as_const(), buffer.as_mut_ptr(), &mut key_len)
    } {
        Err(Unspecified)
    } else {
        Ok(key_len)
    }
}

pub(crate) fn evp_pkey_from_public_raw(
    nid: c_int,
    bytes: &[u8],
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let mut data_ptr = bytes.as_ptr();
    let len = bytes.len().into();
    Ok(LcPtr::new(unsafe {
        EVP_PKEY_pqdsa_new_raw_public_key(nid, data_ptr, len)
    })?)
}
pub(crate) fn evp_pkey_from_private_raw(
    nid: c_int,
    bytes: &[u8],
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let mut data_ptr = bytes.as_ptr();
    let len = bytes.len().into();
    Ok(LcPtr::new(unsafe {
        EVP_PKEY_pqdsa_new_raw_private_key(nid, data_ptr, len)
    })?)
}

pub(crate) fn marshal_public_key_to_buffer(
    buffer: &mut [u8],
    evp_pkey: &LcPtr<EVP_PKEY>,
) -> Result<usize, Unspecified> {
    let mut cbb = LcCBB::new_from_slice(buffer);
    if 1 != unsafe { EVP_marshal_public_key(cbb.as_mut_ptr(), *evp_pkey.as_const()) } {
        return Err(Unspecified);
    }
    cbb.finish()
}

pub(crate) fn marshal_private_key_to_buffer(
    buffer: &mut [u8],
    evp_pkey: &LcPtr<EVP_PKEY>,
) -> Result<usize, Unspecified> {
    let mut cbb = LcCBB::new_from_slice(buffer);
    if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), *evp_pkey.as_const()) } {
        return Err(Unspecified);
    }
    cbb.finish()
}

#[cfg(test)]
mod tests {
    use crate::pq::{
        evp_key_pqdsa_generate, evp_pkey_from_private, evp_pkey_from_private_raw,
        evp_pkey_from_public, evp_pkey_from_public_raw, evp_pkey_to_private_raw,
        evp_pkey_to_public_raw, marshal_private_key_to_buffer, marshal_public_key_to_buffer,
    };

    #[test]
    fn test_keygen() {
        let mut buffer = [0u8; 4096];
        let key = evp_key_pqdsa_generate(aws_lc::NID_MLDSA44).unwrap();

        let len = marshal_public_key_to_buffer(&mut buffer, &key).unwrap();
        println!("public marshall len: {}", len);
        let key_public = evp_pkey_from_public(&buffer[0..len]).unwrap();

        let len = marshal_private_key_to_buffer(&mut buffer, &key).unwrap();
        println!("private marshall len: {}", len);
        let key_copy = evp_pkey_from_private(&buffer[0..len]).unwrap();

        let raw_public = evp_pkey_to_public_raw(&mut buffer, &key_public).unwrap();
        println!("raw public len: {}", raw_public);
        let key_public2 =
            evp_pkey_from_public_raw(aws_lc::NID_MLDSA44, &buffer[0..raw_public]).unwrap();

        let raw_private = evp_pkey_to_private_raw(&mut buffer, &key_copy).unwrap();
        println!("raw private len: {}", raw_private);
        let key_copy2 =
            evp_pkey_from_private_raw(aws_lc::NID_MLDSA44, &buffer[0..raw_private]).unwrap();
    }
}
