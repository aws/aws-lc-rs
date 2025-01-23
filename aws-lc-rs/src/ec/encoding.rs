// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aws_lc::{
    d2i_PrivateKey, point_conversion_form_t, BN_bn2bin_padded, BN_num_bytes, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_POINT_new, EC_POINT_oct2point,
    EC_POINT_point2oct, EVP_PKEY_get0_EC_KEY, EC_GROUP, EC_KEY, EC_POINT, EVP_PKEY, EVP_PKEY_EC,
};
use crate::ec;
use crate::ec::encoding;
#[cfg(feature = "fips")]
use crate::ec::validate_evp_key;
#[cfg(not(feature = "fips"))]
use crate::ec::verify_evp_key_nid;
use crate::error::{KeyRejected, Unspecified};
use crate::ptr::{ConstPointer, LcPtr};
use std::ptr::null_mut;

// [SEC 1](https://secg.org/sec1-v2.pdf)
//
// SEC 1: Elliptic Curve Cryptography, Version 2.0
pub(crate) mod sec1 {
    use crate::aws_lc::{
        EC_GROUP_get_curve_name, EC_KEY_new, EC_KEY_set_group, EC_KEY_set_private_key,
        EC_KEY_set_public_key, EC_POINT_mul, EC_POINT_new, EVP_PKEY_assign_EC_KEY, EVP_PKEY_new,
        BIGNUM, EC_GROUP, EC_POINT, EVP_PKEY,
    };
    use crate::ec::ec_group_from_nid;
    use crate::ec::encoding::ec_point_from_bytes;
    use crate::ec::validate_evp_key;
    use crate::ec::KeyRejected;
    use crate::ptr::ConstPointer;
    use crate::ptr::DetachableLcPtr;
    use crate::ptr::LcPtr;
    use std::ptr::{null, null_mut};

    pub(crate) fn parse_sec1_public_point(
        key_bytes: &[u8],
        expected_curve_nid: i32,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let ec_group = ec_group_from_nid(expected_curve_nid)?;
        let pub_key_point = ec_point_from_bytes(&ec_group, key_bytes)?;
        from_ec_public_point(&ec_group, &pub_key_point)
    }

    #[inline]
    fn from_ec_public_point(
        ec_group: &ConstPointer<EC_GROUP>,
        public_ec_point: &LcPtr<EC_POINT>,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let nid = unsafe { EC_GROUP_get_curve_name(**ec_group) };
        let ec_key = DetachableLcPtr::new(unsafe { EC_KEY_new() })?;
        if 1 != unsafe { EC_KEY_set_group(*ec_key, **ec_group) } {
            return Err(KeyRejected::unexpected_error());
        }
        if 1 != unsafe { EC_KEY_set_public_key(*ec_key, *public_ec_point.as_const()) } {
            return Err(KeyRejected::inconsistent_components());
        }

        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_EC_KEY(*pkey.as_mut(), *ec_key) } {
            return Err(KeyRejected::unexpected_error());
        }

        ec_key.detach();

        validate_evp_key(&pkey.as_const(), nid)?;

        Ok(pkey)
    }

    pub(crate) fn parse_sec1_private_bn(
        priv_key: &[u8],
        nid: i32,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let ec_group = ec_group_from_nid(nid)?;
        let priv_key = LcPtr::<BIGNUM>::try_from(priv_key)?;

        let pkey = from_ec_private_bn(&ec_group, &priv_key.as_const())?;

        Ok(pkey)
    }

    fn from_ec_private_bn(
        ec_group: &ConstPointer<EC_GROUP>,
        private_big_num: &ConstPointer<BIGNUM>,
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let ec_key = DetachableLcPtr::new(unsafe { EC_KEY_new() })?;
        if 1 != unsafe { EC_KEY_set_group(*ec_key, **ec_group) } {
            return Err(KeyRejected::unexpected_error());
        }
        if 1 != unsafe { EC_KEY_set_private_key(*ec_key, **private_big_num) } {
            return Err(KeyRejected::unexpected_error());
        }
        let mut pub_key = LcPtr::new(unsafe { EC_POINT_new(**ec_group) })?;
        if 1 != unsafe {
            EC_POINT_mul(
                **ec_group,
                *pub_key.as_mut(),
                **private_big_num,
                null(),
                null(),
                null_mut(),
            )
        } {
            return Err(KeyRejected::unexpected_error());
        }
        if 1 != unsafe { EC_KEY_set_public_key(*ec_key, *pub_key.as_const()) } {
            return Err(KeyRejected::unexpected_error());
        }
        let expected_curve_nid = unsafe { EC_GROUP_get_curve_name(**ec_group) };

        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_EC_KEY(*pkey.as_mut(), *ec_key) } {
            return Err(KeyRejected::unexpected_error());
        }
        ec_key.detach();

        // Validate the EC_KEY before returning it.
        validate_evp_key(&pkey.as_const(), expected_curve_nid)?;

        Ok(pkey)
    }
}

pub(crate) fn marshal_private_key_to_buffer(
    private_size: usize,
    evp_pkey: &ConstPointer<EVP_PKEY>,
) -> Result<Vec<u8>, Unspecified> {
    let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(**evp_pkey) })?;
    let private_bn = ConstPointer::new(unsafe { EC_KEY_get0_private_key(*ec_key) })?;
    {
        let size: usize = unsafe { BN_num_bytes(*private_bn).try_into()? };
        debug_assert!(size <= private_size);
    }

    let mut buffer = vec![0u8; private_size];
    if 1 != unsafe { BN_bn2bin_padded(buffer.as_mut_ptr(), private_size, *private_bn) } {
        return Err(Unspecified);
    }

    Ok(buffer)
}

pub(crate) fn unmarshal_der_to_private_key(
    key_bytes: &[u8],
    nid: i32,
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let mut out = null_mut();
    // `d2i_PrivateKey` -> ... -> `EC_KEY_parse_private_key` -> `EC_KEY_check_key`
    let evp_pkey = LcPtr::new(unsafe {
        d2i_PrivateKey(
            EVP_PKEY_EC,
            &mut out,
            &mut key_bytes.as_ptr(),
            key_bytes
                .len()
                .try_into()
                .map_err(|_| KeyRejected::too_large())?,
        )
    })?;
    #[cfg(not(feature = "fips"))]
    verify_evp_key_nid(&evp_pkey.as_const(), nid)?;
    #[cfg(feature = "fips")]
    validate_evp_key(&evp_pkey.as_const(), nid)?;

    Ok(evp_pkey)
}

pub(crate) fn marshal_public_key_to_buffer(
    buffer: &mut [u8],
    evp_pkey: &LcPtr<EVP_PKEY>,
    compressed: bool,
) -> Result<usize, Unspecified> {
    let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(*evp_pkey.as_const()) })?;
    marshal_ec_public_key_to_buffer(buffer, &ec_key, compressed)
}

pub(crate) fn marshal_ec_public_key_to_buffer(
    buffer: &mut [u8],
    ec_key: &ConstPointer<EC_KEY>,
    compressed: bool,
) -> Result<usize, Unspecified> {
    let ec_group = ConstPointer::new(unsafe { EC_KEY_get0_group(**ec_key) })?;

    let ec_point = ConstPointer::new(unsafe { EC_KEY_get0_public_key(**ec_key) })?;

    let point_conversion_form = if compressed {
        point_conversion_form_t::POINT_CONVERSION_COMPRESSED
    } else {
        point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED
    };

    let out_len = ec_point_to_bytes(&ec_group, &ec_point, buffer, point_conversion_form)?;
    Ok(out_len)
}

pub(crate) fn try_parse_public_key_bytes(
    key_bytes: &[u8],
    expected_curve_nid: i32,
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(key_bytes, EVP_PKEY_EC)
        .or(encoding::sec1::parse_sec1_public_point(
            key_bytes,
            expected_curve_nid,
        ))
        .and_then(|key| ec::validate_evp_key(&key.as_const(), expected_curve_nid).map(|()| key))
}

#[inline]
pub(crate) fn ec_point_from_bytes(
    ec_group: &ConstPointer<EC_GROUP>,
    bytes: &[u8],
) -> Result<LcPtr<EC_POINT>, KeyRejected> {
    let mut ec_point = LcPtr::new(unsafe { EC_POINT_new(**ec_group) })?;

    if 1 != unsafe {
        EC_POINT_oct2point(
            **ec_group,
            *ec_point.as_mut(),
            bytes.as_ptr(),
            bytes.len(),
            null_mut(),
        )
    } {
        return Err(KeyRejected::invalid_encoding());
    }

    Ok(ec_point)
}

#[inline]
fn ec_point_to_bytes(
    ec_group: &ConstPointer<EC_GROUP>,
    ec_point: &ConstPointer<EC_POINT>,
    buf: &mut [u8],
    pt_conv_form: point_conversion_form_t,
) -> Result<usize, Unspecified> {
    let buf_len = buf.len();
    let out_len = unsafe {
        EC_POINT_point2oct(
            **ec_group,
            **ec_point,
            pt_conv_form,
            buf.as_mut_ptr(),
            buf_len,
            null_mut(),
        )
    };
    if out_len == 0 {
        return Err(Unspecified);
    }

    Ok(out_len)
}
