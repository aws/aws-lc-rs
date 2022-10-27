// Copyright 2015-2017 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::ec::{ec_group_from_nid, ec_key_from_public_point, ec_point_from_bytes};
use crate::error::Unspecified;
use crate::ptr::{LcPtr, NonNullPtr};
use crate::rand::SecureRandom;
use crate::{ec, test};
use aws_lc_sys::{
    ECDH_compute_key, EC_GROUP_get_curve_name, EC_GROUP_get_degree, EC_KEY_get0_group,
    EC_KEY_get0_public_key, NID_X9_62_prime256v1, NID_secp384r1, X25519_public_from_private,
    EC_KEY, NID_X25519,
};
use std::fmt::{Debug, Formatter};
use std::ptr::null_mut;

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum AlgorithmID {
    ECDH_P256,
    ECDH_P384,
    X25519,
}

impl AlgorithmID {
    #[inline]
    fn nid(&self) -> i32 {
        match self {
            AlgorithmID::ECDH_P256 => NID_X9_62_prime256v1,
            AlgorithmID::ECDH_P384 => NID_secp384r1,
            AlgorithmID::X25519 => NID_X25519,
        }
    }

    #[inline]
    fn pub_key_len(&self) -> usize {
        match self {
            AlgorithmID::ECDH_P256 => 65,
            AlgorithmID::ECDH_P384 => 97,
            AlgorithmID::X25519 => 32,
        }
    }
}

impl Debug for AlgorithmID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            AlgorithmID::ECDH_P256 => "curve: P256",
            AlgorithmID::ECDH_P384 => "curve: P384",
            AlgorithmID::X25519 => "curve: Curve25519",
        };
        f.write_str(output)
    }
}

#[derive(PartialEq, Eq)]
pub struct Algorithm {
    id: AlgorithmID,
}

impl Debug for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("Algorithm {{ {:?} }}", self.id))
    }
}

pub static ECDH_P256: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P256,
};
pub static ECDH_P384: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P384,
};
pub static X25519: Algorithm = Algorithm {
    id: AlgorithmID::X25519,
};
const X25519_PRIVATE_KEY_LEN: usize = aws_lc_sys::X25519_PRIVATE_KEY_LEN as usize;
const ECDH_P256_PRIVATE_KEY_LEN: usize = 32;
const ECDH_P384_PRIVATE_KEY_LEN: usize = 48;
const X25519_PUBLIC_VALUE_LEN: usize = aws_lc_sys::X25519_PUBLIC_VALUE_LEN as usize;
const X25519_SHARED_KEY_LEN: usize = aws_lc_sys::X25519_SHARED_KEY_LEN as usize;
#[allow(non_camel_case_types)]
enum KeyInner {
    ECDH_P256(LcPtr<*mut EC_KEY>),
    ECDH_P384(LcPtr<*mut EC_KEY>),
    X25519([u8; X25519_PRIVATE_KEY_LEN], [u8; X25519_PUBLIC_VALUE_LEN]),
}

pub struct EphemeralPrivateKey {
    inner_key: KeyInner,
}

impl KeyInner {
    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        match self {
            KeyInner::ECDH_P256(..) => &ECDH_P256,
            KeyInner::ECDH_P384(..) => &ECDH_P384,
            KeyInner::X25519(..) => &X25519,
        }
    }
}

unsafe impl Send for EphemeralPrivateKey {}

// https://github.com/awslabs/aws-lc/blob/main/include/openssl/ec_key.h#L88
// An |EC_KEY| object represents a public or private EC key. A given object may
// be used concurrently on multiple threads by non-mutating functions, provided
// no other thread is concurrently calling a mutating function. Unless otherwise
// documented, functions which take a |const| pointer are non-mutating and
// functions which take a non-|const| pointer are mutating.
unsafe impl Sync for EphemeralPrivateKey {}

impl Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "EphemeralPrivateKey {{ algorithm: {:?} }}",
            self.inner_key.algorithm()
        ))
    }
}

impl EphemeralPrivateKey {
    #[inline]
    pub fn generate(alg: &'static Algorithm, rng: &dyn SecureRandom) -> Result<Self, Unspecified> {
        match alg.id {
            AlgorithmID::X25519 => {
                let mut priv_key = [0u8; X25519_PRIVATE_KEY_LEN];
                rng.fill(&mut priv_key)?;
                Self::from_x25519_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P256 => {
                let mut priv_key = [0u8; ECDH_P256_PRIVATE_KEY_LEN];
                rng.fill(&mut priv_key)?;
                Self::from_p256_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P384 => {
                let mut priv_key = [0u8; ECDH_P384_PRIVATE_KEY_LEN];
                rng.fill(&mut priv_key)?;
                Self::from_p384_private_key(&priv_key)
            }
        }
    }

    #[inline]
    fn from_x25519_private_key(
        priv_key: &[u8; X25519_PRIVATE_KEY_LEN],
    ) -> Result<Self, Unspecified> {
        unsafe {
            let mut pub_key = [0u8; X25519_PUBLIC_VALUE_LEN];
            X25519_public_from_private(pub_key.as_mut_ptr().cast(), priv_key.as_ptr());
            let inner_key = KeyInner::X25519(*priv_key, pub_key);
            Ok(EphemeralPrivateKey { inner_key })
        }
    }

    #[inline]
    fn from_p256_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        unsafe {
            let ec_group = ec_group_from_nid(ECDH_P256.id.nid())?;
            let priv_key = ec::bignum_from_be_bytes(priv_key)?;

            let ec_key = ec::ec_key_from_private(&ec_group.as_non_null(), &priv_key.as_non_null())?;
            let ec_key = LcPtr::from(ec_key);
            Ok(EphemeralPrivateKey {
                inner_key: KeyInner::ECDH_P256(ec_key),
            })
        }
    }

    #[inline]
    fn from_p384_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        unsafe {
            let ec_group = ec_group_from_nid(ECDH_P384.id.nid())?;
            let priv_key = ec::bignum_from_be_bytes(priv_key)?;

            let ec_key = ec::ec_key_from_private(&ec_group.as_non_null(), &priv_key.as_non_null())?;
            let ec_key = LcPtr::from(ec_key);
            Ok(EphemeralPrivateKey {
                inner_key: KeyInner::ECDH_P384(ec_key),
            })
        }
    }

    pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        match &self.inner_key {
            KeyInner::ECDH_P256(ec_key) | KeyInner::ECDH_P384(ec_key) => {
                let mut buffer = [0u8; MAX_PUBLIC_KEY_LEN];
                unsafe {
                    let key_len =
                        ec::marshal_public_key_to_buffer(&mut buffer, &ec_key.as_non_null())?;
                    Ok(PublicKey {
                        alg: self.algorithm(),
                        public_key: buffer,
                        len: key_len,
                    })
                }
            }
            KeyInner::X25519(_, pub_key) => {
                let mut buffer = [0u8; MAX_PUBLIC_KEY_LEN];
                buffer[0..X25519_PUBLIC_VALUE_LEN].copy_from_slice(pub_key);
                Ok(PublicKey {
                    alg: self.algorithm(),
                    public_key: buffer,
                    len: X25519_PUBLIC_VALUE_LEN,
                })
            }
        }
    }

    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.inner_key.algorithm()
    }
}

const MAX_PUBLIC_KEY_LEN: usize = ec::PUBLIC_KEY_MAX_LEN;

pub struct PublicKey {
    alg: &'static Algorithm,
    public_key: [u8; MAX_PUBLIC_KEY_LEN],
    len: usize,
}

impl PublicKey {
    pub fn algorithm(&self) -> &'static Algorithm {
        self.alg
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "PublicKey {{ algorithm: {:?}, bytes: \"{}\" }}",
            self.alg,
            test::to_hex(&self.public_key[0..self.len])
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.public_key[0..self.len]
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey {
            alg: self.alg,
            public_key: self.public_key,
            len: self.len,
        }
    }
}

#[derive(Copy, Clone)]
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    alg: &'static Algorithm,
    bytes: B,
}

impl<B: AsRef<[u8]>> Debug for UnparsedPublicKey<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "UnparsedPublicKey {{ algorithm: {:?}, bytes: {:?} }}",
            self.alg,
            test::to_hex(self.bytes.as_ref())
        ))
    }
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    pub fn new(algorithm: &'static Algorithm, bytes: B) -> Self {
        UnparsedPublicKey {
            alg: algorithm,
            bytes,
        }
    }
}

#[inline]
pub fn agree_ephemeral<B: AsRef<[u8]>, F, R, E>(
    my_private_key: EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
    error_value: E,
    kdf: F,
) -> Result<R, E>
where
    F: FnOnce(&[u8]) -> Result<R, E>,
{
    let expected_alg = my_private_key.algorithm();
    let expected_pub_key_len = expected_alg.id.pub_key_len();
    let expected_nid = expected_alg.id.nid();

    if peer_public_key.alg != expected_alg {
        return Err(error_value);
    }
    let peer_pub_bytes = peer_public_key.bytes.as_ref();
    if peer_pub_bytes.len() != expected_pub_key_len {
        return Err(error_value);
    }

    let mut buffer = [0u8; MAX_AGREEMENT_SECRET_LEN];

    let secret: &[u8] = match my_private_key.inner_key {
        KeyInner::X25519(priv_key, ..) => {
            let mut pub_key = [0u8; X25519_PUBLIC_VALUE_LEN];
            pub_key.copy_from_slice(peer_pub_bytes);
            unsafe {
                let result = x25519_diffie_hellman(&mut buffer, &priv_key, &pub_key);
                if result.is_err() {
                    return Err(error_value);
                }
                &buffer[0..X25519_SHARED_KEY_LEN]
            }
        }
        KeyInner::ECDH_P256(ec_key) | KeyInner::ECDH_P384(ec_key) => {
            let pub_key_bytes = peer_public_key.bytes.as_ref();
            unsafe {
                let result = ec_key_ecdh(
                    &mut buffer,
                    ec_key.as_non_null(),
                    pub_key_bytes,
                    expected_nid,
                );
                if result.is_err() {
                    return Err(error_value);
                }
                result.unwrap()
            }
        }
    };
    kdf(secret)
}
const MAX_AGREEMENT_SECRET_LEN: usize = 48;

#[inline]
unsafe fn ec_key_ecdh<'a>(
    buffer: &'a mut [u8; MAX_AGREEMENT_SECRET_LEN],
    priv_ec_key: NonNullPtr<*mut EC_KEY>,
    peer_pub_key_bytes: &[u8],
    nid: i32,
) -> Result<&'a [u8], ()> {
    let ec_group = ec_group_from_nid(nid)?;
    let pub_key_point = ec_point_from_bytes(&ec_group, peer_pub_key_bytes)?;
    let peer_ec_key = ec_key_from_public_point(&ec_group, &pub_key_point)?;

    let priv_group = NonNullPtr::new(EC_KEY_get0_group(*priv_ec_key))?;
    let priv_nid = EC_GROUP_get_curve_name(*priv_group);

    let supported_curves = [NID_X9_62_prime256v1, NID_secp384r1];
    if !supported_curves.contains(&priv_nid as &i32) {
        return Err(());
    }

    let peer_group = NonNullPtr::new(EC_KEY_get0_group(*peer_ec_key))?;
    if 0 != aws_lc_sys::EC_GROUP_cmp(*priv_group, *peer_group, null_mut()) {
        return Err(());
    }

    let peer_pub_key = NonNullPtr::new(EC_KEY_get0_public_key(*peer_ec_key))?;

    let field_size = EC_GROUP_get_degree(*priv_group) as usize;
    let max_secret_len = (field_size + 7) / 8;

    let outlen = ECDH_compute_key(
        buffer.as_mut_ptr().cast(),
        max_secret_len,
        *peer_pub_key,
        *priv_ec_key,
        None,
    );
    if 0 >= outlen {
        return Err(());
    }
    let outlen = outlen as usize;

    Ok(&buffer[0..outlen])
}

#[inline]
unsafe fn x25519_diffie_hellman(
    out_shared_key: &mut [u8],
    priv_key: &[u8; X25519_PRIVATE_KEY_LEN],
    peer_pub_key: &[u8; X25519_PUBLIC_VALUE_LEN],
) -> Result<(), ()> {
    debug_assert!(out_shared_key.len() >= X25519_SHARED_KEY_LEN);
    if 1 != aws_lc_sys::X25519(
        out_shared_key.as_mut_ptr(),
        priv_key.as_ptr(),
        peer_pub_key.as_ptr(),
    ) {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{agreement, test};

    #[test]
    fn test_agreement_x25519() {
        let alg = &agreement::X25519;
        let peer_public = agreement::UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            ),
        );

        let my_private = test::from_dirty_hex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019",
        );
        let output = test::from_dirty_hex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );

        assert_eq!(my_private.algorithm(), alg);

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        let result = agreement::agree_ephemeral(my_private, &peer_public, (), |key_material| {
            assert_eq!(key_material, &output[..]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_agreement_ecdh_p256() {
        let alg = &agreement::ECDH_P256;
        let peer_public = agreement::UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF6356FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
            ),
        );

        let my_private = test::from_dirty_hex(
            "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C37725811805271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
        );
        let output = test::from_dirty_hex(
            "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE",
        );

        assert_eq!(my_private.algorithm(), alg);

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        let result = agreement::agree_ephemeral(my_private, &peer_public, (), |key_material| {
            assert_eq!(key_material, &output[..]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_agreement_ecdh_p384() {
        let alg = &agreement::ECDH_P384;
        let peer_public = agreement::UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "04E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C",
            ),
        );

        let my_private = test::from_dirty_hex(
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C",
        );
        let output = test::from_dirty_hex(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746",
        );

        assert_eq!(my_private.algorithm(), alg);

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        let result = agreement::agree_ephemeral(my_private, &peer_public, (), |key_material| {
            assert_eq!(key_material, &output[..]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }
}
