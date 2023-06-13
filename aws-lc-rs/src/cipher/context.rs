use std::{
    mem::MaybeUninit,
    ptr::{null, null_mut},
};

use aws_lc::{
    EVP_CIPHER_CTX_init, EVP_CipherFinal_ex, EVP_CipherInit_ex, EVP_CipherUpdate, EVP_aes_128_cbc,
    EVP_aes_128_ctr, EVP_aes_256_cbc, EVP_aes_256_ctr, EVP_CIPHER_CTX,
};

use crate::{
    cipher::{Algorithm, OperatingMode},
    error::Unspecified,
};

#[derive(Clone, Copy)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

impl From<Direction> for i32 {
    fn from(value: Direction) -> Self {
        match value {
            Direction::Encrypt => 1,
            Direction::Decrypt => 0,
        }
    }
}

pub struct Cipher(EVP_CIPHER_CTX);

impl Cipher {
    pub fn new(
        alg: &'static Algorithm,
        mode: OperatingMode,
        direction: Direction,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Self, Unspecified> {
        let mut ctx = MaybeUninit::<EVP_CIPHER_CTX>::uninit();

        let cipher = get_evp_cipher(alg, mode);

        let iv = iv.map_or_else(null, <[u8]>::as_ptr);

        unsafe {
            EVP_CIPHER_CTX_init(ctx.as_mut_ptr());

            if 1 != EVP_CipherInit_ex(
                ctx.as_mut_ptr(),
                cipher,
                null_mut(),
                key.as_ptr(),
                iv,
                direction.into(),
            ) {
                return Err(Unspecified);
            }
        }

        Ok(Self(unsafe { ctx.assume_init() }))
    }

    pub fn update_in_place(&mut self, in_out: &mut [u8]) -> Result<usize, Unspecified> {
        let mut out_len = MaybeUninit::<i32>::uninit();

        unsafe {
            if 1 != EVP_CipherUpdate(
                &mut self.0,
                in_out.as_mut_ptr(),
                out_len.as_mut_ptr(),
                in_out.as_ptr(),
                in_out.len().try_into().map_err(|_| Unspecified)?,
            ) {
                return Err(Unspecified);
            }
        }

        unsafe { out_len.assume_init() }
            .try_into()
            .map_err(|_| Unspecified)
    }

    pub fn finalize(mut self, out: &mut [u8]) -> Result<usize, Unspecified> {
        let mut out_len = MaybeUninit::<i32>::uninit();

        unsafe {
            if 1 != EVP_CipherFinal_ex(&mut self.0, out.as_mut_ptr(), out_len.as_mut_ptr()) {
                return Err(Unspecified);
            }
        }

        unsafe { out_len.assume_init() }
            .try_into()
            .map_err(|_| Unspecified)
    }
}

fn get_evp_cipher(
    alg: &'static Algorithm,
    mode: OperatingMode,
) -> *const aws_lc::evp_cipher_st {
    unsafe {
        match (alg.id(), mode) {
            (super::AlgorithmId::Aes128, OperatingMode::CBC) => EVP_aes_128_cbc(),
            (super::AlgorithmId::Aes128, OperatingMode::CTR) => EVP_aes_128_ctr(),
            (super::AlgorithmId::Aes256, OperatingMode::CBC) => EVP_aes_256_cbc(),
            (super::AlgorithmId::Aes256, OperatingMode::CTR) => EVP_aes_256_ctr(),
        }
    }
}
