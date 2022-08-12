use std::cmp::min;
use crate::aead::{error, Aad, Algorithm, AlgorithmID, KeyInner, Nonce, Tag, NONCE_LEN, TAG_LEN, counter};
use std::mem::MaybeUninit;
use std::os::raw::c_int;

use std::ptr::{null, null_mut};
use crate::aead::block::Block;
use crate::aead::iv::IV_LEN;
use crate::endian::BigEndian;

pub type Counter = counter::Counter<BigEndian<u32>>;

fn aes_gcm_seal(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    println!("aes_gcm_seal");

    unsafe {
        let (cipher, ctx, key_bytes) = match key {
            KeyInner::Aes128Gcm(key_bytes, ctx) => (aws_lc_sys::EVP_aes_128_gcm(), ctx, key_bytes.as_slice()),
            KeyInner::Aes256Gcm(key_bytes, ctx) => (aws_lc_sys::EVP_aes_256_gcm(), ctx, key_bytes.as_slice()),
            _ => panic!("Unknown algorithm"),
        };

        if 1 != aws_lc_sys::EVP_EncryptInit_ex(*ctx, cipher, null_mut(), null_mut(), null_mut()) {
            return Err(error::Unspecified);
        }

        if 1 != aws_lc_sys::EVP_CIPHER_CTX_ctrl(*ctx, aws_lc_sys::EVP_CTRL_GCM_SET_IVLEN, IV_LEN as c_int, null_mut()) {
            return Err(error::Unspecified);
        }

        let tag_iv = Counter::one(nonce).increment();
        if 1 != aws_lc_sys::EVP_EncryptInit_ex(*ctx, cipher, null_mut(), key_bytes.as_ptr(), tag_iv.into_bytes_less_safe().as_ptr()) {
            return Err(error::Unspecified);
        }

        const CHUNK_SIZE: usize = 96;
        let mut cipher_text = MaybeUninit::<[u8; CHUNK_SIZE]>::uninit();
        let mut out_len  = MaybeUninit::<c_int>::uninit();

        if 1 != aws_lc_sys::EVP_EncryptUpdate(
            *ctx,
            std::ptr::null_mut(),
            out_len.as_mut_ptr(),
            aad.0.as_ptr(),
            NONCE_LEN as c_int,
        ) {
            return Err(error::Unspecified);
        }

        let plaintext_len = in_out.len();
        let mut pos = 0;
        while pos < plaintext_len {
            let in_len = min(plaintext_len - pos, CHUNK_SIZE);
            let next_plain_chunk = &in_out[pos..(pos+in_len)];
            if 1 != aws_lc_sys::EVP_EncryptUpdate(
                *ctx,
                cipher_text.as_mut_ptr().cast(),
                out_len.as_mut_ptr(),
                next_plain_chunk.as_ptr(),
                in_len as c_int,
            ) {
                return Err(error::Unspecified);
            }
            let olen = out_len.assume_init() as usize;
            let ctext = cipher_text.assume_init();
            let mut next_cipher_chunk = &mut in_out[pos..(pos+olen)];
            next_cipher_chunk.copy_from_slice(&ctext[0..olen]);
            pos += olen;
        }

        aws_lc_sys::EVP_EncryptFinal_ex (*ctx, null_mut(), out_len.as_mut_ptr());
        debug_assert_eq!(out_len.assume_init(), 0);

        let mut inner_tag = MaybeUninit::<[u8; 16]>::uninit();
        aws_lc_sys::EVP_CIPHER_CTX_ctrl (*ctx, aws_lc_sys::EVP_CTRL_GCM_GET_TAG, TAG_LEN as c_int, inner_tag.as_mut_ptr().cast());

        let tag = inner_tag.assume_init();
        //let bytes = tag_iv.into_bytes_less_safe();

        //let aes_key  = MaybeUninit::<aws_lc_sys::AES_KEY>::uninit();
        //aws_lc_sys::AES_set_encrypt_key(key_bytes.as_mut_ptr(), aes_key.as_mut_ptr());


        //let mut tag = aes_key.encrypt_block(Block::from(&bytes));
        //tag.bitxor_assign(pre_tag.into());

        Ok(Tag(tag))
    }
}

fn aes_gcm_open(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_prefix_len: usize,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    Ok(Tag([0u8; 16]))
}

pub static AES_128_GCM: Algorithm = Algorithm {
    init: init_128,
    key_len: 16,
    id: AlgorithmID::AES_128_GCM,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    max_input_len: u64::MAX
};

pub static AES_256_GCM: Algorithm = Algorithm {
    init: init_256,
    key_len: 32,
    id: AlgorithmID::AES_256_GCM,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    max_input_len: u64::MAX
};

fn init_128(key: &[u8]) ->  Result<KeyInner, error::Unspecified> {
   return init_aes_gcm(key, AlgorithmID::AES_128_GCM);
}

fn init_256(key: &[u8]) ->  Result<KeyInner, error::Unspecified> {
    return init_aes_gcm(key, AlgorithmID::AES_256_GCM);
}

fn init_aes_gcm(key: &[u8], id: AlgorithmID) -> Result<KeyInner, error::Unspecified> {
    unsafe {
        let cipher= match id {
            AlgorithmID::AES_128_GCM => aws_lc_sys::EVP_aes_128_gcm(),
            AlgorithmID::AES_256_GCM => aws_lc_sys::EVP_aes_256_gcm(),
            _ => panic!("Unknown algorithm"),
        };
        let ctx = aws_lc_sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err(error::Unspecified);
        }

        if id == AlgorithmID::AES_128_GCM {
            let mut key_128 = [0u8; 16];
            key_128.copy_from_slice(key);
            return Ok(KeyInner::Aes128Gcm(key_128, ctx));
        } else if id == AlgorithmID::AES_256_GCM {
            let mut key_256 = [0u8; 32];
            key_256.copy_from_slice(key);
            return Ok(KeyInner::Aes256Gcm(key_256, ctx));
        }
        panic!("Unsupported algorithm");
    }
}
