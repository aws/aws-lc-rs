use crate::aead::{error, Aad, Algorithm, AlgorithmId, InnerKey, Nonce, Tag, NONCE_LEN};
use std::mem::MaybeUninit;
use std::os::raw::c_int;

fn aes_gcm_seal(
    key: &InnerKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    println!("aes_gcm_seal");

    unsafe {
        let (cipher, key_bytes) = match key {
            InnerKey::Aes128Gcm(key_bytes) => (aws_lc_sys::EVP_aes_128_gcm(), key_bytes.as_slice()),
            InnerKey::Aes256Gcm(key_bytes) => (aws_lc_sys::EVP_aes_256_gcm(), key_bytes.as_slice()),
            _ => panic!("Unknown algorithm"),
        };
        let ctx = aws_lc_sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err(error::Unspecified);
        }

        let key_ptr = key_bytes.as_ptr();
        let iv_ptr = aad.as_ref().as_ptr();
        if 1 != aws_lc_sys::EVP_EncryptInit(ctx, cipher, key_ptr, iv_ptr) {
            return Err(error::Unspecified);
        }

        const chunk_size: usize = 256;
        let mut cipher_text = MaybeUninit::<[u8; chunk_size]>::uninit();
        let mut out_len = MaybeUninit::<c_int>::new(0);

        if 1 != aws_lc_sys::EVP_EncryptUpdate(
            ctx,
            std::ptr::null_mut(),
            out_len.as_mut_ptr(),
            nonce.0.as_ptr(),
            NONCE_LEN as c_int,
        ) {
            return Err(error::Unspecified);
        }

        let in_len = in_out.len() as c_int;
        let mut pos: c_int = 0;
        while pos <= (in_len - chunk_size) {
            if 1 != aws_lc_sys::EVP_EncryptUpdate(
                ctx,
                cipher_text.as_mut_ptr().cast(),
                out_len.into(),
                in_out.as_ptr() + pos,
                chunk_size as c_int,
            ) {
                return Err(error::Unspecified);
            }
            pos += chunk_size;
        } /*
                  if pos < in_len {
                      aws_lc_sys::EVP_EncryptUpdate (ctx, cipher_text.as_mut_ptr().cast(),out_len.into() , PLAINTEXT+len, in_len - len);
                  }
                  aws_lc_sys::EVP_EncryptFinal (ctx, TAG, &howmany);
                  aws_lc_sys::EVP_CIPHER_CTX_ctrl (ctx, aws_lc_sys::EVP_CTRL_GCM_GET_TAG, 16, TAG);
                  aws_lc_sys::EVP_CIPHER_CTX_free(ctx);
          */
    }

    Ok(Tag::from([0u8; 16]))
}

fn aes_gcm_open(
    key: &InnerKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_prefix_len: usize,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    Ok(Tag::from([0u8; 16]))
}

pub static AES_128_GCM: Algorithm = Algorithm {
    key_len: 16,
    id: AlgorithmId::Aes128Gcm,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
};

pub static AES_256_GCM: Algorithm = Algorithm {
    key_len: 32,
    id: AlgorithmId::Aes256Gcm,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
};
