// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use super::aead_ctx::AeadCtx;
use super::{
    Algorithm, Nonce, Tag, AES_128_GCM, AES_128_GCM_SIV, AES_192_GCM, AES_256_GCM, AES_256_GCM_SIV,
    CHACHA20_POLY1305, MAX_KEY_LEN, MAX_TAG_LEN, NONCE_LEN,
};
use crate::aws_lc::{
    EVP_AEAD_CTX_open, EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal, EVP_AEAD_CTX_seal_scatter,
};
use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::hkdf;
use crate::iv::FixedLength;
use core::fmt::Debug;
use core::mem::MaybeUninit;
use core::ops::RangeFrom;
use core::ptr::null;

/// The maximum length of a nonce returned by our AEAD API.
const MAX_NONCE_LEN: usize = NONCE_LEN;

/// The maximum required tag buffer needed if using AWS-LC generated nonce construction
const MAX_TAG_NONCE_BUFFER_LEN: usize = MAX_TAG_LEN + MAX_NONCE_LEN;

/// An AEAD key without a designated role or nonce sequence.
pub struct UnboundKey {
    ctx: AeadCtx,
    algorithm: &'static Algorithm,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    /// # Errors
    /// `error::Unspecified` if `key_bytes.len() != algorithm.key_len()`.
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        Ok(Self {
            ctx: (algorithm.init)(key_bytes, algorithm.tag_len())?,
            algorithm,
        })
    }

    #[inline]
    pub(crate) fn open_within<'in_out>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        let in_prefix_len = ciphertext_and_tag.start;
        let ciphertext_and_tag_len = in_out.len().checked_sub(in_prefix_len).ok_or(Unspecified)?;
        let ciphertext_len = ciphertext_and_tag_len
            .checked_sub(self.algorithm().tag_len())
            .ok_or(Unspecified)?;
        self.check_per_nonce_max_bytes(ciphertext_len)?;

        match self.ctx {
            AeadCtx::AES_128_GCM_RANDNONCE(_) | AeadCtx::AES_256_GCM_RANDNONCE(_) => {
                self.open_combined_randnonce(nonce, aad, &mut in_out[in_prefix_len..])
            }
            _ => self.open_combined(nonce, aad.as_ref(), &mut in_out[in_prefix_len..]),
        }?;

        // shift the plaintext to the left
        in_out.copy_within(in_prefix_len..in_prefix_len + ciphertext_len, 0);

        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    #[inline]
    pub(crate) fn open_separate_gather(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_ciphertext: &[u8],
        in_tag: &[u8],
        out_plaintext: &mut [u8],
    ) -> Result<(), Unspecified> {
        self.open_separate_gather_impl(
            nonce,
            aad,
            in_ciphertext.as_ptr(),
            in_ciphertext.len(),
            in_tag,
            out_plaintext.as_mut_ptr(),
            out_plaintext.len(),
        )
    }

    #[inline]
    pub(crate) fn open_in_place_separate_tag(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_tag: &[u8],
        in_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        let ptr = in_out.as_mut_ptr();
        let len = in_out.len();
        self.open_separate_gather_impl(nonce, aad, ptr.cast_const(), len, in_tag, ptr, len)
    }

    /// Common FFI path for `EVP_AEAD_CTX_open_gather`-based opening.
    ///
    /// `in_ciphertext` / `out_plaintext` may alias (exactly, i.e. same base
    /// pointer and length). `EVP_AEAD_CTX_open_gather` explicitly permits
    /// `out == in`, which is how `open_in_place_separate_tag` works.
    ///
    /// Callers must ensure:
    /// * `in_ciphertext` is valid for reads of `in_ciphertext_len` bytes.
    /// * `out_plaintext` is valid for writes of `out_plaintext_len` bytes.
    /// * If the two pointers alias, they must alias exactly (same base, same length).
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn open_separate_gather_impl(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_ciphertext: *const u8,
        in_ciphertext_len: usize,
        in_tag: &[u8],
        out_plaintext: *mut u8,
        out_plaintext_len: usize,
    ) -> Result<(), Unspecified> {
        self.check_per_nonce_max_bytes(in_ciphertext_len)?;

        // ensure that the lengths match
        if in_ciphertext_len != out_plaintext_len {
            return Err(Unspecified);
        }

        unsafe {
            let aead_ctx = self.ctx.as_ref();
            let nonce = nonce.as_ref();

            if 1 != EVP_AEAD_CTX_open_gather(
                aead_ctx.as_const_ptr(),
                out_plaintext,
                nonce.as_ptr(),
                nonce.len(),
                in_ciphertext,
                in_ciphertext_len,
                in_tag.as_ptr(),
                in_tag.len(),
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(Unspecified);
            }
            Ok(())
        }
    }

    #[inline]
    pub(crate) fn seal_in_place_append_tag<'a, InOut>(
        &self,
        nonce: Option<Nonce>,
        aad: &[u8],
        in_out: &'a mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.check_per_nonce_max_bytes(in_out.as_mut().len())?;
        match nonce {
            Some(nonce) => self.seal_combined(nonce, aad, in_out),
            None => self.seal_combined_randnonce(aad, in_out),
        }
    }

    #[inline]
    pub(crate) fn seal_in_place_separate_tag(
        &self,
        nonce: Option<Nonce>,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        self.check_per_nonce_max_bytes(in_out.len())?;
        match nonce {
            Some(nonce) => self.seal_separate(nonce, aad, in_out),
            None => self.seal_separate_randnonce(aad, in_out),
        }
    }

    /// Encrypts `plaintext` into a separate `ciphertext` buffer, leaving `plaintext`
    /// untouched. This is the sealing counterpart to `open_separate_gather`.
    ///
    /// `ciphertext` must be exactly `plaintext.len()` bytes. `extra_in` is additional
    /// plaintext (TLS 1.3's inner content-type byte, for instance) that is encrypted and
    /// written to `extra_out_and_tag` ahead of the tag, so `extra_out_and_tag` must be
    /// `extra_in.len() + algorithm().tag_len()` bytes. The output buffers may not
    /// overlap each other or `plaintext`.
    ///
    /// This variant writes into possibly-uninitialised output. Forming a `&mut [u8]`
    /// over uninitialised memory is undefined behaviour even if every byte is about to
    /// be written, so a caller that wants to skip zeroing its output buffer needs an
    /// entry point that speaks `MaybeUninit`. On success every byte of both output
    /// slices has been written by the AEAD.
    ///
    /// # Errors
    /// `error::Unspecified` if the lengths are wrong or the encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn seal_separate_out_of_place_uninit<'c, 't>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &'c mut [MaybeUninit<u8>],
        extra_in: &[u8],
        extra_out_and_tag: &'t mut [MaybeUninit<u8>],
    ) -> Result<(&'c mut [u8], &'t mut [u8]), Unspecified> {
        self.check_per_nonce_max_bytes(plaintext.len() + extra_in.len())?;
        if ciphertext.len() != plaintext.len()
            || extra_out_and_tag.len() != extra_in.len() + self.algorithm().tag_len()
        {
            return Err(Unspecified);
        }

        let nonce = nonce.as_ref();
        let mut out_tag_len = extra_out_and_tag.len();

        if 1 != unsafe {
            EVP_AEAD_CTX_seal_scatter(
                self.ctx.as_ref().as_const_ptr(),
                ciphertext.as_mut_ptr().cast::<u8>(),
                extra_out_and_tag.as_mut_ptr().cast::<u8>(),
                &mut out_tag_len,
                extra_out_and_tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                extra_in.as_ptr(),
                extra_in.len(),
                aad.as_ptr(),
                aad.len(),
            )
        } {
            return Err(Unspecified);
        }
        // The tag length the C function reports is the only evidence available that it
        // filled the tag buffer, so a mismatch has to be an error rather than a shorter
        // successful write.
        if out_tag_len != extra_out_and_tag.len() {
            return Err(Unspecified);
        }
        // SAFETY: seal_scatter reported success, which per its contract means it wrote
        // exactly plaintext.len() bytes of ciphertext and out_tag_len bytes of tag; the
        // checks above rejected the call unless those lengths cover both slices in full.
        // Doing the assume-init here rather than making the caller do it keeps the one
        // unverifiable FFI claim inside the crate that documents it. MaybeUninit<u8>
        // shares u8's layout, so the casts are otherwise trivial.
        // (`<[MaybeUninit<T>]>::assume_init_mut` says this more directly, but stabilised
        // well after this crate's MSRV of 1.71.)
        unsafe {
            Ok((
                &mut *(ciphertext as *mut [MaybeUninit<u8>] as *mut [u8]),
                &mut *(extra_out_and_tag as *mut [MaybeUninit<u8>] as *mut [u8]),
            ))
        }
    }

    /// As [`Self::seal_separate_out_of_place_uninit`], for callers whose output buffers
    /// are already initialised.
    ///
    /// # Errors
    /// `error::Unspecified` if the lengths are wrong or the encryption operation fails.
    #[inline]
    pub(crate) fn seal_separate_out_of_place(
        &self,
        nonce: Nonce,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified> {
        // SAFETY: `MaybeUninit<u8>` has the same layout as `u8`, and "initialised" is a
        // strictly stronger property than `MaybeUninit` promises, so widening these
        // references is sound. The callee only ever writes AEAD output -- never
        // uninitialised bytes -- so both buffers are still fully initialised when the
        // borrow ends. (`slice::as_uninit_slice_mut` is the direct spelling, but is
        // still unstable.)
        let (ciphertext, extra_out_and_tag) = unsafe {
            (
                &mut *(ciphertext as *mut [u8] as *mut [MaybeUninit<u8>]),
                &mut *(extra_out_and_tag as *mut [u8] as *mut [MaybeUninit<u8>]),
            )
        };
        self.seal_separate_out_of_place_uninit(
            nonce,
            aad,
            plaintext,
            ciphertext,
            extra_in,
            extra_out_and_tag,
        )
        .map(|_| ())
    }

    /// Seals `plaintext` out of place, appending the ciphertext, any `extra_in`
    /// ciphertext and the tag to `out`.
    ///
    /// On success `out` has grown by `plaintext.len() + extra_in.len() + tag_len()`
    /// bytes and everything already in it is preserved. On error `out` is left at its original length, with the region
    /// the cipher would have filled zeroed inside its spare capacity. Nothing is zeroed
    /// on the success path: the cipher is the only thing that writes there.
    ///
    /// # Errors
    /// `error::Unspecified` if the encryption operation fails.
    ///
    /// # Panics
    /// If the required capacity exceeds `isize::MAX` bytes, via [`Vec::reserve`].
    #[inline]
    pub(crate) fn seal_out_of_place_append(
        &self,
        nonce: Nonce,
        aad: &[u8],
        plaintext: &[u8],
        extra_in: &[u8],
        out: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), Unspecified> {
        let grow_by = plaintext.len() + extra_in.len() + self.algorithm().tag_len();
        let start = out.len();
        out.reserve(grow_by);

        {
            let spare = &mut out.spare_capacity_mut()[..grow_by];
            let (ct, extra_and_tag) = spare.split_at_mut(plaintext.len());
            self.seal_separate_out_of_place_uninit(
                nonce,
                aad,
                plaintext,
                ct,
                extra_in,
                extra_and_tag,
            )?;
        }

        // SAFETY: `reserve` guaranteed at least `grow_by` bytes of spare capacity, and
        // the seal above returned Ok, which per its contract means the AEAD filled both
        // output slices -- together exactly that `grow_by` bytes -- in full. On the
        // error path this line is not reached, so `out` keeps its original length.
        unsafe { out.set_len(start + grow_by) };
        Ok(())
    }

    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn seal_in_place_separate_scatter(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified> {
        self.check_per_nonce_max_bytes(in_out.len())?;
        // ensure that the extra lengths match
        {
            let actual = extra_in.len() + self.algorithm().tag_len();
            let expected = extra_out_and_tag.len();

            if actual != expected {
                return Err(Unspecified);
            }
        }

        let nonce = nonce.as_ref();
        let mut out_tag_len = extra_out_and_tag.len();

        if 1 != unsafe {
            EVP_AEAD_CTX_seal_scatter(
                self.ctx.as_ref().as_const_ptr(),
                in_out.as_mut_ptr(),
                extra_out_and_tag.as_mut_ptr(),
                &mut out_tag_len,
                extra_out_and_tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                in_out.len(),
                extra_in.as_ptr(),
                extra_in.len(),
                aad.as_ptr(),
                aad.len(),
            )
        } {
            return Err(Unspecified);
        }
        Ok(())
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    #[inline]
    pub(crate) fn check_per_nonce_max_bytes(&self, in_out_len: usize) -> Result<(), Unspecified> {
        if in_out_len as u64 > self.algorithm().max_input_len {
            return Err(Unspecified);
        }
        Ok(())
    }

    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    fn open_combined(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        let nonce = nonce.as_ref();

        debug_assert_eq!(nonce.len(), self.algorithm().nonce_len());

        let plaintext_len = in_out.len() - self.algorithm().tag_len();

        let mut out_len = MaybeUninit::<usize>::uninit();
        if 1 != indicator_check!(unsafe {
            EVP_AEAD_CTX_open(
                self.ctx.as_ref().as_const_ptr(),
                in_out.as_mut_ptr(),
                out_len.as_mut_ptr(),
                plaintext_len,
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                plaintext_len + self.algorithm().tag_len(),
                aad.as_ptr(),
                aad.len(),
            )
        }) {
            return Err(Unspecified);
        }

        Ok(())
    }

    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    fn open_combined_randnonce(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        let nonce = nonce.as_ref();

        let alg_nonce_len = self.algorithm().nonce_len();
        let alg_tag_len = self.algorithm().tag_len();

        debug_assert_eq!(nonce.len(), alg_nonce_len);
        debug_assert!(alg_tag_len + alg_nonce_len <= MAX_TAG_NONCE_BUFFER_LEN);

        let plaintext_len = in_out.len() - alg_tag_len;

        let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

        tag_buffer[..alg_tag_len]
            .copy_from_slice(&in_out[plaintext_len..plaintext_len + alg_tag_len]);
        tag_buffer[alg_tag_len..alg_tag_len + alg_nonce_len].copy_from_slice(nonce);

        let tag_slice = &tag_buffer[0..alg_tag_len + alg_nonce_len];

        if 1 != indicator_check!(unsafe {
            EVP_AEAD_CTX_open_gather(
                self.ctx.as_ref().as_const_ptr(),
                in_out.as_mut_ptr(),
                null(),
                0,
                in_out.as_ptr(),
                plaintext_len,
                tag_slice.as_ptr(),
                tag_slice.len(),
                aad.as_ptr(),
                aad.len(),
            )
        }) {
            return Err(Unspecified);
        }

        Ok(())
    }

    #[inline]
    fn seal_combined<InOut>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let plaintext_len = in_out.as_mut().len();

        let alg_tag_len = self.algorithm().tag_len();

        debug_assert!(alg_tag_len <= MAX_TAG_LEN);

        let tag_buffer = [0u8; MAX_TAG_LEN];

        in_out.extend(tag_buffer[..alg_tag_len].iter());

        let mut out_len = MaybeUninit::<usize>::uninit();
        let mut_in_out = in_out.as_mut();

        {
            let nonce = nonce.as_ref();

            debug_assert_eq!(nonce.len(), self.algorithm().nonce_len());

            if 1 != indicator_check!(unsafe {
                EVP_AEAD_CTX_seal(
                    self.ctx.as_ref().as_const_ptr(),
                    mut_in_out.as_mut_ptr(),
                    out_len.as_mut_ptr(),
                    plaintext_len + alg_tag_len,
                    nonce.as_ptr(),
                    nonce.len(),
                    mut_in_out.as_ptr(),
                    plaintext_len,
                    aad.as_ptr(),
                    aad.len(),
                )
            }) {
                return Err(Unspecified);
            }
        }

        Ok(nonce)
    }

    #[inline]
    fn seal_combined_randnonce<InOut>(
        &self,
        aad: &[u8],
        in_out: &mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

        let mut out_tag_len = MaybeUninit::<usize>::uninit();

        {
            let plaintext_len = in_out.as_mut().len();
            let in_out = in_out.as_mut();

            if 1 != indicator_check!(unsafe {
                EVP_AEAD_CTX_seal_scatter(
                    self.ctx.as_ref().as_const_ptr(),
                    in_out.as_mut_ptr(),
                    tag_buffer.as_mut_ptr(),
                    out_tag_len.as_mut_ptr(),
                    tag_buffer.len(),
                    null(),
                    0,
                    in_out.as_ptr(),
                    plaintext_len,
                    null(),
                    0,
                    aad.as_ptr(),
                    aad.len(),
                )
            }) {
                return Err(Unspecified);
            }
        }

        let tag_len = self.algorithm().tag_len();
        let nonce_len = self.algorithm().nonce_len();

        let nonce = Nonce(FixedLength::<NONCE_LEN>::try_from(
            &tag_buffer[tag_len..tag_len + nonce_len],
        )?);

        in_out.extend(&tag_buffer[..tag_len]);

        Ok(nonce)
    }

    #[inline]
    fn seal_separate(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        let mut tag = [0u8; MAX_TAG_LEN];
        let mut out_tag_len = MaybeUninit::<usize>::uninit();
        {
            let nonce = nonce.as_ref();

            debug_assert_eq!(nonce.len(), self.algorithm().nonce_len());

            if 1 != indicator_check!(unsafe {
                EVP_AEAD_CTX_seal_scatter(
                    self.ctx.as_ref().as_const_ptr(),
                    in_out.as_mut_ptr(),
                    tag.as_mut_ptr(),
                    out_tag_len.as_mut_ptr(),
                    tag.len(),
                    nonce.as_ptr(),
                    nonce.len(),
                    in_out.as_ptr(),
                    in_out.len(),
                    null(),
                    0usize,
                    aad.as_ptr(),
                    aad.len(),
                )
            }) {
                return Err(Unspecified);
            }
        }
        Ok((nonce, Tag(tag, unsafe { out_tag_len.assume_init() })))
    }

    #[inline]
    fn seal_separate_randnonce(
        &self,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

        debug_assert!(
            self.algorithm().tag_len() + self.algorithm().nonce_len() <= tag_buffer.len()
        );

        let mut out_tag_len = MaybeUninit::<usize>::uninit();

        if 1 != indicator_check!(unsafe {
            EVP_AEAD_CTX_seal_scatter(
                self.ctx.as_ref().as_const_ptr(),
                in_out.as_mut_ptr(),
                tag_buffer.as_mut_ptr(),
                out_tag_len.as_mut_ptr(),
                tag_buffer.len(),
                null(),
                0,
                in_out.as_ptr(),
                in_out.len(),
                null(),
                0usize,
                aad.as_ptr(),
                aad.len(),
            )
        }) {
            return Err(Unspecified);
        }

        let tag_len = self.algorithm().tag_len();
        let nonce_len = self.algorithm().nonce_len();

        let nonce = Nonce(FixedLength::<NONCE_LEN>::try_from(
            &tag_buffer[tag_len..tag_len + nonce_len],
        )?);

        let mut tag = [0u8; MAX_TAG_LEN];
        tag.copy_from_slice(&tag_buffer[..tag_len]);

        Ok((nonce, Tag(tag, tag_len)))
    }
}

impl From<AeadCtx> for UnboundKey {
    fn from(value: AeadCtx) -> Self {
        let algorithm = match value {
            AeadCtx::AES_128_GCM(_)
            | AeadCtx::AES_128_GCM_TLS12(_)
            | AeadCtx::AES_128_GCM_TLS13(_)
            | AeadCtx::AES_128_GCM_RANDNONCE(_) => &AES_128_GCM,
            AeadCtx::AES_192_GCM(_) => &AES_192_GCM,
            AeadCtx::AES_128_GCM_SIV(_) => &AES_128_GCM_SIV,
            AeadCtx::AES_256_GCM(_)
            | AeadCtx::AES_256_GCM_RANDNONCE(_)
            | AeadCtx::AES_256_GCM_TLS12(_)
            | AeadCtx::AES_256_GCM_TLS13(_) => &AES_256_GCM,
            AeadCtx::AES_256_GCM_SIV(_) => &AES_256_GCM_SIV,
            AeadCtx::CHACHA20_POLY1305(_) => &CHACHA20_POLY1305,
        };
        Self {
            ctx: value,
            algorithm,
        }
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}
