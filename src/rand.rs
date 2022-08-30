// Copyright 2015-2016 Brian Smith.
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

//! Cryptographic pseudo-random number generation.
//!
//! An application should create a single `SystemRandom` and then use it for
//! all randomness generation. Functions that generate random bytes should take
//! a `&dyn SecureRandom` parameter instead of instantiating their own. Besides
//! being more efficient, this also helps document where non-deterministic
//! (random) outputs occur. Taking a reference to a `SecureRandom` also helps
//! with testing techniques like fuzzing, where it is useful to use a
//! (non-secure) deterministic implementation of `SecureRandom` so that results
//! can be replayed. Following this pattern also may help with sandboxing
//! (seccomp filters on Linux in particular). See `SystemRandom`'s
//! documentation for more details.

use crate::error;
use crate::error::Unspecified;
use std::fmt::{Debug, Formatter};
use std::os::raw::c_int;
use std::path::PathBuf;

/// A secure random number generator.
pub trait SecureRandom: sealed::SecureRandom {
    /// Fills `dest` with random bytes.
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
}

impl<T> SecureRandom for T
where
    T: sealed::SecureRandom,
{
    #[inline(always)]
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        self.fill_impl(dest)
    }
}

/// A random value constructed from a `SecureRandom` that hasn't been exposed
/// through any safe Rust interface.
///
/// Intentionally does not implement any traits other than `Sized`.
pub struct Random<T: RandomlyConstructable>(T);

impl<T: RandomlyConstructable> Random<T> {
    /// Expose the random value.
    #[inline]
    pub fn expose(self) -> T {
        self.0
    }
}

/// Generate the new random value using `rng`.
#[inline]
pub fn generate<T: RandomlyConstructable>(
    rng: &dyn SecureRandom,
) -> Result<Random<T>, error::Unspecified>
where
    T: RandomlyConstructable,
{
    let mut r = T::zero();
    rng.fill(r.as_mut_bytes())?;
    Ok(Random(r))
}

pub(crate) mod sealed {
    use crate::error;

    pub trait SecureRandom: core::fmt::Debug {
        /// Fills `dest` with random bytes.
        fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
    }

    pub trait RandomlyConstructable: Sized {
        fn zero() -> Self; // `Default::default()`
        fn as_mut_bytes(&mut self) -> &mut [u8]; // `AsMut<[u8]>::as_mut`
    }

    macro_rules! impl_random_arrays {
        [ $($len:expr)+ ] => {
            $(
                impl RandomlyConstructable for [u8; $len] {
                    #[inline]
                    fn zero() -> Self { [0; $len] }

                    #[inline]
                    fn as_mut_bytes(&mut self) -> &mut [u8] { &mut self[..] }
                }
            )+
        }
    }

    impl_random_arrays![4 8 16 32 48 64 128 256];
}

/// A type that can be returned by `ring::rand::generate()`.
pub trait RandomlyConstructable: self::sealed::RandomlyConstructable {}
impl<T> RandomlyConstructable for T where T: self::sealed::RandomlyConstructable {}

/// A secure random number generator where the random values come directly
/// from the operating system.
///
/// A single `SystemRandom` may be shared across multiple threads safely.
///
///
/// [`getrandom`]: http://man7.org/linux/man-pages/man2/getrandom.2.html
#[derive(Clone, Debug)]
pub struct SystemRandom(());

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline(always)]
    pub fn new() -> Self {
        Self(())
    }
}

impl sealed::SecureRandom for SystemRandom {
    #[inline(always)]
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        AWS_LC_SECURE_RANDOM.fill(dest)
    }
}

pub struct AwsLcSecureRandom(());

pub const AWS_LC_SECURE_RANDOM: AwsLcSecureRandom = AwsLcSecureRandom(());

impl Debug for AwsLcSecureRandom {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("{ AWS_LC_SECURE_RANDOM }")
    }
}

impl sealed::SecureRandom for AwsLcSecureRandom {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        unsafe {
            if 1 != aws_lc_sys::RAND_bytes(dest.as_mut_ptr(), dest.len()) {
                Err(error::Unspecified)
            } else {
                Ok(())
            }
        }
    }
}
