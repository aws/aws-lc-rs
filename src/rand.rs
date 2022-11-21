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

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

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

use std::fmt::Debug;

use crate::error;

/// A secure random number generator.
pub trait SecureRandom: sealed::SecureRandom {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    /// `error::Unspecified` if unable to fill `dest`.
    ///
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
}

impl<T> SecureRandom for T
where
    T: sealed::SecureRandom,
{
    #[inline]
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
///
/// # Errors
/// `error::Unspecified` if unable to fill buffer.
///
#[inline]
pub fn generate<T: RandomlyConstructable>(
    rng: &dyn SecureRandom,
) -> Result<Random<T>, error::Unspecified> {
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
        fn zero() -> Self;
        // `Default::default()`
        fn as_mut_bytes(&mut self) -> &mut [u8]; // `AsMut<[u8]>::as_mut`
    }

    impl<const T: usize> RandomlyConstructable for [u8; T] {
        #[inline]
        fn zero() -> Self {
            [0; T]
        }

        #[inline]
        fn as_mut_bytes(&mut self) -> &mut [u8] {
            &mut self[..]
        }
    }
}

/// A type that can be returned by `ring::rand::generate()`.
pub trait RandomlyConstructable: sealed::RandomlyConstructable {}

impl<T> RandomlyConstructable for T where T: sealed::RandomlyConstructable {}

/// A secure random number generator where the random values come from the
/// underlying AWS-LC libcrypto.
///
/// A single `SystemRandom` may be shared across multiple threads safely.
#[derive(Clone, Debug)]
pub struct SystemRandom(());

const SYSTEM_RANDOM: SystemRandom = SystemRandom(());

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for SystemRandom {
    fn default() -> Self {
        SYSTEM_RANDOM
    }
}

impl sealed::SecureRandom for SystemRandom {
    #[inline]
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        unsafe {
            if 1 == aws_lc_sys::RAND_bytes(dest.as_mut_ptr(), dest.len()) {
                Ok(())
            } else {
                Err(error::Unspecified)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::array::IntoIter;

    use crate::rand::generate;
    use crate::rand::SystemRandom;

    #[test]
    fn test_randomly_constructable() {
        let rando = SystemRandom::new();
        let random_array = generate(&rando).unwrap();
        let random_array: [u8; 173] = random_array.expose();
        let (mean, variance) = mean_variance(&mut random_array.into_iter()).unwrap();
        assert!((106f64..150f64).contains(&mean), "Mean: {}", mean);
        assert!(variance > 8f64);
        println!("Mean: {} Variance: {}", mean, variance);
    }

    fn mean_variance<T: Into<f64>, const N: usize>(
        iterable: &mut IntoIter<T, N>,
    ) -> Option<(f64, f64)> {
        let iter = iterable;
        let mean: Option<T> = iter.next();
        mean.as_ref()?;
        let mut mean = mean.unwrap().into();
        let mut var_squared = 0f64;
        let mut count = 1f64;
        for value in iter.by_ref() {
            count += 1f64;
            let value = value.into();
            let prev_mean = mean;
            mean = prev_mean + (value - prev_mean) / count;
            var_squared =
                var_squared + ((value - prev_mean) * (value - mean) - var_squared) / count;
        }

        Some((mean, var_squared.sqrt()))
    }
}
