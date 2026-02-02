// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Tests to verify that the `SecureRandom` trait and related functionality
//! are publicly available when the `dev-tests-only` feature is enabled.
//! This enables consumers to create their own implementations of `SecureRandom`
//! for deterministic testing purposes.
//!
//! These tests are only compiled when `dev_tests_only` cfg is enabled.
//! Run with:
//!    `AWS_LC_RS_DEV_TESTS_ONLY=1 cargo test --test unsealed_rand_test`
//! OR:
//!    `cargo test --features dev-tests-only --test unsealed_rand_test`

#![cfg(dev_tests_only)]
#![allow(clippy::cast_possible_truncation)]

use aws_lc_rs::error::Unspecified;
// When external_tests is enabled, the unsealed module is public, allowing
// consumers to implement unsealed::SecureRandom for their own types.
use aws_lc_rs::rand::unsealed;
use aws_lc_rs::rand::SecureRandom;

/// A deterministic implementation of `SecureRandom` for testing purposes.
/// This fills the destination buffer with a repeating pattern based on
/// the provided seed byte.
#[derive(Debug)]
struct DeterministicRandom {
    seed: u8,
}

impl DeterministicRandom {
    fn new(seed: u8) -> Self {
        Self { seed }
    }
}

// Implement the unsealed::SecureRandom trait. The blanket impl in aws-lc-rs
// will automatically provide the public SecureRandom trait.
impl unsealed::SecureRandom for DeterministicRandom {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        for (i, byte) in dest.iter_mut().enumerate() {
            // Create a deterministic pattern based on seed and position
            *byte = self.seed.wrapping_add(i as u8);
        }
        Ok(())
    }
}

/// A deterministic implementation that returns bytes from a fixed slice.
/// Useful for test vectors where exact byte sequences are required.
#[derive(Debug)]
struct FixedBytesRandom<'a> {
    bytes: &'a [u8],
}

impl<'a> FixedBytesRandom<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl unsealed::SecureRandom for FixedBytesRandom<'_> {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        if dest.len() != self.bytes.len() {
            return Err(Unspecified);
        }
        dest.copy_from_slice(self.bytes);
        Ok(())
    }
}

/// A stateful random implementation that returns different bytes on each call.
/// Useful for testing scenarios requiring multiple random generations.
#[derive(Debug)]
struct SequentialRandom {
    counter: std::cell::Cell<u8>,
}

impl SequentialRandom {
    fn new(start: u8) -> Self {
        Self {
            counter: std::cell::Cell::new(start),
        }
    }
}

impl unsealed::SecureRandom for SequentialRandom {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
        let current = self.counter.get();
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = current.wrapping_add(i as u8);
        }
        self.counter.set(current.wrapping_add(1));
        Ok(())
    }
}

#[test]
fn test_custom_secure_random_implementation() {
    // Verify that we can create and use a custom SecureRandom implementation
    let rng = DeterministicRandom::new(42);

    let mut buffer1 = [0u8; 16];
    let mut buffer2 = [0u8; 16];

    // Fill buffers using the SecureRandom trait's fill method
    // (provided by the blanket impl for any unsealed::SecureRandom implementor)
    rng.fill(&mut buffer1).expect("fill should succeed");
    rng.fill(&mut buffer2).expect("fill should succeed");

    // Since the implementation is deterministic, both fills should produce the same result
    assert_eq!(buffer1, buffer2);

    // Verify the pattern matches our expected deterministic output
    for (i, byte) in buffer1.iter().enumerate() {
        assert_eq!(*byte, 42u8.wrapping_add(i as u8));
    }
}

#[test]
fn test_fixed_bytes_random_implementation() {
    let expected_bytes: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let rng = FixedBytesRandom::new(&expected_bytes);

    let mut buffer = [0u8; 8];
    rng.fill(&mut buffer).expect("fill should succeed");

    assert_eq!(buffer, expected_bytes);
}

#[test]
fn test_fixed_bytes_random_length_mismatch() {
    let bytes: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    let rng = FixedBytesRandom::new(&bytes);

    // Attempting to fill a buffer of different size should fail
    let mut buffer = [0u8; 8];
    assert!(rng.fill(&mut buffer).is_err());
}

#[test]
fn test_sequential_random_implementation() {
    let rng = SequentialRandom::new(0);

    let mut buffer1 = [0u8; 4];
    let mut buffer2 = [0u8; 4];

    rng.fill(&mut buffer1).expect("fill should succeed");
    rng.fill(&mut buffer2).expect("fill should succeed");

    // First call starts at 0
    assert_eq!(buffer1, [0, 1, 2, 3]);
    // Second call starts at 1 (counter incremented)
    assert_eq!(buffer2, [1, 2, 3, 4]);
}

#[test]
fn test_mut_fill_method() {
    // Test that mut_fill is also available for custom implementations
    let mut rng = DeterministicRandom::new(100);

    let mut buffer = [0u8; 8];
    rng.mut_fill(&mut buffer).expect("mut_fill should succeed");

    // Verify the pattern
    for (i, byte) in buffer.iter().enumerate() {
        assert_eq!(*byte, 100u8.wrapping_add(i as u8));
    }
}

#[test]
fn test_empty_buffer_fill() {
    let rng = DeterministicRandom::new(0);

    let mut empty_buffer: [u8; 0] = [];
    // Filling an empty buffer should succeed
    rng.fill(&mut empty_buffer)
        .expect("fill of empty buffer should succeed");
}

#[test]
fn test_large_buffer_fill() {
    let rng = DeterministicRandom::new(0);

    let mut large_buffer = [0u8; 1024];
    rng.fill(&mut large_buffer)
        .expect("fill of large buffer should succeed");

    // Verify wrapping behavior for indices > 255
    assert_eq!(large_buffer[0], 0);
    assert_eq!(large_buffer[255], 255);
    assert_eq!(large_buffer[256], 0); // Wraps around
    assert_eq!(large_buffer[257], 1);
}

#[test]
fn test_system_random_mut_fill() {
    // Verify that the existing SystemRandom also has mut_fill available
    let mut rng = aws_lc_rs::rand::SystemRandom::new();

    let mut buffer = [0u8; 32];
    rng.mut_fill(&mut buffer)
        .expect("SystemRandom mut_fill should succeed");

    // The buffer should have been filled with random data
    // With 32 bytes, it's extremely unlikely to be all zeros
    assert!(buffer.iter().any(|&b| b != 0));
}

#[test]
fn test_use_with_dyn_trait_object() {
    // Verify that custom implementations can be used as trait objects
    let rng: &dyn SecureRandom = &DeterministicRandom::new(55);

    let mut buffer = [0u8; 4];
    rng.fill(&mut buffer)
        .expect("fill via trait object should succeed");

    assert_eq!(buffer, [55, 56, 57, 58]);
}

#[test]
fn test_mut_dyn_trait_object() {
    // Verify that mut_fill works with mutable trait objects
    let mut rng_impl = DeterministicRandom::new(10);
    let rng: &mut dyn SecureRandom = &mut rng_impl;

    let mut buffer = [0u8; 4];
    rng.mut_fill(&mut buffer)
        .expect("mut_fill via trait object should succeed");

    assert_eq!(buffer, [10, 11, 12, 13]);
}
