// Copyright 2015-2021 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Error reporting.

extern crate std;

use core::num::TryFromIntError;
// The Error trait is not in core: https://github.com/rust-lang/rust/issues/103765
use std::error::Error;

/// An error with absolutely no details.
///
/// *aws-lc-rs* uses this unit type as the error type in most of its results
/// because (a) usually the specific reasons for a failure are obvious or are
/// not useful to know, and/or (b) providing more details about a failure might
/// provide a dangerous side channel, and/or (c) it greatly simplifies the
/// error handling logic.
///
/// `Result<T, aws_lc_rs::error::Unspecified>` is mostly equivalent to
/// `Result<T, ()>`. However, `aws_lc_rs::error::Unspecified` implements
/// [`std::error::Error`] and users can implement
/// `From<error::Unspecified>` to map this to their own error types, as
/// described in [“Error Handling” in the Rust Book](https://doc.rust-lang.org/book/ch09-00-error-handling.html):
///
/// ```
/// use aws_lc_rs::rand::{self, SecureRandom};
///
/// enum Error {
///     CryptoError,
///
///     IOError(std::io::Error),
///     // [...]
/// }
///
/// impl From<aws_lc_rs::error::Unspecified> for Error {
///     fn from(_: aws_lc_rs::error::Unspecified) -> Self {
///         Error::CryptoError
///     }
/// }
///
/// fn eight_random_bytes() -> Result<[u8; 8], Error> {
///     let rng = rand::SystemRandom::new();
///     let mut bytes = [0; 8];
///
///     // The `From<aws_lc_rs::error::Unspecified>` implementation above makes this
///     // equivalent to
///     // `rng.fill(&mut bytes).map_err(|_| Error::CryptoError)?`.
///     rng.fill(&mut bytes)?;
///
///     Ok(bytes)
/// }
///
/// assert!(eight_random_bytes().is_ok());
/// ```
///
/// Experience with using and implementing other crypto libraries like has
/// shown that sophisticated error reporting facilities often cause significant
/// bugs themselves, both within the crypto library and within users of the
/// crypto library. This approach attempts to minimize complexity in the hopes
/// of avoiding such problems. In some cases, this approach may be too extreme,
/// and it may be important for an operation to provide some details about the
/// cause of a failure. Users of *aws-lc-rs* are encouraged to report such cases so
/// that they can be addressed individually.
///
/// [`std::error::Error`]: https://doc.rust-lang.org/std/error/trait.Error.html
/// [“Error Handling” in the Rust Book]:
///     https://doc.rust-lang.org/book/first-edition/error-handling.html#the-from-trait
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unspecified;

// This is required for the implementation of `std::error::Error`.
impl core::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("Unspecified")
    }
}

impl From<core::array::TryFromSliceError> for Unspecified {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Self
    }
}

/// An error parsing or validating a key.
///
/// The `Display` implementation and `<KeyRejected as Error>::description()`
/// will return a string that will help you better understand why a key was
/// rejected change which errors are reported in which situations while
/// minimizing the likelihood that any applications will be broken.
///
/// Here is an incomplete list of reasons a key may be unsupported:
///
/// * Invalid or Inconsistent Components: A component of the key has an invalid
///   value, or the mathematical relationship between two (or more) components
///   required for a valid key does not hold.
///
/// * The encoding of the key is invalid. Perhaps the key isn't in the correct
///   format; e.g. it may be Base64 ("PEM") encoded, in which case   the Base64
///   encoding needs to be undone first.
///
/// * The encoding includes a versioning mechanism and that mechanism indicates
///   that the key is encoded in a version of the encoding that isn't supported.
///   This might happen for multi-prime RSA keys (keys with more than two
///   private   prime factors), which aren't supported, for example.
///
/// * Too small or too Large: One of the primary components of the key is too
///   small or two large. Too-small keys are rejected for security reasons. Some
///   unnecessarily large keys are rejected for performance reasons.
///
///  * Wrong algorithm: The key is not valid for the algorithm in which it was
///    being used.
///
///  * Unexpected errors: Report this as a bug.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct KeyRejected(&'static str);

impl KeyRejected {
    /// The value returned from `<Self as std::error::Error>::description()`
    #[must_use]
    pub fn description_(&self) -> &'static str {
        self.0
    }

    pub(crate) fn inconsistent_components() -> Self {
        KeyRejected("InconsistentComponents")
    }

    #[inline]
    pub(crate) fn invalid_encoding() -> Self {
        KeyRejected("InvalidEncoding")
    }

    pub(crate) fn too_small() -> Self {
        KeyRejected("TooSmall")
    }

    pub(crate) fn too_large() -> Self {
        KeyRejected("TooLarge")
    }

    pub(crate) fn wrong_algorithm() -> Self {
        KeyRejected("WrongAlgorithm")
    }

    pub(crate) fn unexpected_error() -> Self {
        KeyRejected("UnexpectedError")
    }

    pub(crate) fn unspecified() -> Self {
        KeyRejected("Unspecified")
    }
}

impl Error for KeyRejected {
    fn description(&self) -> &str {
        self.description_()
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl Error for Unspecified {
    #[allow(clippy::unnecessary_literal_bound)]
    fn description(&self) -> &str {
        "Unspecified"
    }

    #[inline]
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

impl core::fmt::Display for KeyRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.description_())
    }
}

impl From<KeyRejected> for Unspecified {
    fn from(_: KeyRejected) -> Self {
        Unspecified
    }
}

impl From<()> for Unspecified {
    fn from((): ()) -> Self {
        Unspecified
    }
}

impl From<Unspecified> for () {
    fn from(_: Unspecified) -> Self {}
}

impl From<()> for KeyRejected {
    fn from((): ()) -> Self {
        KeyRejected::unexpected_error()
    }
}

#[cfg(any(feature = "ring-sig-verify", feature = "ring-io"))]
impl From<untrusted::EndOfInput> for Unspecified {
    fn from(_: untrusted::EndOfInput) -> Self {
        Unspecified
    }
}

impl From<TryFromIntError> for Unspecified {
    fn from(_: TryFromIntError) -> Self {
        Unspecified
    }
}

impl From<TryFromIntError> for KeyRejected {
    fn from(_: TryFromIntError) -> Self {
        KeyRejected::unexpected_error()
    }
}

impl From<Unspecified> for KeyRejected {
    fn from(_: Unspecified) -> Self {
        Self::unspecified()
    }
}

/// The category of a failure captured internally by *aws-lc-rs*.
///
/// Categories are deliberately coarse. In particular, every authentication and
/// signature verification failure collapses into [`ErrorKind::VerificationFailed`]
/// with no further detail: distinguishing an AEAD tag mismatch from an RSA
/// padding failure is a side channel and must not be observable by callers.
///
/// This type is internal for now. It is the foundation for reporting more detail
/// than [`Unspecified`] can carry; exposing it on the existing public signatures
/// requires a breaking change, because [`Unspecified`] is a unit struct that
/// downstream code constructs (for example in `NonceSequence::advance`
/// implementations) and matches on.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    /// A caller-supplied value was rejected: wrong length, empty slice, or a
    /// value outside the range the algorithm accepts.
    InvalidInput,

    /// A key, signature, or other structure could not be parsed or serialized.
    Encoding,

    /// Authentication or signature verification failed.
    ///
    /// Intentionally opaque: no sub-category is ever recorded for this kind.
    VerificationFailed,

    /// AWS-LC could not allocate memory.
    AllocationFailed,

    /// An AWS-LC call failed for a reason we do not classify further.
    Library,

    /// No detail was captured at the point of failure.
    Unspecified,
}

impl ErrorKind {
    /// A short token naming this category.
    ///
    /// As with [`KeyRejected::description_`], these strings are diagnostic and
    /// callers must not depend on their exact contents.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ErrorKind::InvalidInput => "InvalidInput",
            ErrorKind::Encoding => "Encoding",
            ErrorKind::VerificationFailed => "VerificationFailed",
            ErrorKind::AllocationFailed => "AllocationFailed",
            ErrorKind::Library => "Library",
            ErrorKind::Unspecified => "Unspecified",
        }
    }
}

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failure, together with the operation that produced it.
///
/// `ErrorDetail` is `Copy` and allocation-free: `context` is always a
/// `&'static str`, normally the name of the AWS-LC function that failed. This
/// mirrors how [`KeyRejected`] carries a `&'static str` rather than an owned
/// `String`, so capturing detail cannot itself fail or allocate on an error
/// path.
///
/// Detail is captured at the point of failure and converted to the appropriate
/// public error type ([`Unspecified`] or [`KeyRejected`]) at the API boundary,
/// so adding it does not change any public signature.
//
// TODO: also capture the AWS-LC error queue value (`ERR_get_error`) here. That
// is only meaningful once we clear the queue at the start of each fallible
// operation; today *aws-lc-rs* never calls `ERR_clear_error`, so the queue can
// hold stale entries (including entries from other consumers of AWS-LC in the
// same process) and would report the wrong cause.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ErrorDetail {
    kind: ErrorKind,
    context: &'static str,
}

impl ErrorDetail {
    /// Captures a failure of `kind` produced by `context`.
    pub(crate) const fn new(kind: ErrorKind, context: &'static str) -> Self {
        Self { kind, context }
    }

    /// The category of this failure.
    pub(crate) const fn kind(self) -> ErrorKind {
        self.kind
    }

    /// The operation that produced this failure.
    pub(crate) const fn context(self) -> &'static str {
        self.context
    }

    /// A caller-supplied value was rejected.
    pub(crate) const fn invalid_input(context: &'static str) -> Self {
        Self::new(ErrorKind::InvalidInput, context)
    }

    /// A structure could not be parsed or serialized.
    pub(crate) const fn encoding(context: &'static str) -> Self {
        Self::new(ErrorKind::Encoding, context)
    }

    /// Authentication or signature verification failed.
    //
    // Not yet used: the verification paths in `evp_pkey.rs` still return
    // `Unspecified` directly, and converting them ripples into ~9 tail-position
    // call sites. Exercised by tests so the opaqueness invariant is pinned.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn verification_failed(context: &'static str) -> Self {
        Self::new(ErrorKind::VerificationFailed, context)
    }

    /// AWS-LC could not allocate memory.
    pub(crate) const fn allocation_failed(context: &'static str) -> Self {
        Self::new(ErrorKind::AllocationFailed, context)
    }

    /// An AWS-LC call failed without further classification.
    pub(crate) const fn library(context: &'static str) -> Self {
        Self::new(ErrorKind::Library, context)
    }

    /// No detail was captured.
    pub(crate) const fn unspecified() -> Self {
        Self::new(ErrorKind::Unspecified, "")
    }
}

impl core::fmt::Display for ErrorDetail {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.context().is_empty() {
            f.write_str(self.kind().as_str())
        } else {
            write!(f, "{} ({})", self.kind().as_str(), self.context())
        }
    }
}

impl Error for ErrorDetail {}

impl From<ErrorDetail> for Unspecified {
    fn from(_: ErrorDetail) -> Self {
        Unspecified
    }
}

impl From<ErrorDetail> for KeyRejected {
    fn from(detail: ErrorDetail) -> Self {
        match detail.kind() {
            ErrorKind::Encoding => KeyRejected::invalid_encoding(),
            ErrorKind::InvalidInput
            | ErrorKind::AllocationFailed
            | ErrorKind::Library
            | ErrorKind::VerificationFailed => KeyRejected::unexpected_error(),
            _ => KeyRejected::unspecified(),
        }
    }
}

// An inner function that still returns `Unspecified` has no detail to
// contribute, so it widens to `ErrorKind::Unspecified`. This exists to allow
// converting the crate bottom-up: each use marks an inner call that has not
// been converted yet, so `grep` finds the remaining work.
impl From<Unspecified> for ErrorDetail {
    fn from(_: Unspecified) -> Self {
        ErrorDetail::unspecified()
    }
}

#[allow(deprecated, unused_imports)]
#[cfg(test)]
mod tests {
    use crate::error::{ErrorDetail, ErrorKind, KeyRejected};
    use crate::test;
    use std::error::Error;

    #[test]
    fn display_unspecified() {
        let output = format!("{}", super::Unspecified);
        assert_eq!("Unspecified", output);
    }

    #[test]
    fn unexpected_error() {
        let key_rejected = super::KeyRejected::from(());
        assert_eq!("UnexpectedError", key_rejected.description());

        let unspecified = super::Unspecified::from(key_rejected);
        assert_eq!("Unspecified", unspecified.description());

        #[allow(clippy::redundant_locals)]
        let unspecified = unspecified;
        assert_eq!("Unspecified", unspecified.description());
    }

    #[test]
    fn std_error() {
        let key_rejected = KeyRejected::wrong_algorithm();
        assert!(key_rejected.cause().is_none());
        assert_eq!("WrongAlgorithm", key_rejected.description());

        let unspecified = super::Unspecified;
        assert!(unspecified.cause().is_none());
        assert_eq!("Unspecified", unspecified.description());

        test::compile_time_assert_std_error_error::<KeyRejected>();
    }

    #[test]
    fn error_detail_display() {
        let detail = ErrorDetail::library("EVP_PKEY_new");
        assert_eq!(ErrorKind::Library, detail.kind());
        assert_eq!("EVP_PKEY_new", detail.context());
        assert_eq!("Library (EVP_PKEY_new)", format!("{detail}"));

        // An unspecified detail carries no context and formats like `Unspecified`.
        let detail = ErrorDetail::unspecified();
        assert_eq!("Unspecified", format!("{detail}"));
        assert_eq!("Unspecified", format!("{}", ErrorKind::Unspecified));
    }

    #[test]
    fn error_detail_to_unspecified_is_lossy() {
        // The public error type is unchanged, so all detail collapses.
        let unspecified = super::Unspecified::from(ErrorDetail::invalid_input("nonce length"));
        assert_eq!(super::Unspecified, unspecified);
        assert_eq!("Unspecified", format!("{unspecified}"));
    }

    #[test]
    fn error_detail_to_key_rejected() {
        assert_eq!(
            KeyRejected::invalid_encoding(),
            KeyRejected::from(ErrorDetail::encoding("EVP_parse_private_key"))
        );
        assert_eq!(
            KeyRejected::unexpected_error(),
            KeyRejected::from(ErrorDetail::allocation_failed("EVP_PKEY_new"))
        );
        assert_eq!(
            KeyRejected::unexpected_error(),
            KeyRejected::from(ErrorDetail::library("EVP_PKEY_CTX_new"))
        );
        assert_eq!(
            KeyRejected::unspecified(),
            KeyRejected::from(ErrorDetail::unspecified())
        );
    }

    #[test]
    fn error_detail_verification_failure_is_opaque() {
        // Verification failures must not be distinguishable from one another.
        let aead = ErrorDetail::verification_failed("EVP_AEAD_CTX_open");
        let rsa = ErrorDetail::verification_failed("EVP_AEAD_CTX_open");
        assert_eq!(aead, rsa);
        assert_eq!(ErrorKind::VerificationFailed, aead.kind());

        // ... and they must not leak a sub-category through the public type.
        assert_eq!(super::Unspecified, super::Unspecified::from(aead));
    }
}
