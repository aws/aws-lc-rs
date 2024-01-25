// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Serialization formats

use self::types::Pkcs8V1DerType;
use crate::buffer::Buffer;
use crate::encoding::types::{
    Curve25519SeedBinType, EcPrivateKeyBinType, EcPrivateKeyRfc5915DerType, EcPublicKeyX509DerType,
};
use core::fmt::{Debug, Error, Formatter};
use core::ops::Deref;

use paste::paste;

macro_rules! generated_encodings {
    ($($name:ident),*) => {paste! {
        mod types {
            $(
                pub struct [<$name Type>] {
                    _priv: (),
                }
            )*
        }
        $(
            /// Serialized bytes
            pub struct $name<'a>(Buffer<'a, [<$name Type>]>);

            impl<'a> Deref for $name<'a> {
                type Target = Buffer<'a, [<$name Type>]>;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl $name<'static> {
                #[allow(dead_code)]
                pub(crate) fn new(owned: Vec<u8>) -> Self {
                    Self(Buffer::new(owned))
                }
                #[allow(dead_code)]
                pub(crate) fn take_from_slice(owned: &mut [u8]) -> Self {
                    Self(Buffer::take_from_slice(owned))
                }
            }

            impl Debug for $name<'_> {
                fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
                    f.debug_struct(stringify!($name)).finish()
                }

            }
        )*
    }}
}
generated_encodings!(
    EcPrivateKeyBin,
    EcPrivateKeyRfc5915Der,
    EcPublicKeyX509Der,
    Curve25519SeedBin,
    Pkcs8V1Der
);

/// Trait for types that can be serialized into a DER format.
pub trait AsDer<T> {
    /// Serializes into a DER format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_der(&self) -> Result<T, crate::error::Unspecified>;
}

/// Trait for values that can be serialized into a big-endian format
pub trait AsBigEndian<T> {
    /// Serializes into a big-endian format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_be_bytes(&self) -> Result<T, crate::error::Unspecified>;
}
