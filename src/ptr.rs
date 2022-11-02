/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 */

use std::ops::Deref;

use aws_lc_sys::OPENSSL_free;

#[derive(Debug)]
pub(crate) struct LcPtr<P: Pointer> {
    pointer: P,
}

impl<P: Pointer> Deref for LcPtr<P> {
    type Target = P;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.pointer
    }
}

impl<P: Pointer> LcPtr<P> {
    #[inline]
    pub fn new<T: IntoPointer<P>>(value: T) -> Result<Self, ()> {
        if let Some(pointer) = value.into_pointer() {
            Ok(Self { pointer })
        } else {
            Err(())
        }
    }
}

impl<P: Pointer> Drop for LcPtr<P> {
    #[inline]
    fn drop(&mut self) {
        self.pointer.free();
    }
}

impl<P: Pointer + Copy> LcPtr<P> {
    #[inline]
    pub fn as_non_null(&self) -> NonNullPtr<P> {
        NonNullPtr {
            pointer: self.pointer,
        }
    }
}

#[derive(Debug)]
pub struct DetachableLcPtr<P: Pointer> {
    pointer: Option<P>,
}

impl<P: Pointer> Deref for DetachableLcPtr<P> {
    type Target = P;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.pointer {
            Some(pointer) => pointer,
            None => unsafe {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                core::hint::unreachable_unchecked()
            },
        }
    }
}

impl<P: Pointer> DetachableLcPtr<P> {
    #[inline]
    pub fn new<T: IntoPointer<P>>(value: T) -> Result<Self, ()> {
        if let Some(pointer) = value.into_pointer() {
            Ok(Self {
                pointer: Some(pointer),
            })
        } else {
            Err(())
        }
    }
    #[inline]
    pub fn detach(mut self) -> NonNullPtr<P> {
        match self.pointer.take() {
            Some(pointer) => NonNullPtr { pointer },
            None => unsafe {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                core::hint::unreachable_unchecked()
            },
        }
    }
}

impl<P: Pointer + Copy> DetachableLcPtr<P> {
    #[inline]
    pub fn as_non_null(&self) -> NonNullPtr<P> {
        match self.pointer {
            Some(pointer) => NonNullPtr { pointer },
            None => unsafe {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                core::hint::unreachable_unchecked()
            },
        }
    }
}

impl<P: Pointer> From<DetachableLcPtr<P>> for LcPtr<P> {
    #[inline]
    fn from(mut dptr: DetachableLcPtr<P>) -> Self {
        match dptr.pointer.take() {
            Some(pointer) => LcPtr { pointer },
            None => unsafe {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                core::hint::unreachable_unchecked()
            },
        }
    }
}

impl<P: Pointer> Drop for DetachableLcPtr<P> {
    #[inline]
    fn drop(&mut self) {
        if let Some(mut pointer) = self.pointer.take() {
            pointer.free();
        }
    }
}

pub struct NonNullPtr<P: Pointer> {
    pointer: P,
}

impl<P: Pointer> Deref for NonNullPtr<P> {
    type Target = P;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.pointer
    }
}

impl<P: Pointer> NonNullPtr<P> {
    #[inline]
    pub fn new<T: IntoPointer<P>>(value: T) -> Result<Self, ()> {
        if let Some(pointer) = value.into_pointer() {
            Ok(Self { pointer })
        } else {
            Err(())
        }
    }
}

impl<P: Pointer> From<NonNullPtr<P>> for LcPtr<P> {
    #[inline]
    fn from(nnptr: NonNullPtr<P>) -> Self {
        LcPtr {
            pointer: nnptr.pointer,
        }
    }
}

pub trait Pointer {
    fn free(&mut self);
}

pub trait IntoPointer<P> {
    fn into_pointer(self) -> Option<P>;
}

impl<T> IntoPointer<*mut T> for *const T {
    #[inline]
    fn into_pointer(self) -> Option<*mut T> {
        if self.is_null() {
            None
        } else {
            Some(self as *mut T)
        }
    }
}

impl<T> IntoPointer<*mut T> for *mut T {
    #[inline]
    fn into_pointer(self) -> Option<*mut T> {
        if self.is_null() {
            None
        } else {
            Some(self)
        }
    }
}

impl<T> IntoPointer<*mut T> for NonNullPtr<*mut T>
where
    *mut T: Pointer,
{
    #[inline]
    fn into_pointer(self) -> Option<*mut T> {
        if self.is_null() {
            None
        } else {
            Some(self.pointer)
        }
    }
}

#[macro_export]
macro_rules! create_pointer {
    ($ty:ty, $free:path) => {
        impl Pointer for *mut $ty {
            #[inline]
            fn free(&mut self) {
                unsafe {
                    let ptr = *self;
                    $free(ptr.cast());
                }
            }
        }
    };
}
use aws_lc_sys::*;
create_pointer!(u8, OPENSSL_free);
create_pointer!(EC_GROUP, EC_GROUP_free);
create_pointer!(EC_POINT, EC_POINT_free);
create_pointer!(EC_KEY, EC_KEY_free);
create_pointer!(ECDSA_SIG, ECDSA_SIG_free);
create_pointer!(BIGNUM, BN_free);
create_pointer!(EVP_PKEY, EVP_PKEY_free);
create_pointer!(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
create_pointer!(EVP_MD_CTX, EVP_MD_CTX_free);
create_pointer!(HMAC_CTX, HMAC_CTX_free);
create_pointer!(RSA, RSA_free);
