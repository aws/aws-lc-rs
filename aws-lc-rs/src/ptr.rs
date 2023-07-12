// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::ops::Deref;

use aws_lc::{OPENSSL_free, EVP_PKEY_CTX};

use mirai_annotations::verify_unreachable;

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
    pub fn as_const<T>(&self) -> ConstPointer<T> {
        ConstPointer {
            ptr: self.pointer.as_const_ptr(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) struct DetachableLcPtr<P: Pointer> {
    pointer: Option<P>,
}

impl<P: Pointer> Deref for DetachableLcPtr<P> {
    type Target = P;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match &self.pointer {
            Some(pointer) => pointer,
            None => {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                verify_unreachable!()
            }
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
    pub fn detach(mut self) -> P {
        self.pointer.take().unwrap()
    }
}

impl<P: Pointer + Copy> DetachableLcPtr<P> {
    #[inline]
    pub fn as_const<T>(&self) -> ConstPointer<T> {
        match self.pointer {
            Some(pointer) => ConstPointer {
                ptr: pointer.as_const_ptr(),
            },
            None => {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                verify_unreachable!()
            }
        }
    }
}

impl<P: Pointer> From<DetachableLcPtr<P>> for LcPtr<P> {
    #[inline]
    fn from(mut dptr: DetachableLcPtr<P>) -> Self {
        match dptr.pointer.take() {
            Some(pointer) => LcPtr { pointer },
            None => {
                // Safety: pointer is only None when DetachableLcPtr is detached or dropped
                verify_unreachable!()
            }
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

#[derive(Debug)]
pub(crate) struct ConstPointer<T> {
    ptr: *const T,
}

impl<T> ConstPointer<T> {
    pub fn new(ptr: *const T) -> Result<ConstPointer<T>, ()> {
        if ptr.is_null() {
            return Err(());
        }
        Ok(ConstPointer { ptr })
    }
}

impl<T> Deref for ConstPointer<T> {
    type Target = *const T;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

pub(crate) trait Pointer {
    fn free(&mut self);
    fn as_const_ptr<T>(&self) -> *const T;
}

pub(crate) trait IntoPointer<P> {
    fn into_pointer(self) -> Option<P>;
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

            fn as_const_ptr<T>(&self) -> *const T {
                self.cast()
            }
        }
    };
}
use aws_lc::{
    BN_free, ECDSA_SIG_free, EC_GROUP_free, EC_KEY_free, EC_POINT_free, EVP_PKEY_free, RSA_free,
    BIGNUM, ECDSA_SIG, EC_GROUP, EC_KEY, EC_POINT, EVP_PKEY, RSA,
};

// `OPENSSL_free` and the other `XXX_free` functions perform a zeroization of the memory when it's
// freed. This is different than functions of the same name in OpenSSL which generally do not zero
// memory.
create_pointer!(u8, OPENSSL_free);
create_pointer!(EC_GROUP, EC_GROUP_free);
create_pointer!(EC_POINT, EC_POINT_free);
create_pointer!(EC_KEY, EC_KEY_free);
create_pointer!(ECDSA_SIG, ECDSA_SIG_free);
create_pointer!(BIGNUM, BN_free);
create_pointer!(EVP_PKEY, EVP_PKEY_free);
create_pointer!(EVP_PKEY_CTX, EVP_PKEY_free);
create_pointer!(RSA, RSA_free);

#[cfg(test)]
mod tests {
    use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr};
    use aws_lc::BIGNUM;

    #[test]
    fn test_debug() {
        let num = 100u64;
        let detachable_ptr: DetachableLcPtr<*mut BIGNUM> = DetachableLcPtr::try_from(num).unwrap();
        let debug = format!("{detachable_ptr:?}");
        assert!(debug.contains("DetachableLcPtr { pointer: Some("));

        let const_ptr: ConstPointer<BIGNUM> = detachable_ptr.as_const();
        let debug = format!("{const_ptr:?}");
        assert!(debug.contains("ConstPointer { ptr:"));

        let lc_ptr = LcPtr::new(detachable_ptr.detach()).unwrap();
        let debug = format!("{lc_ptr:?}");
        assert!(debug.contains("LcPtr { pointer:"));
    }
}
