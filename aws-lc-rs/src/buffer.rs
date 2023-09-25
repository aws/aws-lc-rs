//! This module exposes a buffer type used in crate APIs returning private keys and other "private"
//! contents.

use std::fmt;

use zeroize::Zeroize;

/// This is a buffer type for private contents (e.g., private key bytes) which is zeroed on drop.
pub struct PrivateBuffer(Box<[u8]>);

impl PrivateBuffer {
    pub(crate) fn new(slice: &mut [u8]) -> PrivateBuffer {
        let ret = PrivateBuffer(slice.to_vec().into_boxed_slice());
        slice.zeroize();
        ret
    }
}

impl Drop for PrivateBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PrivateBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("PrivateBuffer()")
    }
}

impl AsRef<[u8]> for PrivateBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
