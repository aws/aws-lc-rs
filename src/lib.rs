extern crate core;

pub mod aead;

pub mod digest;

pub mod test;

pub mod error;

mod debug;

mod c;

mod endian;

mod polyfill;

use std::sync::Once;
static START: Once = Once::new();

#[inline]
pub fn init() {
    START.call_once(|| unsafe {
        aws_lc_sys::CRYPTO_library_init();
    });
}
