extern crate core;

pub mod aead;

#[macro_use]
pub mod test;

pub mod error;

mod debug;

mod c;

mod endian;

mod polyfill;
