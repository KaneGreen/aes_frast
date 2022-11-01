//! # aes_frast
//! `aes_frast` is an easy-to-use lib for AES encryption and decryption, coded in pure safe
//! Rust-lang.
/// The `aes_core` mod provides the essential functions of AES, including key scheduling and
/// single-block crypto.
pub mod aes_core;
/// The `aes_with_operation_mode` mod provides operation modes such as CBC and OFB, and so on.
pub mod aes_with_operation_mode;
/// The `padding_128bit` mod provides padding and depadding functions for 128bit-block crypto.
pub mod padding_128bit;
///// The `aes_with_operation_mode_inplace` mod is similar to `aes_with_operation_mode` but operates inplace.
//pub mod aes_with_operation_mode_inplace;

pub mod misc {
    /// Convert hexadecimal string to 32-bit words (u32) using big endian.
    #[inline(always)]
    pub fn hex(s: &str) -> u32 {
        ::std::primitive::u32::from_str_radix(s, 16)
            .unwrap()
            .to_be()
    }
}

pub use aes_core::N_SUBKEYS_128BIT;
pub use aes_core::N_SUBKEYS_192BIT;
pub use aes_core::N_SUBKEYS_256BIT;
