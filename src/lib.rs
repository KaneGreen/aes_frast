//! # aes_frast
//! `aes_frast` is an easy-to-use lib for AES encryption and decryption, coded in pure safe Rust-lang.
/// The `aes_core` mod provides the essential functions of AES, including key schedule and single-block crypto.
pub mod aes_core;
/// The `padding_128bit` mod provides padding and depadding functions for 128bit-block crypto.
pub mod padding_128bit;
// /// The `aes_with_operation_mode` mod provides operation modes such as CBC and OFB, and so on.
// pub mod aes_with_operation_mode;
