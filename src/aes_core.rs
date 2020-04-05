//! # aes_core
//! `aes_core` is the core part of AES crypto, including key scheduling, block encryption and
//! decryption.
//!
//! This module provides **low-level API**.
//!
//! In this library, AES is implemented by looking-up-tables.
//! ## Attention!
//! This low-level API does NOT provide error handling.
//!
//! Please be careful with the lengths of the slices when passing it as the parameters of a
//! function. Otherwise, it will panic at `index out of bounds` or `assertion failed`.
//! ## Block cipher
//! The AES algorithm only supports 128-bit (16 bytes) block.
//!
//! It supports 128-bit (16 bytes), 192-bit (24 bytes) and 265-bit (32 bytes) keys.
//!
//! AES block crypto uses sub-keys, which are derived from a key. This derivation process is called
//! *key schedule*.
//!
//! key size in bits | key size in bytes | sub-keys size in bytes
//! - | - | -
//! 128 | 16 | 44
//! 192 | 24 | 52
//! 256 | 32 | 60

include!("tables.rs");

const N_SUBKEYS_128BIT: usize = 44;
const N_SUBKEYS_192BIT: usize = 52;
const N_SUBKEYS_256BIT: usize = 60;

// Put four u8 numbers in big-endian order to get an u32 number.  
// The first u8 will become the most significant bits (MSB), and the last one will be the least
// significant bits (LSB).
// # Examples
// ```
// let output: u32 = four_u8_to_u32!(0x1Au8, 0x2Bu8, 0x3Cu8, 0x4Du8);
// assert_eq!(output, 0x1A2B3C4Du32);
// ```
macro_rules! four_u8_to_u32 {
    ($b0:expr, $b1:expr, $b2:expr, $b3:expr) => {{
        (($b0 as u32) << 24) ^ (($b1 as u32) << 16) ^ (($b2 as u32) << 8) ^ ($b3 as u32)
    }};
}

// The g function used in key schedule rounds.
macro_rules! round_g_function {
    ($word:expr, $round:expr) => {{
        four_u8_to_u32!(
            SBOX[(($word >> 16) as usize) & 0xFF] ^ RC[$round],
            SBOX[(($word >>  8) as usize) & 0xFF],
            SBOX[( $word        as usize) & 0xFF],
            SBOX[ ($word >> 24) as usize        ]
        )
    }};
}

// The h function used in 256bit key schedule rounds.
macro_rules! round_h_function {
    ($word:expr) => {{
        four_u8_to_u32!(
            SBOX[ ($word >> 24) as usize        ],
            SBOX[(($word >> 16) as usize) & 0xFF],
            SBOX[(($word >>  8) as usize) & 0xFF],
            SBOX[( $word        as usize) & 0xFF]
        )
    }};
}

// 128bit key schedule
macro_rules! key_schedule_128_function {
    ($origin:ident, $keys:ident) => {{
        ::std::assert_eq!($keys.len(), N_SUBKEYS_128BIT);
        for i in 0..4 {
            $keys[i] = four_u8_to_u32!(
                $origin[4 * i    ],
                $origin[4 * i + 1],
                $origin[4 * i + 2],
                $origin[4 * i + 3]
            );
        }
        for i in 0..10 {
            $keys[4 * i + 4] = $keys[4 * i    ] ^ round_g_function!($keys[4 * i + 3], i);
            $keys[4 * i + 5] = $keys[4 * i + 1] ^ $keys[4 * i + 4];
            $keys[4 * i + 6] = $keys[4 * i + 2] ^ $keys[4 * i + 5];
            $keys[4 * i + 7] = $keys[4 * i + 3] ^ $keys[4 * i + 6];
        }
    }};
}

// 192bit key schedule
macro_rules! key_schedule_192_function {
    ($origin:ident, $keys:ident) => {{
        ::std::assert_eq!($keys.len(), N_SUBKEYS_192BIT);
        for i in 0..6 {
            $keys[i] = four_u8_to_u32!(
                $origin[4 * i    ],
                $origin[4 * i + 1],
                $origin[4 * i + 2],
                $origin[4 * i + 3]
            );
        }
        for i in 0..7 {
            $keys[6 * i +  6] = $keys[6 * i    ] ^ round_g_function!($keys[6 * i + 5], i);
            $keys[6 * i +  7] = $keys[6 * i + 1] ^ $keys[6 * i +  6];
            $keys[6 * i +  8] = $keys[6 * i + 2] ^ $keys[6 * i +  7];
            $keys[6 * i +  9] = $keys[6 * i + 3] ^ $keys[6 * i +  8];
            $keys[6 * i + 10] = $keys[6 * i + 4] ^ $keys[6 * i +  9];
            $keys[6 * i + 11] = $keys[6 * i + 5] ^ $keys[6 * i + 10];
        }
        $keys[48] = $keys[42] ^ round_g_function!($keys[47], 7);
        $keys[49] = $keys[43] ^ $keys[48];
        $keys[50] = $keys[44] ^ $keys[49];
        $keys[51] = $keys[45] ^ $keys[50];
    }};
}

// 256bit key schedule
macro_rules! key_schedule_256_function {
    ($origin:ident, $keys:ident) => {{
        ::std::assert_eq!($keys.len(), N_SUBKEYS_256BIT);
        for i in 0..8 {
            $keys[i] = four_u8_to_u32!(
                $origin[4 * i    ],
                $origin[4 * i + 1],
                $origin[4 * i + 2],
                $origin[4 * i + 3]
            );
        }
        for i in 0..6 {
            $keys[8 * i +  8] = $keys[8 * i    ] ^ round_g_function!($keys[8 * i + 7], i);
            $keys[8 * i +  9] = $keys[8 * i + 1] ^ $keys[8 * i +  8];
            $keys[8 * i + 10] = $keys[8 * i + 2] ^ $keys[8 * i +  9];
            $keys[8 * i + 11] = $keys[8 * i + 3] ^ $keys[8 * i + 10];
            $keys[8 * i + 12] = $keys[8 * i + 4] ^ round_h_function!($keys[8 * i + 11]);
            $keys[8 * i + 13] = $keys[8 * i + 5] ^ $keys[8 * i + 12];
            $keys[8 * i + 14] = $keys[8 * i + 6] ^ $keys[8 * i + 13];
            $keys[8 * i + 15] = $keys[8 * i + 7] ^ $keys[8 * i + 14];
        }
        $keys[56] = $keys[48] ^ round_g_function!($keys[55], 6);
        $keys[57] = $keys[49] ^ $keys[56];
        $keys[58] = $keys[50] ^ $keys[57];
        $keys[59] = $keys[51] ^ $keys[58];
    }};
}

// The keys for decryption need extra transform -- the inverse MixColumn.
macro_rules! dkey_mixcolumn {
    ($keys:ident, $length:expr) => {{
        // The first and the last round don't need the inverse MixColumn transform
        for i in 4..($length-4) {
            $keys[i] = TD0[SBOX[ ($keys[i] >> 24) as usize        ] as usize] ^
                       TD1[SBOX[(($keys[i] >> 16) as usize) & 0xFF] as usize] ^
                       TD2[SBOX[(($keys[i] >>  8) as usize) & 0xFF] as usize] ^
                       TD3[SBOX[( $keys[i]        as usize) & 0xFF] as usize];
        }
    }};
}

// Encrypt a block.
macro_rules! encryption_function {
    ($input:ident, $output:ident, $keys:ident, $inner_rounds:expr, $keys_length:expr) => {
        // These `assert` improved performance.
        ::std::assert_eq!($input.len(), 128 / 8_usize);
        ::std::assert_eq!($keys.len(), $keys_length);
        let mut wa0: u32 = four_u8_to_u32!($input[ 0], $input[ 1], $input[ 2], $input[ 3]) ^
                           $keys[0];
        let mut wa1: u32 = four_u8_to_u32!($input[ 4], $input[ 5], $input[ 6], $input[ 7]) ^
                           $keys[1];
        let mut wa2: u32 = four_u8_to_u32!($input[ 8], $input[ 9], $input[10], $input[11]) ^
                           $keys[2];
        let mut wa3: u32 = four_u8_to_u32!($input[12], $input[13], $input[14], $input[15]) ^
                           $keys[3];
        // round 1
        let mut wb0: u32 = TE0[ (wa0 >> 24) as usize        ] ^ TE1[((wa1 >> 16) as usize) & 0xFF] ^
                           TE2[((wa2 >>  8) as usize) & 0xFF] ^ TE3[( wa3        as usize) & 0xFF] ^
                           $keys[4];
        let mut wb1: u32 = TE0[ (wa1 >> 24) as usize        ] ^ TE1[((wa2 >> 16) as usize) & 0xFF] ^
                           TE2[((wa3 >>  8) as usize) & 0xFF] ^ TE3[( wa0        as usize) & 0xFF] ^
                           $keys[5];
        let mut wb2: u32 = TE0[ (wa2 >> 24) as usize        ] ^ TE1[((wa3 >> 16) as usize) & 0xFF] ^
                           TE2[((wa0 >>  8) as usize) & 0xFF] ^ TE3[( wa1        as usize) & 0xFF] ^
                           $keys[6];
        let mut wb3: u32 = TE0[ (wa3 >> 24) as usize        ] ^ TE1[((wa0 >> 16) as usize) & 0xFF] ^
                           TE2[((wa1 >>  8) as usize) & 0xFF] ^ TE3[( wa2        as usize) & 0xFF] ^
                           $keys[7];
        // round 2 to round 9 (or 11, 13)
        for i in 1..$inner_rounds {
            // even-number rounds
            wa0 = TE0[ (wb0 >> 24) as usize        ] ^ TE1[((wb1 >> 16) as usize) & 0xFF] ^
                  TE2[((wb2 >>  8) as usize) & 0xFF] ^ TE3[( wb3        as usize) & 0xFF] ^
                  $keys[8 * i];
            wa1 = TE0[ (wb1 >> 24) as usize        ] ^ TE1[((wb2 >> 16) as usize) & 0xFF] ^
                  TE2[((wb3 >>  8) as usize) & 0xFF] ^ TE3[( wb0        as usize) & 0xFF] ^
                  $keys[8 * i + 1];
            wa2 = TE0[ (wb2 >> 24) as usize        ] ^ TE1[((wb3 >> 16) as usize) & 0xFF] ^
                  TE2[((wb0 >>  8) as usize) & 0xFF] ^ TE3[( wb1        as usize) & 0xFF] ^
                  $keys[8 * i + 2];
            wa3 = TE0[ (wb3 >> 24) as usize        ] ^ TE1[((wb0 >> 16) as usize) & 0xFF] ^
                  TE2[((wb1 >>  8) as usize) & 0xFF] ^ TE3[( wb2        as usize) & 0xFF] ^
                  $keys[8 * i + 3];
            // odd-number rounds
            wb0 = TE0[ (wa0 >> 24) as usize        ] ^ TE1[((wa1 >> 16) as usize) & 0xFF] ^
                  TE2[((wa2 >>  8) as usize) & 0xFF] ^ TE3[( wa3        as usize) & 0xFF] ^
                  $keys[8 * i + 4];
            wb1 = TE0[ (wa1 >> 24) as usize        ] ^ TE1[((wa2 >> 16) as usize) & 0xFF] ^
                  TE2[((wa3 >>  8) as usize) & 0xFF] ^ TE3[( wa0        as usize) & 0xFF] ^
                  $keys[8 * i + 5];
            wb2 = TE0[ (wa2 >> 24) as usize        ] ^ TE1[((wa3 >> 16) as usize) & 0xFF] ^
                  TE2[((wa0 >>  8) as usize) & 0xFF] ^ TE3[( wa1        as usize) & 0xFF] ^
                  $keys[8 * i + 6];
            wb3 = TE0[ (wa3 >> 24) as usize        ] ^ TE1[((wa0 >> 16) as usize) & 0xFF] ^
                  TE2[((wa1 >>  8) as usize) & 0xFF] ^ TE3[( wa2        as usize) & 0xFF] ^
                  $keys[8 * i + 7];
        }
        // final round
        // accessing array elements by index in reverse order is faster than in normal order
        $output[15] = SBOX[( wb2        as usize) & 0xFF] ^ ( $keys[$keys_length - 1]        as u8);
        $output[14] = SBOX[((wb1 >>  8) as usize) & 0xFF] ^ (($keys[$keys_length - 1] >>  8) as u8);
        $output[13] = SBOX[((wb0 >> 16) as usize) & 0xFF] ^ (($keys[$keys_length - 1] >> 16) as u8);
        $output[12] = SBOX[ (wb3 >> 24) as usize        ] ^ (($keys[$keys_length - 1] >> 24) as u8);
        $output[11] = SBOX[( wb1        as usize) & 0xFF] ^ ( $keys[$keys_length - 2]        as u8);
        $output[10] = SBOX[((wb0 >>  8) as usize) & 0xFF] ^ (($keys[$keys_length - 2] >>  8) as u8);
        $output[ 9] = SBOX[((wb3 >> 16) as usize) & 0xFF] ^ (($keys[$keys_length - 2] >> 16) as u8);
        $output[ 8] = SBOX[ (wb2 >> 24) as usize        ] ^ (($keys[$keys_length - 2] >> 24) as u8);
        $output[ 7] = SBOX[( wb0        as usize) & 0xFF] ^ ( $keys[$keys_length - 3]        as u8);
        $output[ 6] = SBOX[((wb3 >>  8) as usize) & 0xFF] ^ (($keys[$keys_length - 3] >>  8) as u8);
        $output[ 5] = SBOX[((wb2 >> 16) as usize) & 0xFF] ^ (($keys[$keys_length - 3] >> 16) as u8);
        $output[ 4] = SBOX[ (wb1 >> 24) as usize        ] ^ (($keys[$keys_length - 3] >> 24) as u8);
        $output[ 3] = SBOX[( wb3        as usize) & 0xFF] ^ ( $keys[$keys_length - 4]        as u8);
        $output[ 2] = SBOX[((wb2 >>  8) as usize) & 0xFF] ^ (($keys[$keys_length - 4] >>  8) as u8);
        $output[ 1] = SBOX[((wb1 >> 16) as usize) & 0xFF] ^ (($keys[$keys_length - 4] >> 16) as u8);
        $output[ 0] = SBOX[ (wb0 >> 24) as usize        ] ^ (($keys[$keys_length - 4] >> 24) as u8);
    };
}

// Decrypt a block.
macro_rules! decryption_function {
     ($input:ident, $output:ident, $keys:ident, $inner_rounds:expr, $keys_length:expr) => {{
        // These `assert` improved performance.
        ::std::assert_eq!($input.len(), 128 / 8_usize);
        ::std::assert_eq!($keys.len(), $keys_length);
        let mut wa0: u32 = four_u8_to_u32!($input[ 0], $input[ 1], $input[ 2], $input[ 3]) ^
                           $keys[$keys_length - 4];
        let mut wa1: u32 = four_u8_to_u32!($input[ 4], $input[ 5], $input[ 6], $input[ 7]) ^
                           $keys[$keys_length - 3];
        let mut wa2: u32 = four_u8_to_u32!($input[ 8], $input[ 9], $input[10], $input[11]) ^
                           $keys[$keys_length - 2];
        let mut wa3: u32 = four_u8_to_u32!($input[12], $input[13], $input[14], $input[15]) ^
                           $keys[$keys_length - 1];
        // round 1
        let mut wb0: u32 = TD0[ (wa0 >> 24) as usize        ] ^ TD1[((wa3 >> 16) as usize) & 0xFF] ^
                           TD2[((wa2 >>  8) as usize) & 0xFF] ^ TD3[( wa1        as usize) & 0xFF] ^
                           $keys[$keys_length - 8];
        let mut wb1: u32 = TD0[ (wa1 >> 24) as usize        ] ^ TD1[((wa0 >> 16) as usize) & 0xFF] ^
                           TD2[((wa3 >>  8) as usize) & 0xFF] ^ TD3[( wa2        as usize) & 0xFF] ^
                           $keys[$keys_length - 7];
        let mut wb2: u32 = TD0[ (wa2 >> 24) as usize        ] ^ TD1[((wa1 >> 16) as usize) & 0xFF] ^
                           TD2[((wa0 >>  8) as usize) & 0xFF] ^ TD3[( wa3        as usize) & 0xFF] ^
                           $keys[$keys_length - 6];
        let mut wb3: u32 = TD0[ (wa3 >> 24) as usize        ] ^ TD1[((wa2 >> 16) as usize) & 0xFF] ^
                           TD2[((wa1 >>  8) as usize) & 0xFF] ^ TD3[( wa0        as usize) & 0xFF] ^
                           $keys[$keys_length - 5];
        // round 2 to round 9 (or 11, 13)
        for i in 1..$inner_rounds {
            // even-number rounds
            wa0 = TD0[ (wb0 >> 24) as usize        ] ^ TD1[((wb3 >> 16) as usize) & 0xFF] ^
                  TD2[((wb2 >>  8) as usize) & 0xFF] ^ TD3[( wb1        as usize) & 0xFF] ^
                  $keys[$keys_length - 4 - (8 * i)];
            wa1 = TD0[ (wb1 >> 24) as usize        ] ^ TD1[((wb0 >> 16) as usize) & 0xFF] ^
                  TD2[((wb3 >>  8) as usize) & 0xFF] ^ TD3[( wb2        as usize) & 0xFF] ^
                  $keys[$keys_length - 3 - (8 * i)];
            wa2 = TD0[ (wb2 >> 24) as usize        ] ^ TD1[((wb1 >> 16) as usize) & 0xFF] ^
                  TD2[((wb0 >>  8) as usize) & 0xFF] ^ TD3[( wb3        as usize) & 0xFF] ^
                  $keys[$keys_length - 2 - (8 * i)];
            wa3 = TD0[ (wb3 >> 24) as usize        ] ^ TD1[((wb2 >> 16) as usize) & 0xFF] ^
                  TD2[((wb1 >>  8) as usize) & 0xFF] ^ TD3[( wb0        as usize) & 0xFF] ^
                  $keys[$keys_length - 1 - (8 * i)];
           // odd-number rounds
            wb0 = TD0[ (wa0 >> 24) as usize        ] ^ TD1[((wa3 >> 16) as usize) & 0xFF] ^
                  TD2[((wa2 >>  8) as usize) & 0xFF] ^ TD3[( wa1        as usize) & 0xFF] ^
                  $keys[$keys_length - 8 - (8 * i)];
            wb1 = TD0[ (wa1 >> 24) as usize        ] ^ TD1[((wa0 >> 16) as usize) & 0xFF] ^
                  TD2[((wa3 >>  8) as usize) & 0xFF] ^ TD3[( wa2        as usize) & 0xFF] ^
                  $keys[$keys_length - 7 - (8 * i)];
            wb2 = TD0[ (wa2 >> 24) as usize        ] ^ TD1[((wa1 >> 16) as usize) & 0xFF] ^
                  TD2[((wa0 >>  8) as usize) & 0xFF] ^ TD3[( wa3        as usize) & 0xFF] ^
                  $keys[$keys_length - 6 - (8 * i)];
            wb3 = TD0[ (wa3 >> 24) as usize        ] ^ TD1[((wa2 >> 16) as usize) & 0xFF] ^
                  TD2[((wa1 >>  8) as usize) & 0xFF] ^ TD3[( wa0        as usize) & 0xFF] ^
                  $keys[$keys_length - 5 - (8 * i)];
        }
        // final round
        // accessing array elements by index in reverse order is faster than in normal order
        $output[15] = SINV[( wb0        as usize) & 0xFF] ^ ( $keys[3]        as u8);
        $output[14] = SINV[((wb1 >>  8) as usize) & 0xFF] ^ (($keys[3] >>  8) as u8);
        $output[13] = SINV[((wb2 >> 16) as usize) & 0xFF] ^ (($keys[3] >> 16) as u8);
        $output[12] = SINV[ (wb3 >> 24) as usize        ] ^ (($keys[3] >> 24) as u8);
        $output[11] = SINV[( wb3        as usize) & 0xFF] ^ ( $keys[2]        as u8);
        $output[10] = SINV[((wb0 >>  8) as usize) & 0xFF] ^ (($keys[2] >>  8) as u8);
        $output[ 9] = SINV[((wb1 >> 16) as usize) & 0xFF] ^ (($keys[2] >> 16) as u8);
        $output[ 8] = SINV[ (wb2 >> 24) as usize        ] ^ (($keys[2] >> 24) as u8);
        $output[ 7] = SINV[( wb2        as usize) & 0xFF] ^ ( $keys[1]        as u8);
        $output[ 6] = SINV[((wb3 >>  8) as usize) & 0xFF] ^ (($keys[1] >>  8) as u8);
        $output[ 5] = SINV[((wb0 >> 16) as usize) & 0xFF] ^ (($keys[1] >> 16) as u8);
        $output[ 4] = SINV[ (wb1 >> 24) as usize        ] ^ (($keys[1] >> 24) as u8);
        $output[ 3] = SINV[( wb1        as usize) & 0xFF] ^ ( $keys[0]        as u8);
        $output[ 2] = SINV[((wb2 >>  8) as usize) & 0xFF] ^ (($keys[0] >>  8) as u8);
        $output[ 1] = SINV[((wb3 >> 16) as usize) & 0xFF] ^ (($keys[0] >> 16) as u8);
        $output[ 0] = SINV[ (wb0 >> 24) as usize        ] ^ (($keys[0] >> 24) as u8);
    }};
}

/// Schedule a key to sub-keys for **encryption** with **auto-selected** key-size.
/// * *parameter* `origin`: the slice that contains original key.
/// * *parameter* `buffer`: the buffer to store the sub-keys.
///
/// The parameters must possess elements of the following amounts:
///
/// key-size | `origin` | `buffer`
/// - | - | -
/// 128bit | 16 | 44
/// 192bit | 24 | 52
/// 256bit | 32 | 60
///
/// This function is an alternative to [`key_schedule_encrypt128`], [`key_schedule_encrypt192`] and
/// [`key_schedule_encrypt256`] functions. Which one to use is up to you.
/// # Examples
/// Please refer to [`key_schedule_encrypt128`], [`key_schedule_encrypt192`] and
/// [`key_schedule_encrypt256`] functions, they are very similar.
///
/// [`key_schedule_encrypt128`]: ../aes_core/fn.key_schedule_encrypt128.html
/// [`key_schedule_encrypt192`]: ../aes_core/fn.key_schedule_encrypt192.html
/// [`key_schedule_encrypt256`]: ../aes_core/fn.key_schedule_encrypt256.html
pub fn key_schedule_encrypt_auto(origin: &[u8], buffer: &mut [u32]) {
    match origin.len() {
        16 => key_schedule_128_function!(origin, buffer),
        24 => key_schedule_192_function!(origin, buffer),
        32 => key_schedule_256_function!(origin, buffer),
        _ => panic!("Invalid key length."),
    }
}

/// Schedule a **128bit key** to sub-keys for **encryption**.
///
/// * *parameter* `origin`: the slice (length = 16) that contains original key.
/// * *parameter* `buffer`: the buffer (length = 44) to store the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::key_schedule_encrypt128;
/// const N_SUBKEYS_128BIT: usize = 44;
///
/// let origin_key: [u8; 16] = [
///     0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
///     0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
///
/// key_schedule_encrypt128(&origin_key, &mut subkeys);
///
/// let expected: [u32; N_SUBKEYS_128BIT] = [
///     0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,
///     0xA0FAFE17, 0x88542CB1, 0x23A33939, 0x2A6C7605,
///     0xF2C295F2, 0x7A96B943, 0x5935807A, 0x7359F67F,
///     0x3D80477D, 0x4716FE3E, 0x1E237E44, 0x6D7A883B,
///     0xEF44A541, 0xA8525B7F, 0xB671253B, 0xDB0BAD00,
///     0xD4D1C6F8, 0x7C839D87, 0xCAF2B8BC, 0x11F915BC,
///     0x6D88A37A, 0x110B3EFD, 0xDBF98641, 0xCA0093FD,
///     0x4E54F70E, 0x5F5FC9F3, 0x84A64FB2, 0x4EA6DC4F,
///     0xEAD27321, 0xB58DBAD2, 0x312BF560, 0x7F8D292F,
///     0xAC7766F3, 0x19FADC21, 0x28D12941, 0x575C006E,
///     0xD014F9A8, 0xC9EE2589, 0xE13F0CC8, 0xB6630CA6
/// ];
/// for i in 0..N_SUBKEYS_128BIT {
///     assert_eq!(subkeys[i], expected[i]);
/// }
/// ```
pub fn key_schedule_encrypt128(origin: &[u8], buffer: &mut [u32]) {
    assert_eq!(origin.len(), 128 / 8_usize);
    key_schedule_128_function!(origin, buffer);
}

/// Schedule a **192bit key** to sub-keys for **encryption**.
///
/// * *parameter* `origin`: the slice (length = 24) that contains original key.
/// * *parameter* `buffer`: the buffer (length = 52) to store the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::key_schedule_encrypt192;
/// const N_SUBKEYS_192BIT: usize = 52;
///
/// let origin_key: [u8; 24] = [
///     0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
///     0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
///     0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
///
/// key_schedule_encrypt192(&origin_key, &mut subkeys);
///
/// let expected: [u32; N_SUBKEYS_192BIT] = [
///     0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5,
///     0x62F8EAD2, 0x522C6B7B, 0xFE0C91F7, 0x2402F5A5,
///     0xEC12068E, 0x6C827F6B, 0x0E7A95B9, 0x5C56FEC2,
///     0x4DB7B4BD, 0x69B54118, 0x85A74796, 0xE92538FD,
///     0xE75FAD44, 0xBB095386, 0x485AF057, 0x21EFB14F,
///     0xA448F6D9, 0x4D6DCE24, 0xAA326360, 0x113B30E6,
///     0xA25E7ED5, 0x83B1CF9A, 0x27F93943, 0x6A94F767,
///     0xC0A69407, 0xD19DA4E1, 0xEC1786EB, 0x6FA64971,
///     0x485F7032, 0x22CB8755, 0xE26D1352, 0x33F0B7B3,
///     0x40BEEB28, 0x2F18A259, 0x6747D26B, 0x458C553E,
///     0xA7E1466C, 0x9411F1DF, 0x821F750A, 0xAD07D753,
///     0xCA400538, 0x8FCC5006, 0x282D166A, 0xBC3CE7B5,
///     0xE98BA06F, 0x448C773C, 0x8ECC7204, 0x01002202
/// ];
/// for i in 0..N_SUBKEYS_192BIT {
///     assert_eq!(subkeys[i], expected[i]);
/// }
/// ```
pub fn key_schedule_encrypt192(origin: &[u8], buffer: &mut [u32]) {
    assert_eq!(origin.len(), 192 / 8_usize);
    key_schedule_192_function!(origin, buffer);
}

/// Schedule a **256bit key** to sub-keys for **encryption**.
///
/// * *parameter* `origin`: the slice (length = 32) that contains original key.
/// * *parameter* `buffer`: the buffer (length = 60) to store the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::key_schedule_encrypt256;
/// const N_SUBKEYS_256BIT: usize = 60;
///
/// let origin_key: [u8; 32] = [
///     0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
///     0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
///     0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
///     0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
///
/// key_schedule_encrypt256(&origin_key, &mut subkeys);
///
/// let expected: [u32; N_SUBKEYS_256BIT] = [
///     0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
///     0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4,
///     0x9BA35411, 0x8E6925AF, 0xA51A8B5F, 0x2067FCDE,
///     0xA8B09C1A, 0x93D194CD, 0xBE49846E, 0xB75D5B9A,
///     0xD59AECB8, 0x5BF3C917, 0xFEE94248, 0xDE8EBE96,
///     0xB5A9328A, 0x2678A647, 0x98312229, 0x2F6C79B3,
///     0x812C81AD, 0xDADF48BA, 0x24360AF2, 0xFAB8B464,
///     0x98C5BFC9, 0xBEBD198E, 0x268C3BA7, 0x09E04214,
///     0x68007BAC, 0xB2DF3316, 0x96E939E4, 0x6C518D80,
///     0xC814E204, 0x76A9FB8A, 0x5025C02D, 0x59C58239,
///     0xDE136967, 0x6CCC5A71, 0xFA256395, 0x9674EE15,
///     0x5886CA5D, 0x2E2F31D7, 0x7E0AF1FA, 0x27CF73C3,
///     0x749C47AB, 0x18501DDA, 0xE2757E4F, 0x7401905A,
///     0xCAFAAAE3, 0xE4D59B34, 0x9ADF6ACE, 0xBD10190D,
///     0xFE4890D1, 0xE6188D0B, 0x046DF344, 0x706C631E
/// ];
/// for i in 0..N_SUBKEYS_256BIT {
///     assert_eq!(subkeys[i], expected[i]);
/// }
/// ```
pub fn key_schedule_encrypt256(origin: &[u8], buffer: &mut [u32]) {
    assert_eq!(origin.len(), 256 / 8_usize);
    key_schedule_256_function!(origin, buffer);
}

/// Schedule a key to sub-keys for **decryption** with **auto-selected** key-size.
/// * *parameter* `origin`: the slice that contains original key.
/// * *parameter* `buffer`: the buffer to store the sub-keys.
///
/// The parameters must possess elements of the following amounts:
///
/// key-size | `origin` | `buffer`
/// - | - | -
/// 128bit | 16 | 44
/// 192bit | 24 | 52
/// 256bit | 32 | 60
///
/// This function is an alternative to [`key_schedule_decrypt128`], [`key_schedule_decrypt192`] and
/// [`key_schedule_decrypt256`] functions. Which one to use is up to you.
/// # Examples
/// Please refer to [`key_schedule_decrypt128`], [`key_schedule_decrypt192`] and
/// [`key_schedule_decrypt256`] functions, they are very similar.
///
/// [`key_schedule_decrypt128`]: ../aes_core/fn.key_schedule_decrypt128.html
/// [`key_schedule_decrypt192`]: ../aes_core/fn.key_schedule_decrypt192.html
/// [`key_schedule_decrypt256`]: ../aes_core/fn.key_schedule_decrypt256.html
pub fn key_schedule_decrypt_auto(origin: &[u8], buffer: &mut [u32]) {
    match origin.len() {
        16 => {
            key_schedule_128_function!(origin, buffer);
            dkey_mixcolumn!(buffer, N_SUBKEYS_128BIT);
        }
        24 => {
            key_schedule_192_function!(origin, buffer);
            dkey_mixcolumn!(buffer, N_SUBKEYS_192BIT);
        }
        32 => {
            key_schedule_256_function!(origin, buffer);
            dkey_mixcolumn!(buffer, N_SUBKEYS_256BIT);
        }
        _ => panic!("Invalid key length."),
    }
}

/// Schedule a **128bit key** to sub-keys for **decryption**.
///
/// * *parameter* `origin`: the slice (length = 16) that contains original key.
/// * *parameter* `buffer`: the buffer (length = 44) to store the sub-keys.
/// # Examples
/// Please refer to [`key_schedule_encrypt128`] function, they are very similar.
///
/// [`key_schedule_encrypt128`]: ../aes_core/fn.key_schedule_encrypt128.html
pub fn key_schedule_decrypt128(origin: &[u8], buffer: &mut [u32]) {
    assert_eq!(origin.len(), 128 / 8_usize);
    key_schedule_128_function!(origin, buffer);
    dkey_mixcolumn!(buffer, N_SUBKEYS_128BIT);
}

/// Schedule a **192bit key** to sub-keys for **decryption**.
///
/// * *parameter* `origin`: the slice (length = 24) that contains original key.
/// * *parameter* `buffer`: the buffer (length = 52) to store the sub-keys.
/// # Examples
/// Please refer to [`key_schedule_encrypt192`] function, they are very similar
///
/// [`key_schedule_encrypt192`]: ../aes_core/fn.key_schedule_encrypt192.html
pub fn key_schedule_decrypt192(origin: &[u8], buffer: &mut [u32]) {
    assert_eq!(origin.len(), 192 / 8_usize);
    key_schedule_192_function!(origin, buffer);
    dkey_mixcolumn!(buffer, N_SUBKEYS_192BIT);
}

/// Schedule a **256bit key** to sub-keys for **decryption**.
///
/// * *parameter* `origin`: the slice (length = 32) that contains original key.
/// * *parameter* `buffer`: the buffer (length = 60) to store the sub-keys.
/// # Examples
/// Please refer to [`key_schedule_encrypt256`] function, they are very similar
///
/// [`key_schedule_encrypt256`]: ../aes_core/fn.key_schedule_encrypt256.html
pub fn key_schedule_decrypt256(origin: &[u8], buffer: &mut [u32]) {
    assert_eq!(origin.len(), 256 / 8_usize);
    key_schedule_256_function!(origin, buffer);
    dkey_mixcolumn!(buffer, N_SUBKEYS_256BIT);
}

/// **Encrypt** a block with scheduled keys (from **128bit key**) in place.
///
/// Encrypt the data in `block` and write it back there, using the `subkeys`.
///
/// * *parameter* `block`: the slice (length = 16) that stores a block of data.
/// * *parameter* `subkeys`: the slice (length = 44) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_encrypt128, block_encrypt128_inplace};
/// const N_SUBKEYS_128BIT: usize = 44;
///
/// let mut data_buffer: [u8; 16] = [
///     0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
///     0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
/// ];
/// let origin_key: [u8; 16] = [
///     0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
///     0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
///
/// key_schedule_encrypt128(&origin_key, &mut subkeys);
/// block_encrypt128_inplace(&mut data_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
///     0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32
/// ];
/// for i in 0..16 {
///     assert_eq!(data_buffer[i], expected[i]);
/// }
/// ```
pub fn block_encrypt128_inplace(block: &mut [u8], subkeys: &[u32]) {
    encryption_function!(block, block, subkeys, 5, N_SUBKEYS_128BIT);
}

/// **Encrypt** a block with scheduled keys (from **192bit key**) in place.
///
/// Encrypt the data in `block` and write it back there, using the `subkeys`.
///
/// * *parameter* `block`: the slice (length = 16) that stores a block of data.
/// * *parameter* `subkeys`: the slice (length = 52) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_encrypt192, block_encrypt192_inplace};
/// const N_SUBKEYS_192BIT: usize = 52;
///
/// let mut data_buffer: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// let origin_key: [u8; 24] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
///
/// key_schedule_encrypt192(&origin_key, &mut subkeys);
/// block_encrypt192_inplace(&mut data_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
///     0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91
/// ];
/// for i in 0..16 {
///     assert_eq!(data_buffer[i], expected[i]);
/// }
/// ```
pub fn block_encrypt192_inplace(block: &mut [u8], subkeys: &[u32]) {
    encryption_function!(block, block, subkeys, 6, N_SUBKEYS_192BIT);
}

/// **Encrypt** a block with scheduled keys (from **256bit key**) in place.
///
/// Encrypt the data in `block` and write it back there, using the `subkeys`.
///
/// * *parameter* `block`: the slice (length = 16) that stores a block of data.
/// * *parameter* `subkeys`: the slice (length = 60) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_encrypt256, block_encrypt256_inplace};
/// const N_SUBKEYS_256BIT: usize = 60;
///
/// let mut data_buffer: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// let origin_key: [u8; 32] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
///
/// key_schedule_encrypt256(&origin_key, &mut subkeys);
/// block_encrypt256_inplace(&mut data_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
///     0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89
/// ];
/// for i in 0..16 {
///     assert_eq!(data_buffer[i], expected[i]);
/// }
/// ```
pub fn block_encrypt256_inplace(block: &mut [u8], subkeys: &[u32]) {
    encryption_function!(block, block, subkeys, 7, N_SUBKEYS_256BIT);
}

/// **Decrypt** a block with scheduled keys (from **128bit key**) in place.
///
/// Decrypt the data in `block` and write it back there, using the `subkeys`.
///
/// * *parameter* `block`: the slice (length = 16) that stores a block of data.
/// * *parameter* `subkeys`: the slice (length = 44) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_decrypt128, block_decrypt128_inplace};
/// const N_SUBKEYS_128BIT: usize = 44;
///
/// let mut data_buffer: [u8; 16] = [
///     0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
///     0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32
/// ];
/// let origin_key: [u8; 16] = [
///     0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
///     0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
///
/// key_schedule_decrypt128(&origin_key, &mut subkeys);
/// block_decrypt128_inplace(&mut data_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
///     0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
/// ];
/// for i in 0..16 {
///     assert_eq!(data_buffer[i], expected[i]);
/// }
/// ```
pub fn block_decrypt128_inplace(block: &mut [u8], subkeys: &[u32]) {
    decryption_function!(block, block, subkeys, 5, N_SUBKEYS_128BIT);
}

/// **Decrypt** a block with scheduled keys (from **192bit key**) in place.
///
/// Decrypt the data in `block` and write it back there, using the `subkeys`.
///
/// * *parameter* `block`: the slice (length = 16) that stores a block of data.
/// * *parameter* `subkeys`: the slice (length = 52) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_decrypt192, block_decrypt192_inplace};
/// const N_SUBKEYS_192BIT: usize = 52;
///
/// let mut data_buffer: [u8; 16] = [
///     0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
///     0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91
/// ];
/// let origin_key: [u8; 24] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
///
/// key_schedule_decrypt192(&origin_key, &mut subkeys);
/// block_decrypt192_inplace(&mut data_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// for i in 0..16 {
///     assert_eq!(data_buffer[i], expected[i]);
/// }
/// ```
pub fn block_decrypt192_inplace(block: &mut [u8], subkeys: &[u32]) {
    decryption_function!(block, block, subkeys, 6, N_SUBKEYS_192BIT);
}

/// **Decrypt** a block with scheduled keys (from **256bit key**) in place.
///
/// Decrypt the data in `block` and write it back there, using the `subkeys`.
///
/// * *parameter* `block`: the slice (length = 16) that stores a block of data.
/// * *parameter* `subkeys`: the slice (length = 60) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_decrypt256, block_decrypt256_inplace};
/// const N_SUBKEYS_256BIT: usize = 60;
///
/// let mut data_buffer: [u8; 16] = [
///     0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
///     0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89
/// ];
/// let origin_key: [u8; 32] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
///
/// key_schedule_decrypt256(&origin_key, &mut subkeys);
/// block_decrypt256_inplace(&mut data_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// for i in 0..16 {
///     assert_eq!(data_buffer[i], expected[i]);
/// }
/// ```
pub fn block_decrypt256_inplace(block: &mut [u8], subkeys: &[u32]) {
    decryption_function!(block, block, subkeys, 7, N_SUBKEYS_256BIT);
}

/// **Encrypt** a block with scheduled keys (from **128bit key**).
///
/// Encrypt the data in `input` and write it to `output`, using the `subkeys`.
///
/// * *parameter* `input`: the slice (length = 16) that stores a block of input data.
/// * *parameter* `output`: the buffer (length = 16) to store the output data.
/// * *parameter* `subkeys`: the slice (length = 44) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_encrypt128, block_encrypt128};
/// const N_SUBKEYS_128BIT: usize = 44;
///
/// let input_data: [u8; 16] = [
///     0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
///     0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
/// ];
/// let mut output_buffer: [u8; 16] = [0; 16];
///
/// let origin_key: [u8; 16] = [
///     0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
///     0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
///
/// key_schedule_encrypt128(&origin_key, &mut subkeys);
/// block_encrypt128(&input_data,&mut output_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
///     0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32
/// ];
/// for i in 0..16 {
///     assert_eq!(output_buffer[i], expected[i]);
/// }
/// ```
pub fn block_encrypt128(input: &[u8], output: &mut [u8], subkeys: &[u32]) {
    encryption_function!(input, output, subkeys, 5, N_SUBKEYS_128BIT);
}

/// **Encrypt** a block with scheduled keys (from **192bit key**).
///
/// Encrypt the data in `input` and write it to `output`, using the `subkeys`.
///
/// * *parameter* `input`: the slice (length = 16) that stores a block of input data.
/// * *parameter* `output`: the buffer (length = 16) to store the output data.
/// * *parameter* `subkeys`: the slice (length = 52) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_encrypt192, block_encrypt192};
/// const N_SUBKEYS_192BIT: usize = 52;
///
/// let input_data: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// let mut output_buffer: [u8; 16] = [0; 16];
///
/// let origin_key: [u8; 24] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
///
/// key_schedule_encrypt192(&origin_key, &mut subkeys);
/// block_encrypt192(&input_data, &mut output_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
///     0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91
/// ];
/// for i in 0..16 {
///     assert_eq!(output_buffer[i], expected[i]);
/// }
/// ```
pub fn block_encrypt192(input: &[u8], output: &mut [u8], subkeys: &[u32]) {
    encryption_function!(input, output, subkeys, 6, N_SUBKEYS_192BIT);
}

/// **Encrypt** a block with scheduled keys (from **256bit key**).
///
/// Encrypt the data in `input` and write it to `output`, using the `subkeys`.
///
/// * *parameter* `input`: the slice (length = 16) that stores a block of input data.
/// * *parameter* `output`: the buffer (length = 16) to store the output data.
/// * *parameter* `subkeys`: the slice (length = 60) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_encrypt256, block_encrypt256};
/// const N_SUBKEYS_256BIT: usize = 60;
///
/// let input_data: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// let mut output_buffer: [u8; 16] = [0; 16];
///
/// let origin_key: [u8; 32] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
///
/// key_schedule_encrypt256(&origin_key, &mut subkeys);
/// block_encrypt256(&input_data, &mut output_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
///     0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89
/// ];
/// for i in 0..16 {
///     assert_eq!(output_buffer[i], expected[i]);
/// }
/// ```
pub fn block_encrypt256(input: &[u8], output: &mut [u8], subkeys: &[u32]) {
    encryption_function!(input, output, subkeys, 7, N_SUBKEYS_256BIT);
}

/// **Decrypt** a block with scheduled keys (from **128bit key**).
///
/// Decrypt the data in `input` and write it to `output`, using the `subkeys`.
///
/// * *parameter* `input`: the slice (length = 16) that stores a block of input data.
/// * *parameter* `output`: the buffer (length = 16) to store the output data.
/// * *parameter* `subkeys`: the slice (length = 44) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_decrypt128, block_decrypt128};
/// const N_SUBKEYS_128BIT: usize = 44;
///
/// let input_data: [u8; 16] = [
///     0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
///     0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32
/// ];
/// let mut output_buffer: [u8; 16] = [0; 16];
///
/// let origin_key: [u8; 16] = [
///     0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
///     0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
///
/// key_schedule_decrypt128(&origin_key, &mut subkeys);
/// block_decrypt128(&input_data, &mut output_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
///     0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
/// ];
/// for i in 0..16 {
///     assert_eq!(output_buffer[i], expected[i]);
/// }
/// ```
pub fn block_decrypt128(input: &[u8], output: &mut [u8], subkeys: &[u32]) {
    decryption_function!(input, output, subkeys, 5, N_SUBKEYS_128BIT);
}

/// **Decrypt** a block with scheduled keys (from **192bit key**).
///
/// Decrypt the data in `input` and write it to `output`, using the `subkeys`.
///
/// * *parameter* `input`: the slice (length = 16) that stores a block of input data.
/// * *parameter* `output`: the buffer (length = 16) to store the output data.
/// * *parameter* `subkeys`: the slice (length = 52) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_decrypt192, block_decrypt192};
/// const N_SUBKEYS_192BIT: usize = 52;
///
/// let input_data: [u8; 16] = [
///     0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
///     0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91
/// ];
/// let mut output_buffer: [u8; 16] = [0; 16];
///
/// let origin_key: [u8; 24] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
///
/// key_schedule_decrypt192(&origin_key, &mut subkeys);
/// block_decrypt192(&input_data, &mut output_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// for i in 0..16 {
///     assert_eq!(output_buffer[i], expected[i]);
/// }
/// ```
pub fn block_decrypt192(input: &[u8], output: &mut [u8], subkeys: &[u32]) {
    decryption_function!(input, output, subkeys, 6, N_SUBKEYS_192BIT);
}

/// **Decrypt** a block with scheduled keys (from **256bit key**).
///
/// Decrypt the data in `input` and write it to `output`, using the `subkeys`.
///
/// * *parameter* `input`: the slice (length = 16) that stores a block of input data.
/// * *parameter* `output`: the buffer (length = 16) to store the output data.
/// * *parameter* `subkeys`: the slice (length = 60) that contains the sub-keys.
/// # Examples
/// ```
/// use aes_frast::aes_core::{key_schedule_decrypt256, block_decrypt256};
/// const N_SUBKEYS_256BIT: usize = 60;
///
/// let input_data: [u8; 16] = [
///     0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
///     0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89
/// ];
/// let mut output_buffer: [u8; 16] = [0; 16];
///
/// let origin_key: [u8; 32] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
/// ];
/// let mut subkeys: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
///
/// key_schedule_decrypt256(&origin_key, &mut subkeys);
/// block_decrypt256(&input_data, &mut output_buffer, &subkeys);
///
/// let expected: [u8; 16] = [
///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
/// ];
/// for i in 0..16 {
///     assert_eq!(output_buffer[i], expected[i]);
/// }
/// ```
pub fn block_decrypt256(input: &[u8], output: &mut [u8], subkeys: &[u32]) {
    decryption_function!(input, output, subkeys, 7, N_SUBKEYS_256BIT);
}

#[cfg(test)]
mod tests {
    use super::{*};

    #[test]
    fn key_schedule_decrypt128_works() {
        let origin_key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        ];
        let mut subkeys: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
        key_schedule_decrypt128(&origin_key, &mut subkeys);
        let expected: [u32; N_SUBKEYS_128BIT] = [
            0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C,
            0x2B3708A7, 0xF262D405, 0xBC3EBDBF, 0x4B617D62,
            0xCC7505EB, 0x3E17D1EE, 0x82296C51, 0xC9481133,
            0x7C1F13F7, 0x4208C219, 0xC021AE48, 0x0969BF7B,
            0x90884413, 0xD280860A, 0x12A12842, 0x1BC89739,
            0x6EA30AFC, 0xBC238CF6, 0xAE82A4B4, 0xB54A338D,
            0x6EFCD876, 0xD2DF5480, 0x7C5DF034, 0xC917C3B9,
            0x12C07647, 0xC01F22C7, 0xBC42D2F3, 0x7555114A,
            0xDF7D925A, 0x1F62B09D, 0xA320626E, 0xD6757324,
            0x0C7B5A63, 0x1319EAFE, 0xB0398890, 0x664CFBB4,
            0xD014F9A8, 0xC9EE2589, 0xE13F0CC8, 0xB6630CA6
        ];
        for i in 0..N_SUBKEYS_128BIT {
            assert_eq!(subkeys[i], expected[i]);
        }
    }

    #[test]
    fn key_schedule_decrypt192_works() {
        let origin_key: [u8; 24] = [
            0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
            0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
            0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
        ];
        let mut subkeys: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
        key_schedule_decrypt192(&origin_key, &mut subkeys);
        let expected: [u32; N_SUBKEYS_192BIT] = [
            0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5,
            0x9EB149C4, 0x79D69C5D, 0xFEB4A27C, 0xEAB6D7FD,
            0x659763E7, 0x8C817087, 0x12303943, 0x6BE6A51E,
            0x41B34544, 0xAB0592B9, 0xCE92F15E, 0x421381D9,
            0x5023B89A, 0x3BC51D84, 0xD04B1937, 0x7B4E8B8E,
            0xB5DC7AD0, 0xF7CFFB09, 0xA7EC4393, 0x9C295E17,
            0xC5DDB7F8, 0xBE933C76, 0x0B4F46A6, 0xFC80BDAF,
            0x5B6CFE3C, 0xC745A02B, 0xF8B9A572, 0x462A9904,
            0x4D65DFA2, 0xB1E5620D, 0xEA899C31, 0x2DCC3C1A,
            0xF3B42258, 0xB59EBB5C, 0xF8FB64FE, 0x491E06F3,
            0xA3979AC2, 0x8E5BA6D8, 0xE12CC9E6, 0x54B272BA,
            0xAC491644, 0xE55710B7, 0x46C08A75, 0xC89B2CAD,
            0xE98BA06F, 0x448C773C, 0x8ECC7204, 0x01002202
        ];
        for i in 0..N_SUBKEYS_192BIT {
            assert_eq!(subkeys[i], expected[i]);
        }
    }

    #[test]
    fn key_schedule_decrypt256_works() {
        let origin_key: [u8; 32] = [
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        ];
        let mut subkeys: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
        key_schedule_decrypt256(&origin_key, &mut subkeys);
        let expected: [u32; N_SUBKEYS_256BIT] = [
            0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
            0x8EC6BFF6, 0x829CA03B, 0x9E49AF7E, 0xDBA96125,
            0x42107758, 0xE9EC98F0, 0x66329EA1, 0x93F8858B,
            0x4A7459F9, 0xC8E8F9C2, 0x56A156BC, 0x8D083799,
            0x6C3D6329, 0x85D1FBD9, 0xE3E36578, 0x701BE0F3,
            0x54FB808B, 0x9C137949, 0xCAB22FF5, 0x47BA186C,
            0x25BA3C22, 0xA06BC7FB, 0x4388A283, 0x33934270,
            0xD669A733, 0x4A7ADE7A, 0x80C8F18F, 0xC772E9E3,
            0xC440B289, 0x642B7572, 0x27A3D7F1, 0x14309581,
            0x32526C36, 0x7828B24C, 0xF8E043C3, 0x3F92AA20,
            0x34AD1E44, 0x50866B36, 0x7725BCC7, 0x63152946,
            0xB668B621, 0xCE40046D, 0x36A047AE, 0x0932ED8E,
            0x57C96CF6, 0x074F07C0, 0x706ABB07, 0x137F9241,
            0xADA23F49, 0x63E23B24, 0x55427C8A, 0x5C709104,
            0xFE4890D1, 0xE6188D0B, 0x046DF344, 0x706C631E
        ];
        for i in 0..N_SUBKEYS_256BIT {
            assert_eq!(subkeys[i], expected[i]);
        }
    }

    #[test]
    fn key_schedule_encrypt_auto_works() {
        let origin128: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        ];
        let mut scheduled128a: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
        let mut scheduled128b: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
        key_schedule_encrypt_auto(&origin128, &mut scheduled128a);
        key_schedule_encrypt128(&origin128, &mut scheduled128b);
        for i in 0..N_SUBKEYS_128BIT {
            assert_eq!(scheduled128a[i], scheduled128b[i]);
        }
        let origin192: [u8; 24] = [
            0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
            0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
            0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
        ];
        let mut scheduled192a: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
        let mut scheduled192b: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
        key_schedule_encrypt_auto(&origin192, &mut scheduled192a);
        key_schedule_encrypt192(&origin192, &mut scheduled192b);
        for i in 0..N_SUBKEYS_192BIT {
            assert_eq!(scheduled192a[i], scheduled192b[i]);
        }
        let origin256: [u8; 32] = [
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        ];
        let mut scheduled256a: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
        let mut scheduled256b: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
        key_schedule_encrypt_auto(&origin256, &mut scheduled256a);
        key_schedule_encrypt256(&origin256, &mut scheduled256b);
        for i in 0..N_SUBKEYS_256BIT {
            assert_eq!(scheduled256a[i], scheduled256b[i]);
        }
    }

    #[test]
    fn key_schedule_decrypt_auto_works() {
        let origin128: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        ];
        let mut scheduled128a: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
        let mut scheduled128b: [u32; N_SUBKEYS_128BIT] = [0; N_SUBKEYS_128BIT];
        key_schedule_decrypt_auto(&origin128, &mut scheduled128a);
        key_schedule_decrypt128(&origin128, &mut scheduled128b);
        for i in 0..N_SUBKEYS_128BIT {
            assert_eq!(scheduled128a[i], scheduled128b[i]);
        }
        let origin192: [u8; 24] = [
            0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
            0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
            0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
        ];
        let mut scheduled192a: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
        let mut scheduled192b: [u32; N_SUBKEYS_192BIT] = [0; N_SUBKEYS_192BIT];
        key_schedule_decrypt_auto(&origin192, &mut scheduled192a);
        key_schedule_decrypt192(&origin192, &mut scheduled192b);
        for i in 0..N_SUBKEYS_192BIT {
            assert_eq!(scheduled192a[i], scheduled192b[i]);
        }
        let origin256: [u8; 32] = [
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        ];
        let mut scheduled256a: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
        let mut scheduled256b: [u32; N_SUBKEYS_256BIT] = [0; N_SUBKEYS_256BIT];
        key_schedule_decrypt_auto(&origin256, &mut scheduled256a);
        key_schedule_decrypt256(&origin256, &mut scheduled256b);
        for i in 0..N_SUBKEYS_256BIT {
            assert_eq!(scheduled256a[i], scheduled256b[i]);
        }
    }
}
