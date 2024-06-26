//! Module contains items related to the [`State`] structure which allows to the direct MD5 state manipulation.
//!
//! # Example
//!
//! ```rust
//! use chksum_hash_sha2_384 as sha2_384;
//!
//! // Create new state
//! let mut state = sha2_384::state::default();
//!
//! // By default it returns initialization values
//! assert_eq!(
//!     state.digest(),
//!     [
//!         0xCBBB9D5DC1059ED8,
//!         0x629A292A367CD507,
//!         0x9159015A3070DD17,
//!         0x152FECD8F70E5939,
//!         0x67332667FFC00B31,
//!         0x8EB44A8768581511,
//!     ]
//! );
//!
//! // Manually create block of data with proper padding
//! let data = [
//!     u64::from_be_bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     # u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//!     // ...
//!     u64::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
//! ];
//!
//! // Update state and own new value
//! state = state.update(data);
//!
//! // Proper digest of empty input
//! assert_eq!(
//!     state.digest(),
//!     [
//!         0x38B060A751AC9638,
//!         0x4CD9327EB1B1E36A,
//!         0x21FDB71114BE0743,
//!         0x4C0CC7BF63F6E1DA,
//!         0x274EDEBFE76F65FB,
//!         0xD51AD2F14898B95B,
//!     ]
//! );
//!
//! // Reset state to initial values
//! state = state.reset();
//! assert_eq!(
//!     state.digest(),
//!     [
//!         0xCBBB9D5DC1059ED8,
//!         0x629A292A367CD507,
//!         0x9159015A3070DD17,
//!         0x152FECD8F70E5939,
//!         0x67332667FFC00B31,
//!         0x8EB44A8768581511,
//!     ]
//! );
//! ```
//!
//! # Warning
//!
//! The [`State`] structure does not modify internal state, each function returns a new state that must be used.

use crate::block::LENGTH_QWORDS as BLOCK_LENGTH_QWORDS;
use crate::digest::LENGTH_QWORDS as DIGEST_LENGTH_QWORDS;

#[allow(clippy::unreadable_literal)]
const H: [u64; 8] = [
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
];

#[allow(clippy::unreadable_literal)]
#[rustfmt::skip]
const K: [u64; 80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];

/// Create a new state.
#[must_use]
pub const fn new() -> State {
    State::new()
}

/// Creates a default state.
#[must_use]
pub fn default() -> State {
    State::default()
}

/// A low-level hash state.
///
/// Check [`state`](self) module for usage examples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct State {
    pub(crate) a: u64,
    pub(crate) b: u64,
    pub(crate) c: u64,
    pub(crate) d: u64,
    pub(crate) e: u64,
    pub(crate) f: u64,
    pub(crate) g: u64,
    pub(crate) h: u64,
}

impl State {
    /// Creates a new state.
    #[must_use]
    pub const fn new() -> Self {
        let [a, b, c, d, e, f, g, h] = H;
        Self { a, b, c, d, e, f, g, h }
    }

    /// Returns modified state with the passed data.
    ///
    /// **Warning!** Input block must be in the big-endian byte order.
    #[must_use]
    pub const fn update(&self, block: [u64; BLOCK_LENGTH_QWORDS]) -> Self {
        const fn small_sigma0(x: u64) -> u64 {
            x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
        }

        const fn small_sigma1(x: u64) -> u64 {
            x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
        }

        #[rustfmt::skip]
        let mut w = [
            block[0x0], block[0x1], block[0x2], block[0x3],
            block[0x4], block[0x5], block[0x6], block[0x7],
            block[0x8], block[0x9], block[0xA], block[0xB],
            block[0xC], block[0xD], block[0xE], block[0xF],
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
        ];
        w[0x10] = small_sigma1(w[0x0E])
            .wrapping_add(w[0x09])
            .wrapping_add(small_sigma0(w[0x01]))
            .wrapping_add(w[0x00]);
        w[0x11] = small_sigma1(w[0x0F])
            .wrapping_add(w[0x0A])
            .wrapping_add(small_sigma0(w[0x02]))
            .wrapping_add(w[0x01]);
        w[0x12] = small_sigma1(w[0x10])
            .wrapping_add(w[0x0B])
            .wrapping_add(small_sigma0(w[0x03]))
            .wrapping_add(w[0x02]);
        w[0x13] = small_sigma1(w[0x11])
            .wrapping_add(w[0x0C])
            .wrapping_add(small_sigma0(w[0x04]))
            .wrapping_add(w[0x03]);
        w[0x14] = small_sigma1(w[0x12])
            .wrapping_add(w[0x0D])
            .wrapping_add(small_sigma0(w[0x05]))
            .wrapping_add(w[0x04]);
        w[0x15] = small_sigma1(w[0x13])
            .wrapping_add(w[0x0E])
            .wrapping_add(small_sigma0(w[0x06]))
            .wrapping_add(w[0x05]);
        w[0x16] = small_sigma1(w[0x14])
            .wrapping_add(w[0x0F])
            .wrapping_add(small_sigma0(w[0x07]))
            .wrapping_add(w[0x06]);
        w[0x17] = small_sigma1(w[0x15])
            .wrapping_add(w[0x10])
            .wrapping_add(small_sigma0(w[0x08]))
            .wrapping_add(w[0x07]);
        w[0x18] = small_sigma1(w[0x16])
            .wrapping_add(w[0x11])
            .wrapping_add(small_sigma0(w[0x09]))
            .wrapping_add(w[0x08]);
        w[0x19] = small_sigma1(w[0x17])
            .wrapping_add(w[0x12])
            .wrapping_add(small_sigma0(w[0x0A]))
            .wrapping_add(w[0x09]);
        w[0x1A] = small_sigma1(w[0x18])
            .wrapping_add(w[0x13])
            .wrapping_add(small_sigma0(w[0x0B]))
            .wrapping_add(w[0x0A]);
        w[0x1B] = small_sigma1(w[0x19])
            .wrapping_add(w[0x14])
            .wrapping_add(small_sigma0(w[0x0C]))
            .wrapping_add(w[0x0B]);
        w[0x1C] = small_sigma1(w[0x1A])
            .wrapping_add(w[0x15])
            .wrapping_add(small_sigma0(w[0x0D]))
            .wrapping_add(w[0x0C]);
        w[0x1D] = small_sigma1(w[0x1B])
            .wrapping_add(w[0x16])
            .wrapping_add(small_sigma0(w[0x0E]))
            .wrapping_add(w[0x0D]);
        w[0x1E] = small_sigma1(w[0x1C])
            .wrapping_add(w[0x17])
            .wrapping_add(small_sigma0(w[0x0F]))
            .wrapping_add(w[0x0E]);
        w[0x1F] = small_sigma1(w[0x1D])
            .wrapping_add(w[0x18])
            .wrapping_add(small_sigma0(w[0x10]))
            .wrapping_add(w[0x0F]);
        w[0x20] = small_sigma1(w[0x1E])
            .wrapping_add(w[0x19])
            .wrapping_add(small_sigma0(w[0x11]))
            .wrapping_add(w[0x10]);
        w[0x21] = small_sigma1(w[0x1F])
            .wrapping_add(w[0x1A])
            .wrapping_add(small_sigma0(w[0x12]))
            .wrapping_add(w[0x11]);
        w[0x22] = small_sigma1(w[0x20])
            .wrapping_add(w[0x1B])
            .wrapping_add(small_sigma0(w[0x13]))
            .wrapping_add(w[0x12]);
        w[0x23] = small_sigma1(w[0x21])
            .wrapping_add(w[0x1C])
            .wrapping_add(small_sigma0(w[0x14]))
            .wrapping_add(w[0x13]);
        w[0x24] = small_sigma1(w[0x22])
            .wrapping_add(w[0x1D])
            .wrapping_add(small_sigma0(w[0x15]))
            .wrapping_add(w[0x14]);
        w[0x25] = small_sigma1(w[0x23])
            .wrapping_add(w[0x1E])
            .wrapping_add(small_sigma0(w[0x16]))
            .wrapping_add(w[0x15]);
        w[0x26] = small_sigma1(w[0x24])
            .wrapping_add(w[0x1F])
            .wrapping_add(small_sigma0(w[0x17]))
            .wrapping_add(w[0x16]);
        w[0x27] = small_sigma1(w[0x25])
            .wrapping_add(w[0x20])
            .wrapping_add(small_sigma0(w[0x18]))
            .wrapping_add(w[0x17]);
        w[0x28] = small_sigma1(w[0x26])
            .wrapping_add(w[0x21])
            .wrapping_add(small_sigma0(w[0x19]))
            .wrapping_add(w[0x18]);
        w[0x29] = small_sigma1(w[0x27])
            .wrapping_add(w[0x22])
            .wrapping_add(small_sigma0(w[0x1A]))
            .wrapping_add(w[0x19]);
        w[0x2A] = small_sigma1(w[0x28])
            .wrapping_add(w[0x23])
            .wrapping_add(small_sigma0(w[0x1B]))
            .wrapping_add(w[0x1A]);
        w[0x2B] = small_sigma1(w[0x29])
            .wrapping_add(w[0x24])
            .wrapping_add(small_sigma0(w[0x1C]))
            .wrapping_add(w[0x1B]);
        w[0x2C] = small_sigma1(w[0x2A])
            .wrapping_add(w[0x25])
            .wrapping_add(small_sigma0(w[0x1D]))
            .wrapping_add(w[0x1C]);
        w[0x2D] = small_sigma1(w[0x2B])
            .wrapping_add(w[0x26])
            .wrapping_add(small_sigma0(w[0x1E]))
            .wrapping_add(w[0x1D]);
        w[0x2E] = small_sigma1(w[0x2C])
            .wrapping_add(w[0x27])
            .wrapping_add(small_sigma0(w[0x1F]))
            .wrapping_add(w[0x1E]);
        w[0x2F] = small_sigma1(w[0x2D])
            .wrapping_add(w[0x28])
            .wrapping_add(small_sigma0(w[0x20]))
            .wrapping_add(w[0x1F]);
        w[0x30] = small_sigma1(w[0x2E])
            .wrapping_add(w[0x29])
            .wrapping_add(small_sigma0(w[0x21]))
            .wrapping_add(w[0x20]);
        w[0x31] = small_sigma1(w[0x2F])
            .wrapping_add(w[0x2A])
            .wrapping_add(small_sigma0(w[0x22]))
            .wrapping_add(w[0x21]);
        w[0x32] = small_sigma1(w[0x30])
            .wrapping_add(w[0x2B])
            .wrapping_add(small_sigma0(w[0x23]))
            .wrapping_add(w[0x22]);
        w[0x33] = small_sigma1(w[0x31])
            .wrapping_add(w[0x2C])
            .wrapping_add(small_sigma0(w[0x24]))
            .wrapping_add(w[0x23]);
        w[0x34] = small_sigma1(w[0x32])
            .wrapping_add(w[0x2D])
            .wrapping_add(small_sigma0(w[0x25]))
            .wrapping_add(w[0x24]);
        w[0x35] = small_sigma1(w[0x33])
            .wrapping_add(w[0x2E])
            .wrapping_add(small_sigma0(w[0x26]))
            .wrapping_add(w[0x25]);
        w[0x36] = small_sigma1(w[0x34])
            .wrapping_add(w[0x2F])
            .wrapping_add(small_sigma0(w[0x27]))
            .wrapping_add(w[0x26]);
        w[0x37] = small_sigma1(w[0x35])
            .wrapping_add(w[0x30])
            .wrapping_add(small_sigma0(w[0x28]))
            .wrapping_add(w[0x27]);
        w[0x38] = small_sigma1(w[0x36])
            .wrapping_add(w[0x31])
            .wrapping_add(small_sigma0(w[0x29]))
            .wrapping_add(w[0x28]);
        w[0x39] = small_sigma1(w[0x37])
            .wrapping_add(w[0x32])
            .wrapping_add(small_sigma0(w[0x2A]))
            .wrapping_add(w[0x29]);
        w[0x3A] = small_sigma1(w[0x38])
            .wrapping_add(w[0x33])
            .wrapping_add(small_sigma0(w[0x2B]))
            .wrapping_add(w[0x2A]);
        w[0x3B] = small_sigma1(w[0x39])
            .wrapping_add(w[0x34])
            .wrapping_add(small_sigma0(w[0x2C]))
            .wrapping_add(w[0x2B]);
        w[0x3C] = small_sigma1(w[0x3A])
            .wrapping_add(w[0x35])
            .wrapping_add(small_sigma0(w[0x2D]))
            .wrapping_add(w[0x2C]);
        w[0x3D] = small_sigma1(w[0x3B])
            .wrapping_add(w[0x36])
            .wrapping_add(small_sigma0(w[0x2E]))
            .wrapping_add(w[0x2D]);
        w[0x3E] = small_sigma1(w[0x3C])
            .wrapping_add(w[0x37])
            .wrapping_add(small_sigma0(w[0x2F]))
            .wrapping_add(w[0x2E]);
        w[0x3F] = small_sigma1(w[0x3D])
            .wrapping_add(w[0x38])
            .wrapping_add(small_sigma0(w[0x30]))
            .wrapping_add(w[0x2F]);
        w[0x40] = small_sigma1(w[0x3E])
            .wrapping_add(w[0x39])
            .wrapping_add(small_sigma0(w[0x31]))
            .wrapping_add(w[0x30]);
        w[0x41] = small_sigma1(w[0x3F])
            .wrapping_add(w[0x3A])
            .wrapping_add(small_sigma0(w[0x32]))
            .wrapping_add(w[0x31]);
        w[0x42] = small_sigma1(w[0x40])
            .wrapping_add(w[0x3B])
            .wrapping_add(small_sigma0(w[0x33]))
            .wrapping_add(w[0x32]);
        w[0x43] = small_sigma1(w[0x41])
            .wrapping_add(w[0x3C])
            .wrapping_add(small_sigma0(w[0x34]))
            .wrapping_add(w[0x33]);
        w[0x44] = small_sigma1(w[0x42])
            .wrapping_add(w[0x3D])
            .wrapping_add(small_sigma0(w[0x35]))
            .wrapping_add(w[0x34]);
        w[0x45] = small_sigma1(w[0x43])
            .wrapping_add(w[0x3E])
            .wrapping_add(small_sigma0(w[0x36]))
            .wrapping_add(w[0x35]);
        w[0x46] = small_sigma1(w[0x44])
            .wrapping_add(w[0x3F])
            .wrapping_add(small_sigma0(w[0x37]))
            .wrapping_add(w[0x36]);
        w[0x47] = small_sigma1(w[0x45])
            .wrapping_add(w[0x40])
            .wrapping_add(small_sigma0(w[0x38]))
            .wrapping_add(w[0x37]);
        w[0x48] = small_sigma1(w[0x46])
            .wrapping_add(w[0x41])
            .wrapping_add(small_sigma0(w[0x39]))
            .wrapping_add(w[0x38]);
        w[0x49] = small_sigma1(w[0x47])
            .wrapping_add(w[0x42])
            .wrapping_add(small_sigma0(w[0x3A]))
            .wrapping_add(w[0x39]);
        w[0x4A] = small_sigma1(w[0x48])
            .wrapping_add(w[0x43])
            .wrapping_add(small_sigma0(w[0x3B]))
            .wrapping_add(w[0x3A]);
        w[0x4B] = small_sigma1(w[0x49])
            .wrapping_add(w[0x44])
            .wrapping_add(small_sigma0(w[0x3C]))
            .wrapping_add(w[0x3B]);
        w[0x4C] = small_sigma1(w[0x4A])
            .wrapping_add(w[0x45])
            .wrapping_add(small_sigma0(w[0x3D]))
            .wrapping_add(w[0x3C]);
        w[0x4D] = small_sigma1(w[0x4B])
            .wrapping_add(w[0x46])
            .wrapping_add(small_sigma0(w[0x3E]))
            .wrapping_add(w[0x3D]);
        w[0x4E] = small_sigma1(w[0x4C])
            .wrapping_add(w[0x47])
            .wrapping_add(small_sigma0(w[0x3F]))
            .wrapping_add(w[0x3E]);
        w[0x4F] = small_sigma1(w[0x4D])
            .wrapping_add(w[0x48])
            .wrapping_add(small_sigma0(w[0x40]))
            .wrapping_add(w[0x3F]);

        let state = *self;

        const fn ch(x: u64, y: u64, z: u64) -> u64 {
            (x & y) ^ (!x & z)
        }

        const fn maj(x: u64, y: u64, z: u64) -> u64 {
            (x & y) ^ (x & z) ^ (y & z)
        }

        const fn capital_sigma0(x: u64) -> u64 {
            x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
        }

        const fn capital_sigma1(x: u64) -> u64 {
            x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
        }

        #[allow(clippy::too_many_arguments)]
        #[rustfmt::skip]
        const fn round(State { a, b, c, d, e, f, g, h }: State, w: u64, k: u64) -> State {
            let t1 = h.wrapping_add(capital_sigma1(e)).wrapping_add(ch(e, f, g)).wrapping_add(k).wrapping_add(w);
            let t2 = capital_sigma0(a).wrapping_add(maj(a, b, c));
            let h = g;
            let g = f;
            let f = e;
            let e = d.wrapping_add(t1);
            let d = c;
            let c = b;
            let b = a;
            let a = t1.wrapping_add(t2);
            State { a, b, c, d, e, f, g, h }
        }

        let state = round(state, w[0x00], K[0x00]);
        let state = round(state, w[0x01], K[0x01]);
        let state = round(state, w[0x02], K[0x02]);
        let state = round(state, w[0x03], K[0x03]);
        let state = round(state, w[0x04], K[0x04]);
        let state = round(state, w[0x05], K[0x05]);
        let state = round(state, w[0x06], K[0x06]);
        let state = round(state, w[0x07], K[0x07]);
        let state = round(state, w[0x08], K[0x08]);
        let state = round(state, w[0x09], K[0x09]);
        let state = round(state, w[0x0A], K[0x0A]);
        let state = round(state, w[0x0B], K[0x0B]);
        let state = round(state, w[0x0C], K[0x0C]);
        let state = round(state, w[0x0D], K[0x0D]);
        let state = round(state, w[0x0E], K[0x0E]);
        let state = round(state, w[0x0F], K[0x0F]);
        let state = round(state, w[0x10], K[0x10]);
        let state = round(state, w[0x11], K[0x11]);
        let state = round(state, w[0x12], K[0x12]);
        let state = round(state, w[0x13], K[0x13]);
        let state = round(state, w[0x14], K[0x14]);
        let state = round(state, w[0x15], K[0x15]);
        let state = round(state, w[0x16], K[0x16]);
        let state = round(state, w[0x17], K[0x17]);
        let state = round(state, w[0x18], K[0x18]);
        let state = round(state, w[0x19], K[0x19]);
        let state = round(state, w[0x1A], K[0x1A]);
        let state = round(state, w[0x1B], K[0x1B]);
        let state = round(state, w[0x1C], K[0x1C]);
        let state = round(state, w[0x1D], K[0x1D]);
        let state = round(state, w[0x1E], K[0x1E]);
        let state = round(state, w[0x1F], K[0x1F]);
        let state = round(state, w[0x20], K[0x20]);
        let state = round(state, w[0x21], K[0x21]);
        let state = round(state, w[0x22], K[0x22]);
        let state = round(state, w[0x23], K[0x23]);
        let state = round(state, w[0x24], K[0x24]);
        let state = round(state, w[0x25], K[0x25]);
        let state = round(state, w[0x26], K[0x26]);
        let state = round(state, w[0x27], K[0x27]);
        let state = round(state, w[0x28], K[0x28]);
        let state = round(state, w[0x29], K[0x29]);
        let state = round(state, w[0x2A], K[0x2A]);
        let state = round(state, w[0x2B], K[0x2B]);
        let state = round(state, w[0x2C], K[0x2C]);
        let state = round(state, w[0x2D], K[0x2D]);
        let state = round(state, w[0x2E], K[0x2E]);
        let state = round(state, w[0x2F], K[0x2F]);
        let state = round(state, w[0x30], K[0x30]);
        let state = round(state, w[0x31], K[0x31]);
        let state = round(state, w[0x32], K[0x32]);
        let state = round(state, w[0x33], K[0x33]);
        let state = round(state, w[0x34], K[0x34]);
        let state = round(state, w[0x35], K[0x35]);
        let state = round(state, w[0x36], K[0x36]);
        let state = round(state, w[0x37], K[0x37]);
        let state = round(state, w[0x38], K[0x38]);
        let state = round(state, w[0x39], K[0x39]);
        let state = round(state, w[0x3A], K[0x3A]);
        let state = round(state, w[0x3B], K[0x3B]);
        let state = round(state, w[0x3C], K[0x3C]);
        let state = round(state, w[0x3D], K[0x3D]);
        let state = round(state, w[0x3E], K[0x3E]);
        let state = round(state, w[0x3F], K[0x3F]);
        let state = round(state, w[0x40], K[0x40]);
        let state = round(state, w[0x41], K[0x41]);
        let state = round(state, w[0x42], K[0x42]);
        let state = round(state, w[0x43], K[0x43]);
        let state = round(state, w[0x44], K[0x44]);
        let state = round(state, w[0x45], K[0x45]);
        let state = round(state, w[0x46], K[0x46]);
        let state = round(state, w[0x47], K[0x47]);
        let state = round(state, w[0x48], K[0x48]);
        let state = round(state, w[0x49], K[0x49]);
        let state = round(state, w[0x4A], K[0x4A]);
        let state = round(state, w[0x4B], K[0x4B]);
        let state = round(state, w[0x4C], K[0x4C]);
        let state = round(state, w[0x4D], K[0x4D]);
        let state = round(state, w[0x4E], K[0x4E]);
        let state = round(state, w[0x4F], K[0x4F]);

        // Update

        let Self { a, b, c, d, e, f, g, h } = state;

        let a = a.wrapping_add(self.a);
        let b = b.wrapping_add(self.b);
        let c = c.wrapping_add(self.c);
        let d = d.wrapping_add(self.d);
        let e = e.wrapping_add(self.e);
        let f = f.wrapping_add(self.f);
        let g = g.wrapping_add(self.g);
        let h = h.wrapping_add(self.h);

        // Return

        Self { a, b, c, d, e, f, g, h }
    }

    /// Returns a new state with initial values.
    #[must_use]
    pub const fn reset(self) -> Self {
        Self::new()
    }

    /// Returns a digest.
    #[must_use]
    pub const fn digest(&self) -> [u64; DIGEST_LENGTH_QWORDS] {
        let Self { a, b, c, d, e, f, .. } = *self;
        [a, b, c, d, e, f]
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_empty() {
        let digest = new().digest();
        assert_eq!(
            digest,
            [
                0xCBBB9D5DC1059ED8,
                0x629A292A367CD507,
                0x9159015A3070DD17,
                0x152FECD8F70E5939,
                0x67332667FFC00B31,
                0x8EB44A8768581511,
            ]
        );
    }

    #[test]
    fn default_empty() {
        let digest = default().digest();
        assert_eq!(
            digest,
            [
                0xCBBB9D5DC1059ED8,
                0x629A292A367CD507,
                0x9159015A3070DD17,
                0x152FECD8F70E5939,
                0x67332667FFC00B31,
                0x8EB44A8768581511,
            ]
        );
    }

    #[test]
    fn new_zeros() {
        #[rustfmt::skip]
        let block = [
            0x8000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ];
        let digest = new().update(block).digest();
        assert_eq!(
            digest,
            [
                0x38B060A751AC9638,
                0x4CD9327EB1B1E36A,
                0x21FDB71114BE0743,
                0x4C0CC7BF63F6E1DA,
                0x274EDEBFE76F65FB,
                0xD51AD2F14898B95B,
            ]
        );
    }
}
