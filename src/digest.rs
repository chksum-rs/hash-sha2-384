//! Module contains items related to the [`Digest`] structure.
//!
//! # Example
//!
//! ```rust
//! use chksum_hash_sha2_384 as sha2_384;
//!
//! // Digest bytes
//! #[rustfmt::skip]
//! let digest = [
//!     0x38, 0xB0, 0x60, 0xA7,
//!     0x51, 0xAC, 0x96, 0x38,
//!     0x4C, 0xD9, 0x32, 0x7E,
//!     0xB1, 0xB1, 0xE3, 0x6A,
//!     0x21, 0xFD, 0xB7, 0x11,
//!     0x14, 0xBE, 0x07, 0x43,
//!     0x4C, 0x0C, 0xC7, 0xBF,
//!     0x63, 0xF6, 0xE1, 0xDA,
//!     0x27, 0x4E, 0xDE, 0xBF,
//!     0xE7, 0x6F, 0x65, 0xFB,
//!     0xD5, 0x1A, 0xD2, 0xF1,
//!     0x48, 0x98, 0xB9, 0x5B,
//! ];
//!
//! // Create new digest
//! let digest = sha2_384::digest::new(digest);
//!
//! // Print digest (by default it uses hex lowercase format)
//! println!("digest {}", digest);
//!
//! // You can also specify which format you prefer
//! println!("digest {:x}", digest);
//! println!("digest {:X}", digest);
//!
//! // Turn into byte slice
//! let bytes = digest.as_bytes();
//!
//! // Get inner bytes
//! let digest = digest.into_inner();
//!
//! // Should be same
//! assert_eq!(bytes, &digest[..]);
//! ```

use std::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use std::num::ParseIntError;

use chksum_hash_core as core;

/// Digest length in bits.
pub const LENGTH_BITS: usize = 384;
/// Digest length in bytes.
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
/// Digest length in words (double bytes).
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
/// Digest length in double words (quadruple bytes).
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;
/// Digest length in quadruple words (octuple bytes).
pub const LENGTH_QWORDS: usize = LENGTH_DWORDS / 2;
/// Digest length in hexadecimal format.
pub const LENGTH_HEX: usize = LENGTH_BYTES * 2;

/// Creates a new [`Digest`].
#[must_use]
pub fn new(digest: [u8; LENGTH_BYTES]) -> Digest {
    Digest::new(digest)
}

/// A hash digest.
///
/// Check [`digest`](self) module for usage examples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; LENGTH_BYTES]);

impl Digest {
    /// Creates a new digest.
    #[must_use]
    pub const fn new(digest: [u8; LENGTH_BYTES]) -> Self {
        Self(digest)
    }

    /// Returns a byte slice of the digest's contents.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the digest, returning the digest bytes.
    #[must_use]
    pub fn into_inner(self) -> [u8; LENGTH_BYTES] {
        let Self(inner) = self;
        inner
    }

    /// Returns a string in the lowercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash_sha2_384 as sha2_384;
    ///
    /// let digest = [
    ///     0x38, 0xB0, 0x60, 0xA7,
    ///     0x51, 0xAC, 0x96, 0x38,
    ///     0x4C, 0xD9, 0x32, 0x7E,
    ///     0xB1, 0xB1, 0xE3, 0x6A,
    ///     0x21, 0xFD, 0xB7, 0x11,
    ///     0x14, 0xBE, 0x07, 0x43,
    ///     0x4C, 0x0C, 0xC7, 0xBF,
    ///     0x63, 0xF6, 0xE1, 0xDA,
    ///     0x27, 0x4E, 0xDE, 0xBF,
    ///     0xE7, 0x6F, 0x65, 0xFB,
    ///     0xD5, 0x1A, 0xD2, 0xF1,
    ///     0x48, 0x98, 0xB9, 0x5B,
    /// ];
    /// let digest = sha2_384::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        format!("{self:x}")
    }

    /// Returns a string in the uppercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash_sha2_384 as sha2_384;
    ///
    /// let digest = [
    ///     0x38, 0xB0, 0x60, 0xA7,
    ///     0x51, 0xAC, 0x96, 0x38,
    ///     0x4C, 0xD9, 0x32, 0x7E,
    ///     0xB1, 0xB1, 0xE3, 0x6A,
    ///     0x21, 0xFD, 0xB7, 0x11,
    ///     0x14, 0xBE, 0x07, 0x43,
    ///     0x4C, 0x0C, 0xC7, 0xBF,
    ///     0x63, 0xF6, 0xE1, 0xDA,
    ///     0x27, 0x4E, 0xDE, 0xBF,
    ///     0xE7, 0x6F, 0x65, 0xFB,
    ///     0xD5, 0x1A, 0xD2, 0xF1,
    ///     0x48, 0x98, 0xB9, 0x5B,
    /// ];
    /// let digest = sha2_384::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        format!("{self:X}")
    }
}

impl core::Digest for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; LENGTH_BYTES]> for Digest {
    fn from(digest: [u8; LENGTH_BYTES]) -> Self {
        Self::new(digest)
    }
}

impl From<Digest> for [u8; LENGTH_BYTES] {
    fn from(digest: Digest) -> Self {
        digest.into_inner()
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        LowerHex::fmt(self, f)
    }
}

impl LowerHex for Digest {
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
            self.0[0x1C], self.0[0x1D], self.0[0x1E], self.0[0x1F],
            self.0[0x20], self.0[0x21], self.0[0x22], self.0[0x23],
            self.0[0x24], self.0[0x25], self.0[0x26], self.0[0x27],
            self.0[0x28], self.0[0x29], self.0[0x2A], self.0[0x2B],
            self.0[0x2C], self.0[0x2D], self.0[0x2E], self.0[0x2F],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0x", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl UpperHex for Digest {
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
            self.0[0x1C], self.0[0x1D], self.0[0x1E], self.0[0x1F],
            self.0[0x20], self.0[0x21], self.0[0x22], self.0[0x23],
            self.0[0x24], self.0[0x25], self.0[0x26], self.0[0x27],
            self.0[0x28], self.0[0x29], self.0[0x2A], self.0[0x2B],
            self.0[0x2C], self.0[0x2D], self.0[0x2E], self.0[0x2F],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0X", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl TryFrom<&str> for Digest {
    type Error = FormatError;

    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != LENGTH_HEX {
            let error = Self::Error::InvalidLength {
                value: digest.len(),
                proper: LENGTH_HEX,
            };
            return Err(error);
        }
        let digest = [
            u64::from_str_radix(&digest[0x00..0x10], 16)?.to_be_bytes(),
            u64::from_str_radix(&digest[0x10..0x20], 16)?.to_be_bytes(),
            u64::from_str_radix(&digest[0x20..0x30], 16)?.to_be_bytes(),
            u64::from_str_radix(&digest[0x30..0x40], 16)?.to_be_bytes(),
            u64::from_str_radix(&digest[0x40..0x50], 16)?.to_be_bytes(),
            u64::from_str_radix(&digest[0x50..0x60], 16)?.to_be_bytes(),
        ];
        #[rustfmt::skip]
        let digest = [
            digest[0][0], digest[0][1], digest[0][2], digest[0][3],
            digest[0][4], digest[0][5], digest[0][6], digest[0][7],
            digest[1][0], digest[1][1], digest[1][2], digest[1][3],
            digest[1][4], digest[1][5], digest[1][6], digest[1][7],
            digest[2][0], digest[2][1], digest[2][2], digest[2][3],
            digest[2][4], digest[2][5], digest[2][6], digest[2][7],
            digest[3][0], digest[3][1], digest[3][2], digest[3][3],
            digest[3][4], digest[3][5], digest[3][6], digest[3][7],
            digest[4][0], digest[4][1], digest[4][2], digest[4][3],
            digest[4][4], digest[4][5], digest[4][6], digest[4][7],
            digest[5][0], digest[5][1], digest[5][2], digest[5][3],
            digest[5][4], digest[5][5], digest[5][6], digest[5][7],
        ];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

/// An error type for the digest conversion.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum FormatError {
    /// Represents an invalid length error with detailed information.
    #[error("Invalid length `{value}`, proper value `{proper}`")]
    InvalidLength { value: usize, proper: usize },
    /// Represents an error that occurs during parsing.
    #[error(transparent)]
    ParseError(#[from] ParseIntError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_bytes() {
        #[rustfmt::skip]
        let digest = [
            0x38, 0xB0, 0x60, 0xA7,
            0x51, 0xAC, 0x96, 0x38,
            0x4C, 0xD9, 0x32, 0x7E,
            0xB1, 0xB1, 0xE3, 0x6A,
            0x21, 0xFD, 0xB7, 0x11,
            0x14, 0xBE, 0x07, 0x43,
            0x4C, 0x0C, 0xC7, 0xBF,
            0x63, 0xF6, 0xE1, 0xDA,
            0x27, 0x4E, 0xDE, 0xBF,
            0xE7, 0x6F, 0x65, 0xFB,
            0xD5, 0x1A, 0xD2, 0xF1,
            0x48, 0x98, 0xB9, 0x5B,
        ];
        assert_eq!(Digest::new(digest).as_bytes(), &digest);
    }

    #[test]
    fn as_ref() {
        #[rustfmt::skip]
        let digest = [
            0x38, 0xB0, 0x60, 0xA7,
            0x51, 0xAC, 0x96, 0x38,
            0x4C, 0xD9, 0x32, 0x7E,
            0xB1, 0xB1, 0xE3, 0x6A,
            0x21, 0xFD, 0xB7, 0x11,
            0x14, 0xBE, 0x07, 0x43,
            0x4C, 0x0C, 0xC7, 0xBF,
            0x63, 0xF6, 0xE1, 0xDA,
            0x27, 0x4E, 0xDE, 0xBF,
            0xE7, 0x6F, 0x65, 0xFB,
            0xD5, 0x1A, 0xD2, 0xF1,
            0x48, 0x98, 0xB9, 0x5B,
        ];
        assert_eq!(Digest::new(digest).as_ref(), &digest);
    }

    #[test]
    fn format() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0x38, 0xB0, 0x60, 0xA7,
            0x51, 0xAC, 0x96, 0x38,
            0x4C, 0xD9, 0x32, 0x7E,
            0xB1, 0xB1, 0xE3, 0x6A,
            0x21, 0xFD, 0xB7, 0x11,
            0x14, 0xBE, 0x07, 0x43,
            0x4C, 0x0C, 0xC7, 0xBF,
            0x63, 0xF6, 0xE1, 0xDA,
            0x27, 0x4E, 0xDE, 0xBF,
            0xE7, 0x6F, 0x65, 0xFB,
            0xD5, 0x1A, 0xD2, 0xF1,
            0x48, 0x98, 0xB9, 0x5B,
        ]);
        assert_eq!(
            format!("{digest:x}"),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0x38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            format!("{digest:104x}"),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b        "
        );
        assert_eq!(
            format!("{digest:>104x}"),
            "        38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            format!("{digest:^104x}"),
            "    38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b    "
        );
        assert_eq!(
            format!("{digest:<104x}"),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b        "
        );
        assert_eq!(
            format!("{digest:.^104x}"),
            "....38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b...."
        );
        assert_eq!(format!("{digest:.8x}"), "38b060a7");
        assert_eq!(
            format!("{digest:X}"),
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0X38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
        );
        assert_eq!(
            format!("{digest:104X}"),
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B        "
        );
        assert_eq!(
            format!("{digest:>104X}"),
            "        38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
        );
        assert_eq!(
            format!("{digest:^104X}"),
            "    38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B    "
        );
        assert_eq!(
            format!("{digest:<104X}"),
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B        "
        );
        assert_eq!(
            format!("{digest:.^104X}"),
            "....38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B...."
        );
        assert_eq!(format!("{digest:.8X}"), "38B060A7");
    }

    #[test]
    fn from() {
        #[rustfmt::skip]
        let digest = [
            0x38, 0xB0, 0x60, 0xA7,
            0x51, 0xAC, 0x96, 0x38,
            0x4C, 0xD9, 0x32, 0x7E,
            0xB1, 0xB1, 0xE3, 0x6A,
            0x21, 0xFD, 0xB7, 0x11,
            0x14, 0xBE, 0x07, 0x43,
            0x4C, 0x0C, 0xC7, 0xBF,
            0x63, 0xF6, 0xE1, 0xDA,
            0x27, 0x4E, 0xDE, 0xBF,
            0xE7, 0x6F, 0x65, 0xFB,
            0xD5, 0x1A, 0xD2, 0xF1,
            0x48, 0x98, 0xB9, 0x5B,
        ];
        assert_eq!(Digest::from(digest), Digest::new(digest));
        assert_eq!(<[u8; 48]>::from(Digest::new(digest)), digest);
    }

    #[test]
    fn to_hex() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0x38, 0xB0, 0x60, 0xA7,
            0x51, 0xAC, 0x96, 0x38,
            0x4C, 0xD9, 0x32, 0x7E,
            0xB1, 0xB1, 0xE3, 0x6A,
            0x21, 0xFD, 0xB7, 0x11,
            0x14, 0xBE, 0x07, 0x43,
            0x4C, 0x0C, 0xC7, 0xBF,
            0x63, 0xF6, 0xE1, 0xDA,
            0x27, 0x4E, 0xDE, 0xBF,
            0xE7, 0x6F, 0x65, 0xFB,
            0xD5, 0x1A, 0xD2, 0xF1,
            0x48, 0x98, 0xB9, 0x5B,
        ]);
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B");
    }

    #[test]
    fn try_from() {
        assert_eq!(
            Digest::try_from(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            ),
            Digest::try_from(
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
            )
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"),
            Ok(Digest::new([
                0x38, 0xB0, 0x60, 0xA7,
                0x51, 0xAC, 0x96, 0x38,
                0x4C, 0xD9, 0x32, 0x7E,
                0xB1, 0xB1, 0xE3, 0x6A,
                0x21, 0xFD, 0xB7, 0x11,
                0x14, 0xBE, 0x07, 0x43,
                0x4C, 0x0C, 0xC7, 0xBF,
                0x63, 0xF6, 0xE1, 0xDA,
                0x27, 0x4E, 0xDE, 0xBF,
                0xE7, 0x6F, 0x65, 0xFB,
                0xD5, 0x1A, 0xD2, 0xF1,
                0x48, 0x98, 0xB9, 0x5B,
            ]))
        );
        assert!(matches!(Digest::try_from("38"), Err(FormatError::InvalidLength { .. })));
        assert!(matches!(
            Digest::try_from(
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95BXX"
            ),
            Err(FormatError::InvalidLength { .. })
        ));
        assert!(matches!(
            Digest::try_from(
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B9XX"
            ),
            Err(FormatError::ParseError(_))
        ));
    }
}
