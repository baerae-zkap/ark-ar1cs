//! `K` arwtns blobs packed into a single byte stream.
//!
//! Format (length-prefixed concatenation):
//!
//! ```text
//!   magic[6]                "ARWPCK"
//!   version[1]              0x00
//!   reserved[1]             0x00
//!   count[4 LE u32]
//!   for each item:
//!     item_len[4 LE u32]
//!     item_bytes[item_len]
//! ```
//!
//! Each `item_bytes` is a complete `ArwtnsFile::write` output (header, body,
//! and 32-byte trailer). `pack` and `unpack` are intentionally byte-only —
//! they don't touch the field type — so the host can split a packed blob
//! without pulling in any curve dependency.

use alloc::vec::Vec;

const PACK_MAGIC: &[u8; 6] = b"ARWPCK";
const PACK_VERSION_V0: u8 = 0x00;
const PACK_HEADER_LEN: usize = 12;

/// Errors raised by [`pack`] and [`unpack`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackedError {
    #[error("packed blob too short")]
    TooShort,
    #[error("invalid magic bytes")]
    BadMagic,
    #[error("unsupported pack version: {0:#x}")]
    UnsupportedVersion(u8),
    #[error("reserved byte must be zero")]
    ReservedNotZero,
    #[error("item length {0} exceeds remaining buffer")]
    ItemOutOfBounds(u32),
    #[error("trailing bytes after final item")]
    TrailingBytes,
    #[error("item count overflow")]
    CountOverflow,
}

/// Concatenate `items` into a packed blob using the layout documented at the
/// module level.
pub fn pack<I>(items: I) -> Vec<u8>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let items: Vec<_> = items.into_iter().collect();
    let count = items.len() as u32;

    let body_len: usize = items.iter().map(|x| 4 + x.as_ref().len()).sum();
    let mut out = Vec::with_capacity(PACK_HEADER_LEN + body_len);
    out.extend_from_slice(PACK_MAGIC);
    out.push(PACK_VERSION_V0);
    out.push(0x00);
    out.extend_from_slice(&count.to_le_bytes());

    for item in items {
        let bytes = item.as_ref();
        let item_len = bytes.len() as u32;
        out.extend_from_slice(&item_len.to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// Borrow each item back out of a packed blob.
///
/// The returned slices reference `buf` directly — no copies. Callers can
/// hand each slice to `ArwtnsFile::read` independently.
pub fn unpack(buf: &[u8]) -> Result<Vec<&[u8]>, PackedError> {
    if buf.len() < PACK_HEADER_LEN {
        return Err(PackedError::TooShort);
    }
    if &buf[0..6] != PACK_MAGIC {
        return Err(PackedError::BadMagic);
    }
    if buf[6] != PACK_VERSION_V0 {
        return Err(PackedError::UnsupportedVersion(buf[6]));
    }
    if buf[7] != 0x00 {
        return Err(PackedError::ReservedNotZero);
    }
    let count = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;

    let mut out: Vec<&[u8]> = Vec::with_capacity(count);
    let mut cursor = PACK_HEADER_LEN;
    for _ in 0..count {
        if cursor + 4 > buf.len() {
            return Err(PackedError::TooShort);
        }
        let item_len = u32::from_le_bytes([
            buf[cursor],
            buf[cursor + 1],
            buf[cursor + 2],
            buf[cursor + 3],
        ]);
        cursor += 4;
        let item_end = cursor
            .checked_add(item_len as usize)
            .ok_or(PackedError::CountOverflow)?;
        if item_end > buf.len() {
            return Err(PackedError::ItemOutOfBounds(item_len));
        }
        out.push(&buf[cursor..item_end]);
        cursor = item_end;
    }
    if cursor != buf.len() {
        return Err(PackedError::TrailingBytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip_three_items() {
        let a: Vec<u8> = (0..7).collect();
        let b: Vec<u8> = (10..23).collect();
        let c: Vec<u8> = (50..51).collect();
        let blob = pack([a.as_slice(), b.as_slice(), c.as_slice()]);
        let parts = unpack(&blob).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], a.as_slice());
        assert_eq!(parts[1], b.as_slice());
        assert_eq!(parts[2], c.as_slice());
    }

    #[test]
    fn pack_unpack_roundtrip_empty() {
        let blob: Vec<u8> = pack::<[&[u8]; 0]>([]);
        let parts = unpack(&blob).unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn unpack_rejects_truncated_blob() {
        let a: Vec<u8> = (0..7).collect();
        let b: Vec<u8> = (10..23).collect();
        let mut blob = pack([a.as_slice(), b.as_slice()]);
        let truncated_len = blob.len() - 1;
        blob.truncate(truncated_len);
        assert!(matches!(
            unpack(&blob),
            Err(PackedError::ItemOutOfBounds(_)),
        ));
    }

    #[test]
    fn unpack_rejects_bad_magic() {
        let mut blob = pack([b"x".as_slice()]);
        blob[0] = b'Z';
        assert_eq!(unpack(&blob), Err(PackedError::BadMagic));
    }

    #[test]
    fn unpack_rejects_trailing_bytes() {
        let mut blob = pack([b"hello".as_slice()]);
        blob.push(0xff);
        assert_eq!(unpack(&blob), Err(PackedError::TrailingBytes));
    }
}
