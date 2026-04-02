//! Zstd compression for message payloads.

use anyhow::Result;

const DEFAULT_LEVEL: i32 = 3;

/// Compress data with zstd.
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::encode_all(data, DEFAULT_LEVEL)?)
}

/// Decompress zstd data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::decode_all(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_roundtrip() {
        let original = b"the quick brown fox jumps over the lazy dog. ".repeat(100);
        let compressed = compress(&original).unwrap();
        assert!(compressed.len() < original.len());
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_empty() {
        let compressed = compress(b"").unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }
}
