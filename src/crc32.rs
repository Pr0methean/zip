//! Helper module to compute a CRC32 checksum

use bzip2::read::BzDecoder;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;

use crate::read::lzma::LzmaDecoder;
use crate::read::CryptoReader;
use crc32fast::Hasher;
use deflate64::Deflate64Decoder;
use flate2::read::DeflateDecoder;

/// Reader that validates the CRC32 when it reaches the EOF.
pub struct Crc32Reader<R: ReadAndSupplyExpectedCRC32> {
    inner: R,
    hasher: Hasher,
    /// Signals if `inner` stores aes encrypted data.
    /// AE-2 encrypted data doesn't use crc and sets the value to 0.
    ae2_encrypted: bool,
}

impl<R: ReadAndSupplyExpectedCRC32> Crc32Reader<R> {
    /// Get a new Crc32Reader which checks the inner reader against checksum.
    /// The check is disabled if `ae2_encrypted == true`.
    pub(crate) fn new(inner: R, ae2_encrypted: bool) -> Crc32Reader<R> {
        Crc32Reader {
            inner,
            hasher: Hasher::new(),
            ae2_encrypted,
        }
    }

    fn check_matches(&self) -> std::io::Result<bool> {
        Ok(self.inner.get_crc32()? == self.hasher.clone().finalize())
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: ReadAndSupplyExpectedCRC32> Read for Crc32Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = match self.inner.read(buf) {
            Ok(0) if !buf.is_empty() && !self.check_matches()? && !self.ae2_encrypted => {
                return Err(io::Error::new(io::ErrorKind::Other, "Invalid checksum"))
            }
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        self.hasher.update(&buf[0..count]);
        Ok(count)
    }
}

/// A reader trait that provides a method to get the expected crc of the data read.
/// In the normal case, the expected crc is known before the zip entry is read.
/// In streaming mode with data descriptors, the crc will be available after the data is read.
/// Still in both cases the crc is available after the data is read and can be checked.
pub trait ReadAndSupplyExpectedCRC32: Read {
    fn get_crc32(&self) -> std::io::Result<u32>;
}

pub struct InitiallyKnownCRC32<R: Read> {
    reader: R,
    crc: u32,
}

impl<R: Read> InitiallyKnownCRC32<R> {
    pub fn new(reader: R, crc: u32) -> InitiallyKnownCRC32<R> {
        InitiallyKnownCRC32 { reader, crc }
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> R {
        self.reader
    }

    #[allow(dead_code)]
    pub fn get_ref(&self) -> &R {
        &self.reader
    }
}

impl<R: Read> Read for InitiallyKnownCRC32<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: Read> ReadAndSupplyExpectedCRC32 for InitiallyKnownCRC32<R> {
    fn get_crc32(&self) -> std::io::Result<u32> {
        Ok(self.crc)
    }
}

impl<'a, T: ReadAndSupplyExpectedCRC32 + 'a> ReadAndSupplyExpectedCRC32 for CryptoReader<'a, T> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_crc32()
    }
}

impl<T: ReadAndSupplyExpectedCRC32> ReadAndSupplyExpectedCRC32 for DeflateDecoder<T> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_crc32()
    }
}

impl<T: ReadAndSupplyExpectedCRC32> ReadAndSupplyExpectedCRC32 for Deflate64Decoder<BufReader<T>> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_ref().get_crc32()
    }
}

impl<T: ReadAndSupplyExpectedCRC32> ReadAndSupplyExpectedCRC32 for BzDecoder<T> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_crc32()
    }
}

impl<'a, T: ReadAndSupplyExpectedCRC32 + BufRead> ReadAndSupplyExpectedCRC32
    for zstd::Decoder<'a, T>
{
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_crc32()
    }
}

impl<'a, T: ReadAndSupplyExpectedCRC32> ReadAndSupplyExpectedCRC32
    for zstd::Decoder<'a, BufReader<T>>
{
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_ref().get_crc32()
    }
}

impl<T: ReadAndSupplyExpectedCRC32> ReadAndSupplyExpectedCRC32 for LzmaDecoder<T> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_crc32()
    }
}

impl<'a> ReadAndSupplyExpectedCRC32 for Box<(dyn ReadAndSupplyExpectedCRC32 + 'a)> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.as_ref().get_crc32()
    }
}

impl<'a, T: ReadAndSupplyExpectedCRC32 + 'a> ReadAndSupplyExpectedCRC32 for Box<T> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.as_ref().get_crc32()
    }
}

impl<T: ReadAndSupplyExpectedCRC32> ReadAndSupplyExpectedCRC32 for std::io::Take<&mut T> {
    fn get_crc32(&self) -> io::Result<u32> {
        self.get_ref().get_crc32()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_empty_reader() {
        let data: &[u8] = b"";
        let mut buf = [0; 1];

        let mut reader = Crc32Reader::new(InitiallyKnownCRC32::new(data, 0), false);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);

        let mut reader = Crc32Reader::new(InitiallyKnownCRC32::new(data, 1), false);
        assert!(reader
            .read(&mut buf)
            .unwrap_err()
            .to_string()
            .contains("Invalid checksum"));
    }

    #[test]
    fn test_byte_by_byte() {
        let data: &[u8] = b"1234";
        let mut buf = [0; 1];

        let mut reader = Crc32Reader::new(InitiallyKnownCRC32::new(data, 0x9be3e0a3), false);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        // Can keep reading 0 bytes after the end
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn test_zero_read() {
        let data: &[u8] = b"1234";
        let mut buf = [0; 5];

        let mut reader = Crc32Reader::new(InitiallyKnownCRC32::new(data, 0x9be3e0a3), false);
        assert_eq!(reader.read(&mut buf[..0]).unwrap(), 0);
        assert_eq!(reader.read(&mut buf).unwrap(), 4);
    }
}
