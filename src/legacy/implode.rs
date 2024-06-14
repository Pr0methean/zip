use super::huffman::HuffmanDecoder;
use super::lz77::lz77_output_backref;
use bitstream_io::{BitRead, BitReader, Endianness, LittleEndian};
use std::collections::VecDeque;
use std::io::{self, copy, Cursor, Error, Read, Result};

/// Initialize the Huffman decoder d with num_lens codeword lengths read from is.
/// Returns false if the input is invalid.
fn read_huffman_code<T: std::io::Read, E: Endianness>(
    is: &mut BitReader<T, E>,
    num_lens: usize,
) -> std::io::Result<HuffmanDecoder> {
    let mut lens = [0; 1 << 8];
    let mut len_count = [0; 17];
    // debug_assert!(num_lens <= sizeof(lens) / sizeof(lens[0]));

    // Number of bytes representing the Huffman code.
    let byte = is.read::<u8>(8)?;
    let num_bytes = (byte + 1) as usize;

    let mut codeword_idx = 0;
    for _byte_idx in 0..num_bytes {
        let byte = is.read::<u16>(8)?;

        let codeword_len = (byte & 0xf) + 1; /* Low four bits plus one. */
        let run_length = (byte >> 4) + 1; /* High four bits plus one. */

        debug_assert!(codeword_len >= 1 && codeword_len <= 16);
        //debug_assert!(codeword_len < sizeof(len_count) / sizeof(len_count[0]));
        len_count[codeword_len as usize] += run_length;

        if (codeword_idx + run_length) as usize > num_lens {
            return Err(Error::new(
                io::ErrorKind::InvalidData,
                "too many codeword lengths",
            ));
        }
        for _ in 0..run_length {
            debug_assert!((codeword_idx as usize) < num_lens);
            lens[codeword_idx as usize] = codeword_len as u8;
            codeword_idx += 1;
        }
    }

    debug_assert!(codeword_idx as usize <= num_lens);
    if (codeword_idx as usize) < num_lens {
        return Err(Error::new(
            io::ErrorKind::InvalidData,
            "not enough codeword lengths",
        ));
    }

    // Check that the Huffman tree is full.
    let mut avail_codewords = 1;
    for i in 1..=16 {
        debug_assert!(avail_codewords >= 0);
        avail_codewords *= 2;
        avail_codewords -= len_count[i] as i32;
        if avail_codewords < 0 {
            return Err(Error::new(
                io::ErrorKind::InvalidData,
                "huffman tree is not full",
            ));
        }
    }
    if avail_codewords != 0 {
        // Not all codewords were used.
        return Err(Error::new(
            io::ErrorKind::InvalidData,
            "not all codewords were used",
        ));
    }

    let mut d = HuffmanDecoder::default();
    d.init(&lens, num_lens)?;
    Ok(d)
}

fn hwexplode(
    src: &[u8],
    uncomp_len: usize,
    large_wnd: bool,
    lit_tree: bool,
    pk101_bug_compat: bool,
    dst: &mut VecDeque<u8>,
) -> std::io::Result<()> {
    let bit_length = src.len() as u64 * 8;
    let mut is = BitReader::endian(Cursor::new(&src), LittleEndian);
    let mut lit_decoder_opt = if lit_tree {
        Some(read_huffman_code(&mut is, 256)?)
    } else {
        None
    };
    let mut len_decoder = read_huffman_code(&mut is, 64)?;
    let mut dist_decoder = read_huffman_code(&mut is, 64)?;
    let min_len = if pk101_bug_compat && large_wnd {
        3
    } else if !pk101_bug_compat && lit_tree {
        3
    } else {
        2
    };
    let dist_low_bits = if large_wnd { 7 } else { 6 };
    while dst.len() < uncomp_len {
        let is_literal = is.read_bit()?;
        if is_literal {
            // Literal.
            let sym;
            if let Some(lit_decoder) = &mut lit_decoder_opt {
                sym = lit_decoder.huffman_decode(bit_length, &mut is)?;
            } else {
                sym = is.read::<u8>(8)? as u16;
            }
            debug_assert!(sym <= u8::MAX as u16);
            dst.push_back(sym as u8);
            continue;
        }

        // Read the low dist bits.
        let mut dist = is.read::<u16>(dist_low_bits)?;
        // Read the Huffman-encoded high dist bits.
        let sym = dist_decoder.huffman_decode(bit_length, &mut is)?;
        dist |= (sym as u16) << dist_low_bits;
        dist += 1;

        // Read the Huffman-encoded len.
        let sym = len_decoder.huffman_decode(bit_length, &mut is)?;
        let mut len = (sym + min_len) as usize;

        if sym == 63 {
            // Read an extra len byte.
            len += is.read::<u16>(8)? as usize;
        }
        let len = len.min(uncomp_len - dst.len());
        if len <= uncomp_len - dst.len() && dist as usize <= dst.len() {
            // Enough room and no implicit zeros; chunked copy.
            lz77_output_backref(dst, dist as usize, len);
        } else {
            // Copy, handling overlap and implicit zeros.
            for _i in 0..len {
                if dist as usize > dst.len() {
                    dst.push_back(0);
                    continue;
                }
                dst.push_back(dst[dst.len() - dist as usize]);
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct ImplodeDecoder<R> {
    compressed_reader: R,
    uncompressed_size: u64,
    stream_read: bool,
    large_wnd: bool,
    lit_tree: bool,
    stream: VecDeque<u8>,
}

impl<R: Read> ImplodeDecoder<R> {
    pub fn new(inner: R, uncompressed_size: u64, flags: u16) -> Self {
        let large_wnd = (flags & 2) != 0;
        let lit_tree = (flags & 4) != 0;
        ImplodeDecoder {
            compressed_reader: inner,
            uncompressed_size,
            stream_read: false,
            large_wnd,
            lit_tree,
            stream: VecDeque::new(),
        }
    }

    pub fn finish(mut self) -> Result<VecDeque<u8>> {
        copy(&mut self.compressed_reader, &mut self.stream)?;
        Ok(self.stream)
    }
}

impl<R: Read> Read for ImplodeDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.stream_read {
            self.stream_read = true;
            let mut compressed_bytes = Vec::new();
            if let Err(err) = self.compressed_reader.read_to_end(&mut compressed_bytes) {
                return Err(err.into());
            }
            hwexplode(
                &compressed_bytes,
                self.uncompressed_size as usize,
                self.large_wnd,
                self.lit_tree,
                false,
                &mut self.stream,
            )?;
        }
        let bytes_read = self.stream.len().min(buf.len());
        buf[..bytes_read].copy_from_slice(&self.stream.drain(..bytes_read).collect::<Vec<u8>>());
        Ok(bytes_read)
    }
}

#[cfg(test)]
mod tests {
    use super::hwexplode;
    use std::collections::VecDeque;
    const HAMLET_256: &[u8; 249] = include_bytes!("../../tests/implode_hamlet_256.bin");

    #[test]
    fn test_explode_hamlet_256() {
        let mut dst = VecDeque::new();
        hwexplode(HAMLET_256, 256, false, false, false, &mut dst).unwrap();
        assert_eq!(dst.len(), 256);
    }
}
