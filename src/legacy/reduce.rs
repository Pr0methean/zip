use std::collections::VecDeque;
use std::io::{self, copy, Read, Result};

use bitstream_io::{BitRead, BitReader, Endianness, LittleEndian};

use crate::legacy::lsb;
use crate::legacy::lz77::lz77_output_backref;

/// Number of bits used to represent indices in a follower set of size n.
fn follower_idx_bw(n: u8) -> u8 {
    debug_assert!(n <= 32);
    match n {
        0 => 0,
        1 => 1,
        _ => 8 - (n - 1).leading_zeros() as u8,
    }
}

#[derive(Default, Clone, Copy)]
struct FollowerSet {
    size: u8,
    idx_bw: u8,
    followers: [u8; 32],
}

/// Read the follower sets from is into fsets. Returns true on success.
fn read_follower_sets<T: std::io::Read, E: Endianness>(
    is: &mut BitReader<T, E>,
    fsets: &mut [FollowerSet],
) -> io::Result<()> {
    for i in (0..=u8::MAX as usize).rev() {
        let n = is.read::<u8>(6)?;
        if n > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid follower set",
            ));
        }
        fsets[i].size = n;
        fsets[i].idx_bw = follower_idx_bw(n);

        for j in 0..fsets[i].size as usize {
            fsets[i].followers[j] = is.read::<u8>(8)?;
        }
    }

    Ok(())
}

/// Read the next byte from is, decoded based on prev_byte and the follower sets.
/// The byte is returned in *out_byte. The function returns true on success,
/// and false on bad data or end of input.
fn read_next_byte<T: std::io::Read, E: Endianness>(
    is: &mut BitReader<T, E>,
    prev_byte: u8,
    fsets: &mut [FollowerSet],
) -> io::Result<u8> {
    if fsets[prev_byte as usize].size == 0 {
        // No followers; read a literal byte.
        return Ok(is.read::<u8>(8)?);
    }

    if is.read::<u8>(1)? == 1 {
        // Don't use the follower set; read a literal byte.
        return Ok(is.read::<u8>(8)?);
    }

    // The bits represent the index of a follower byte.
    let idx_bw = fsets[prev_byte as usize].idx_bw;
    let follower_idx = is.read::<u16>(idx_bw as u32)? as usize;
    if follower_idx >= fsets[prev_byte as usize].size as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid follower index",
        ));
    }
    Ok(fsets[prev_byte as usize].followers[follower_idx])
}

fn max_len(comp_factor: u8) -> usize {
    let v_len_bits = (8 - comp_factor) as usize;
    debug_assert!(comp_factor >= 1 && comp_factor <= 4);
    // Bits in V + extra len byte + implicit 3.
    ((1 << v_len_bits) - 1) + u8::MAX as usize + 3
}

fn max_dist(comp_factor: u8) -> usize {
    debug_assert!(comp_factor >= 1 && comp_factor <= 4);
    let v_dist_bits = comp_factor as usize;
    // Bits in V * 256 + W byte + implicit 1. */
    1 << (v_dist_bits + 8)
}

const DLE_BYTE: u8 = 0x90;

fn hwexpand(
    src: &[u8],
    uncomp_len: usize,
    comp_factor: u8,
    dst: &mut VecDeque<u8>,
) -> io::Result<()> {
    let mut fsets = [FollowerSet::default(); 1 << 8];
    debug_assert!(comp_factor >= 1 && comp_factor <= 4);

    let mut is = BitReader::endian(src, LittleEndian);
    read_follower_sets(&mut is, &mut fsets)?;

    // Number of bits in V used for backref length.
    let v_len_bits = 8 - comp_factor;

    let mut curr_byte = 0; // The first "previous byte" is implicitly zero.

    while dst.len() < uncomp_len {
        // Read a literal byte or DLE marker.
        curr_byte = read_next_byte(&mut is, curr_byte, &mut fsets)?;
        if curr_byte != DLE_BYTE {
            // Output a literal byte.
            dst.push_back(curr_byte);
            continue;
        }

        // Read the V byte which determines the length.
        curr_byte = read_next_byte(&mut is, curr_byte, &mut fsets)?;
        if curr_byte == 0 {
            // Output a literal DLE byte.
            dst.push_back(DLE_BYTE);
            continue;
        }
        let v = curr_byte;
        let mut len = lsb(v as u64, v_len_bits) as usize;
        if len == (1 << v_len_bits) - 1 {
            // Read an extra length byte.
            curr_byte = read_next_byte(&mut is, curr_byte, &mut fsets)?;
            len += curr_byte as usize;
        }
        len += 3;

        // Read the W byte, which together with V gives the distance.
        curr_byte = read_next_byte(&mut is, curr_byte, &mut fsets)?;
        let dist = ((v as usize) >> v_len_bits) << 8 + curr_byte as usize + 1;

        debug_assert!(len <= max_len(comp_factor));
        debug_assert!(dist as usize <= max_dist(comp_factor));

        // Output the back reference.
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
pub struct ReduceDecoder<R> {
    compressed_reader: R,
    uncompressed_size: u64,
    stream_read: bool,
    comp_factor: u8,
    stream: VecDeque<u8>,
}

impl<R: Read> ReduceDecoder<R> {
    pub fn new(inner: R, uncompressed_size: u64, comp_factor: u8) -> Self {
        ReduceDecoder {
            compressed_reader: inner,
            uncompressed_size,
            stream_read: false,
            comp_factor,
            stream: VecDeque::new(),
        }
    }

    pub fn finish(mut self) -> Result<VecDeque<u8>> {
        copy(&mut self.compressed_reader, &mut self.stream)?;
        Ok(self.stream)
    }
}

impl<R: Read> Read for ReduceDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.stream_read {
            self.stream_read = true;
            let mut compressed_bytes = Vec::new();
            if let Err(err) = self.compressed_reader.read_to_end(&mut compressed_bytes) {
                return Err(err.into());
            }
            hwexpand(
                &compressed_bytes,
                self.uncompressed_size as usize,
                self.comp_factor,
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
    use super::hwexpand;
    use crate::legacy::reduce::{follower_idx_bw, max_dist};
    use std::collections::VecDeque;
    const HAMLET_2048: &[u8; 1285] = include_bytes!("../../tests/reduce_hamlet_2048.bin");

    #[test]
    fn test_expand_hamlet2048() {
        let mut dst = VecDeque::new();
        hwexpand(HAMLET_2048, 2048, 4, &mut dst).unwrap();
        assert_eq!(dst.len(), 2048);
    }

    /*
      Put some text first to make PKZIP actually use Reduce compression.
      Target the code path which copies a zero when dist > current position.

      $ curl -O http://cd.textfiles.com/originalsw/25/pkz092.exe
      $ dosbox -c "mount c ." -c "c:" -c "pkz092" -c "exit"
      $ dd if=hamlet.txt bs=1 count=2048 > a
      $ dd if=/dev/zero  bs=1 count=1024 >> a
      $ dosbox -c "mount c ." -c "c:" -c "pkzip -ea4 a.zip a" -c "exit"
      $ xxd -i -s 31 -l $(expr $(find A.ZIP -printf %s) - 100) A.ZIP
    */
    const ZEROS_REDUCED: &[u8; 1297] = include_bytes!("../../tests/reduce_zero_reduced.bin");

    #[test]
    fn test_expand_zeros() {
        let mut dst = VecDeque::new();
        hwexpand(ZEROS_REDUCED, 2048 + 1024, 4, &mut dst).unwrap();
        assert_eq!(dst.len(), 2048 + 1024);
        for i in 0..(1 << 10) {
            assert_eq!(dst[(1 << 11) + i], 0);
        }
    }

    fn orig_follower_idx_bw(n: u8) -> u8 {
        if n > 16 {
            return 5;
        }
        if n > 8 {
            return 4;
        }
        if n > 4 {
            return 3;
        }
        if n > 2 {
            return 2;
        }
        if n > 0 {
            return 1;
        }
        return 0;
    }

    #[test]
    fn test_follower_idx_bw() {
        for i in 0..=32 {
            assert_eq!(orig_follower_idx_bw(i), follower_idx_bw(i));
        }
    }

    #[test]
    fn test_max_dist() {
        for i in 1..=4 {
            let v_dist_bits = i as usize;
            let c = ((1 << v_dist_bits) - 1) * 256 + 255 + 1;
            assert_eq!(max_dist(i), c);
        }
    }
}
