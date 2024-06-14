use std::collections::VecDeque;

/// Output the (dist,len) back reference at dst_pos in dst.
pub(crate) fn lz77_output_backref(dst: &mut VecDeque<u8>, dist: usize, len: usize) {
    //    debug_assert!(dist <= dst_pos, "cannot reference before beginning of dst");

    for _ in 0..len {
        dst.push_back(dst[dst.len() - dist]);
    }
}
