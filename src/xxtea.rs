const DELTA: u32 = 0x9E3779B9;

fn mx(sum: u32, y: u32, z: u32, p: u32, e: u32, k: &[u32]) -> u32 {
    ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
        ^ ((sum ^ y).wrapping_add(k[(p & 3 ^ e) as usize] ^ z))
}

fn encrypt_words(v: &mut [u32], key: &[u32]) {
    let length = v.len();
    let n = length - 1;
    let mut z = v[n as usize];
    let mut sum: u32 = 0;
    let mut q = 6 + 52 / length;
    while q > 0 {
        sum = sum.wrapping_add(DELTA);
        let e = sum >> 2 & 3;
        let mut y: u32;
        for p in 0..n {
            y = v[(p) + 1];
            v[p] = v[p].wrapping_add(mx(sum, y, z, p as u32, e, key));
            z = v[p];
        }
        y = v[0];
        v[n] = v[n].wrapping_add(mx(sum, y, z, n as u32, e, key));
        z = v[n];
        q -= 1;
    }
}

fn decrypt_words(v: &mut [u32], key: &[u32]) {
    let length = v.len();
    let n = length - 1;
    let mut e: u32;
    let mut y: u32 = v[0];
    let mut z;
    let q: u32 = (6 + 52 / length) as u32;
    let mut sum: u32 = q.wrapping_mul(DELTA);
    while sum != 0 {
        e = sum >> 2 & 3;
        let mut p: usize = n as usize;
        while p > 0 {
            z = v[p - 1];
            v[p] = v[p].wrapping_sub(mx(sum, y, z, p as u32, e, key));
            y = v[p];
            p -= 1;
        }
        z = v[n];
        v[0] = v[0].wrapping_sub(mx(sum, y, z, 0, e, key));
        y = v[0];
        sum = sum.wrapping_sub(DELTA);
    }
}

/// Panics if `data` or `key` do not meet the size or alignment restrictions for this algorithm.
/// If this function returns successfully, then key is guaranteed to be 16 bytes long and aligned to
/// a multiple of 4 bytes, and data is guaranteed to be a multiple 4 bytes and also aligned to a 4
/// byte boundary.
fn check_sizes_and_alignment(data: &[u8], key: &[u8]) {
    if data.len() % 4 != 0 {
        panic!("Data not multiple of 32 bits");
    }
    if data.as_ptr().align_offset(4) != 0 {
        panic!("Data not aligned to 4 byte boundary");
    }
    if key.len() != 16 {
        panic!("Key size not 128 bits! Expected len 16, got {}", key.len());
    }
    if key.as_ptr().align_offset(4) != 0 {
        panic!("Key not aligned to 4 byte boundary");
    }
}

/// Encrypt a u8 vector with XXTEA
///
/// *Note:* XXTEA works on 32 bit words. If input is not evenly dividable by
/// four, this function will panic.
///
/// # Arguments
///
/// * `data` - The data to be encrypted
/// * `key` - encryption key. Must be 16 bytes
///
pub fn encrypt(data: &mut [u8], key: &[u8]) {
    check_sizes_and_alignment(data, key);
    // # SAFETY:
    // `data` is of the proper size and alignment as verified by `check_sizes_and_alignment`
    let data_aligned: &mut [u32] =
        unsafe { core::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u32, data.len() / 4) };

    // # SAFETY:
    // `key` is of the proper size and alignment as verified by `check_sizes_and_alignment`
    let key_aligned: &[u32] =
        unsafe { core::slice::from_raw_parts(key.as_ptr() as *const u32, data.len() / 4) };

    encrypt_words(data_aligned, key_aligned);
}

/// Decrypt a u8 vector with XXTEA
///
/// The output isn't verified for correctness, thus additional checks needs to
/// be performed on the output.
///
/// # Arguments
///
/// * `data` - The data to be decrypted
/// * `key` - encryption key. Must be 16 bytes
///
pub fn decrypt(data: &mut [u8], key: &[u8]) {
    check_sizes_and_alignment(data, key);
    // # SAFETY:
    // `data` is of the proper size and alignment as verified by `check_sizes_and_alignment`
    let data_aligned: &mut [u32] =
        unsafe { core::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u32, data.len() / 4) };

    // # SAFETY:
    // `key` is of the proper size and alignment as verified by `check_sizes_and_alignment`
    let key_aligned: &[u32] =
        unsafe { core::slice::from_raw_parts(key.as_ptr() as *const u32, data.len() / 4) };

    decrypt_words(data_aligned, key_aligned);
}
