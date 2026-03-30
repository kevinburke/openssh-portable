use core::ffi::c_int;

use md5::Digest;
use md5::Md5;
use sha1::Sha1;

pub(crate) const SSH_DIGEST_MD5: c_int = 0;
pub(crate) const SSH_DIGEST_SHA1: c_int = 1;
pub(crate) const SSH_DIGEST_SHA256: c_int = 2;
pub(crate) const SSH_DIGEST_SHA384: c_int = 3;
pub(crate) const SSH_DIGEST_SHA512: c_int = 4;

pub(crate) const MD5_DIGEST_LENGTH: usize = 16;
pub(crate) const SHA1_DIGEST_LENGTH: usize = 20;
const SHA256_BLOCK_LENGTH: usize = 64;
pub(crate) const SHA256_DIGEST_LENGTH: usize = 32;
pub(crate) const SHA384_DIGEST_LENGTH: usize = 48;
const SHA512_BLOCK_LENGTH: usize = 128;
pub(crate) const SHA512_DIGEST_LENGTH: usize = 64;

// SHA-256 round constants K[0..63] from FIPS 180-4 section 4.2.2.
// These are the first 32 bits of the fractional parts of the cube roots
// of the first 64 prime numbers.
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// SHA-384/SHA-512 round constants K[0..79] from FIPS 180-4 section 4.2.3.
// These are the first 64 bits of the fractional parts of the cube roots
// of the first 80 prime numbers.
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Clone)]
pub(crate) struct Sha256State {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_LENGTH],
    buffer_len: usize,
    bit_len: u64,
}

#[derive(Clone)]
pub(crate) struct Sha512State {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_LENGTH],
    buffer_len: usize,
    bit_len: u128,
}

#[derive(Clone)]
pub(crate) enum DigestState {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256State),
    Sha384(Sha512State),
    Sha512(Sha512State),
}

impl Sha256State {
    fn new() -> Self {
        Self {
            // SHA-256 initial hash value H(0) from FIPS 180-4 section 5.3.3:
            // the first 32 bits of the fractional parts of the square roots
            // of the first 8 prime numbers.
            state: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; SHA256_BLOCK_LENGTH],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.bit_len = self.bit_len.wrapping_add((data.len() as u64).wrapping_mul(8));
        while !data.is_empty() {
            let take = core::cmp::min(SHA256_BLOCK_LENGTH - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == SHA256_BLOCK_LENGTH {
                sha256_compress(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }
    }

    fn finalize(mut self, out: &mut [u8]) {
        let mut block = [0u8; SHA256_BLOCK_LENGTH];
        block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        block[self.buffer_len] = 0x80;

        if self.buffer_len >= 56 {
            sha256_compress(&mut self.state, &block);
            block = [0; SHA256_BLOCK_LENGTH];
        }

        block[56..64].copy_from_slice(&self.bit_len.to_be_bytes());
        sha256_compress(&mut self.state, &block);

        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

impl Sha512State {
    // SHA-384 reuses the SHA-512 compression function and 1024-bit block
    // processing. It differs only in the initial hash value and in truncating
    // the final digest to 384 bits.
    fn new_sha384() -> Self {
        Self {
            // SHA-384 initial hash value H(0) from FIPS 180-4 section 5.3.4.
            state: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            buffer: [0; SHA512_BLOCK_LENGTH],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    fn new_sha512() -> Self {
        Self {
            // SHA-512 initial hash value H(0) from FIPS 180-4 section 5.3.5:
            // the first 64 bits of the fractional parts of the square roots
            // of the first 8 prime numbers.
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0; SHA512_BLOCK_LENGTH],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.bit_len = self.bit_len.wrapping_add((data.len() as u128).wrapping_mul(8));
        while !data.is_empty() {
            let take = core::cmp::min(SHA512_BLOCK_LENGTH - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == SHA512_BLOCK_LENGTH {
                sha512_compress(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }
    }

    fn finalize(mut self, out: &mut [u8]) {
        let mut block = [0u8; SHA512_BLOCK_LENGTH];
        block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        block[self.buffer_len] = 0x80;

        if self.buffer_len >= 112 {
            sha512_compress(&mut self.state, &block);
            block = [0; SHA512_BLOCK_LENGTH];
        }

        block[112..128].copy_from_slice(&self.bit_len.to_be_bytes());
        sha512_compress(&mut self.state, &block);

        for (chunk, word) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

impl DigestState {
    pub(crate) fn new(alg: c_int) -> Option<Self> {
        match alg {
            SSH_DIGEST_MD5 => Some(Self::Md5(Md5::new())),
            SSH_DIGEST_SHA1 => Some(Self::Sha1(Sha1::new())),
            SSH_DIGEST_SHA256 => Some(Self::Sha256(Sha256State::new())),
            SSH_DIGEST_SHA384 => Some(Self::Sha384(Sha512State::new_sha384())),
            SSH_DIGEST_SHA512 => Some(Self::Sha512(Sha512State::new_sha512())),
            _ => None,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(state) => md5::Digest::update(state, data),
            Self::Sha1(state) => sha1::Digest::update(state, data),
            Self::Sha256(state) => state.update(data),
            Self::Sha384(state) | Self::Sha512(state) => state.update(data),
        }
    }

    pub(crate) fn finalize_to(&self, out: &mut [u8]) -> Result<(), ()> {
        match self.clone() {
            Self::Md5(state) => {
                if out.len() < MD5_DIGEST_LENGTH {
                    return Err(());
                }
                let digest = md5::Digest::finalize(state);
                out[..MD5_DIGEST_LENGTH].copy_from_slice(&digest);
            }
            Self::Sha1(state) => {
                if out.len() < SHA1_DIGEST_LENGTH {
                    return Err(());
                }
                let digest = sha1::Digest::finalize(state);
                out[..SHA1_DIGEST_LENGTH].copy_from_slice(&digest);
            }
            Self::Sha256(state) => {
                if out.len() < SHA256_DIGEST_LENGTH {
                    return Err(());
                }
                state.finalize(&mut out[..SHA256_DIGEST_LENGTH]);
            }
            Self::Sha384(state) => {
                let mut full = [0u8; SHA512_DIGEST_LENGTH];
                if out.len() < SHA384_DIGEST_LENGTH {
                    return Err(());
                }
                state.finalize(&mut full);
                out[..SHA384_DIGEST_LENGTH].copy_from_slice(&full[..SHA384_DIGEST_LENGTH]);
            }
            Self::Sha512(state) => {
                if out.len() < SHA512_DIGEST_LENGTH {
                    return Err(());
                }
                state.finalize(&mut out[..SHA512_DIGEST_LENGTH]);
            }
        }
        Ok(())
    }

    pub(crate) fn scrub(&mut self) {
        match self {
            Self::Md5(state) => *state = Md5::new(),
            Self::Sha1(state) => *state = Sha1::new(),
            Self::Sha256(state) => {
                state.state = [0; 8];
                state.buffer = [0; SHA256_BLOCK_LENGTH];
                state.buffer_len = 0;
                state.bit_len = 0;
            }
            Self::Sha384(state) | Self::Sha512(state) => {
                state.state = [0; 8];
                state.buffer = [0; SHA512_BLOCK_LENGTH];
                state.buffer_len = 0;
                state.bit_len = 0;
            }
        }
    }
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma0_256(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn big_sigma1_256(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn small_sigma0_256(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn small_sigma1_256(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn ch64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

fn maj64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma0_512(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn big_sigma1_512(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn small_sigma0_512(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn small_sigma1_512(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_LENGTH]) {
    let mut w = [0u32; 64];

    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        w[i] = small_sigma1_256(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0_256(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1_256(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0_256(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn sha512_compress(state: &mut [u64; 8], block: &[u8; SHA512_BLOCK_LENGTH]) {
    let mut w = [0u64; 80];

    for (i, chunk) in block.chunks_exact(8).enumerate() {
        w[i] = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }
    for i in 16..80 {
        w[i] = small_sigma1_512(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0_512(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..80 {
        let t1 = h
            .wrapping_add(big_sigma1_512(e))
            .wrapping_add(ch64(e, f, g))
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0_512(a).wrapping_add(maj64(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::{
        DigestState, MD5_DIGEST_LENGTH, SHA1_DIGEST_LENGTH, SHA256_DIGEST_LENGTH,
        SHA384_DIGEST_LENGTH, SHA512_DIGEST_LENGTH,
    };

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn md5_matches_known_vector() {
        let mut out = [0u8; MD5_DIGEST_LENGTH];
        let mut state = DigestState::new(0).unwrap();
        state.update(b"abc");
        state.finalize_to(&mut out).unwrap();
        assert_eq!(hex(&out), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn sha1_matches_known_vector() {
        let mut out = [0u8; SHA1_DIGEST_LENGTH];
        let mut state = DigestState::new(1).unwrap();
        state.update(b"abc");
        state.finalize_to(&mut out).unwrap();
        assert_eq!(hex(&out), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha256_matches_known_vector() {
        let mut out = [0u8; SHA256_DIGEST_LENGTH];
        let mut state = DigestState::new(2).unwrap();
        state.update(b"abc");
        state.finalize_to(&mut out).unwrap();
        assert_eq!(
            hex(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha384_matches_known_vector() {
        let mut out = [0u8; SHA384_DIGEST_LENGTH];
        let mut state = DigestState::new(3).unwrap();
        state.update(b"abc");
        state.finalize_to(&mut out).unwrap();
        assert_eq!(
            hex(&out),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
             1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_matches_known_vector() {
        let mut out = [0u8; SHA512_DIGEST_LENGTH];
        let mut state = DigestState::new(4).unwrap();
        state.update(b"abc");
        state.finalize_to(&mut out).unwrap();
        assert_eq!(
            hex(&out),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2\
             0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn split_updates_match_single_update() {
        let mut one = [0u8; SHA256_DIGEST_LENGTH];
        let mut split = [0u8; SHA256_DIGEST_LENGTH];
        let mut state_one = DigestState::new(2).unwrap();
        let mut state_split = DigestState::new(2).unwrap();
        let msg = b"The quick brown fox jumps over the lazy dog";

        state_one.update(msg);
        state_one.finalize_to(&mut one).unwrap();

        state_split.update(&msg[..10]);
        state_split.update(&msg[10..30]);
        state_split.update(&msg[30..]);
        state_split.finalize_to(&mut split).unwrap();

        assert_eq!(one, split);
    }

    #[test]
    fn cloned_state_preserves_partial_digest() {
        let mut original = DigestState::new(2).unwrap();
        let mut clone_out = [0u8; SHA256_DIGEST_LENGTH];
        let mut original_out = [0u8; SHA256_DIGEST_LENGTH];

        original.update(b"prefix-");
        let mut cloned = original.clone();
        original.update(b"suffix");
        cloned.update(b"suffix");

        original.finalize_to(&mut original_out).unwrap();
        cloned.finalize_to(&mut clone_out).unwrap();

        assert_eq!(original_out, clone_out);
    }
}
