use core::ffi::{c_char, c_int, c_void};
use core::slice;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use p521::{PublicKey as P521PublicKey, SecretKey as P521SecretKey};
use poly1305::Poly1305;
use rand_core::OsRng;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

const OSSH_RUST_CRYPTO_ABI_VERSION: u32 = 6;
const OSSH_RUST_ECDH_NISTP256: c_int = 1;
const OSSH_RUST_ECDH_NISTP384: c_int = 2;
const OSSH_RUST_ECDH_NISTP521: c_int = 3;
const SSH_DIGEST_SHA256: c_int = 2;
const SSH_DIGEST_SHA384: c_int = 3;
const SSH_DIGEST_SHA512: c_int = 4;

static BACKEND_LABEL: &[u8] = b"Rust crypto backend\0";
const SHA256_BLOCK_LENGTH: usize = 64;
const SHA256_DIGEST_LENGTH: usize = 32;
const SHA384_DIGEST_LENGTH: usize = 48;
const SHA512_BLOCK_LENGTH: usize = 128;
const SHA512_DIGEST_LENGTH: usize = 64;
const ED25519_SEED_LENGTH: usize = 32;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SECRET_KEY_LENGTH: usize = 64;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const CURVE25519_KEY_LENGTH: usize = 32;
const ECDH_NISTP256_SECRET_LENGTH: usize = 32;
const ECDH_NISTP256_PUBLIC_LENGTH: usize = 65;
const ECDH_NISTP384_SECRET_LENGTH: usize = 48;
const ECDH_NISTP384_PUBLIC_LENGTH: usize = 97;
const ECDH_NISTP521_SECRET_LENGTH: usize = 66;
const ECDH_NISTP521_PUBLIC_LENGTH: usize = 133;
const AES_BLOCK_SIZE: usize = 16;
const CHACHA_KEY_LENGTH: usize = 32;
const CHACHA_BLOCK_SIZE: usize = 64;
const CHACHA_NONCE_LENGTH: usize = 8;
const CHACHAPOLY_KEY_LENGTH: usize = 64;
const POLY1305_KEY_LENGTH: usize = 32;
const POLY1305_TAG_LENGTH: usize = 16;

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
struct Sha256State {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_LENGTH],
    buffer_len: usize,
    bit_len: u64,
}

#[derive(Clone)]
struct Sha512State {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_LENGTH],
    buffer_len: usize,
    bit_len: u128,
}

#[derive(Clone)]
enum DigestState {
    Sha256(Sha256State),
    Sha384(Sha512State),
    Sha512(Sha512State),
}

enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

struct AesCtrState {
    cipher: AesCipher,
    ctr: [u8; AES_BLOCK_SIZE],
}

struct ChachaPolyState {
    main_key: [u8; CHACHA_KEY_LENGTH],
    header_key: [u8; CHACHA_KEY_LENGTH],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChachaPolyError {
    Invalid,
    Mac,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EcdhCurve {
    NistP256,
    NistP384,
    NistP521,
}

impl Sha256State {
    fn new() -> Self {
        Self {
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
    fn new_sha384() -> Self {
        Self {
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
    fn new(alg: c_int) -> Option<Self> {
        match alg {
            SSH_DIGEST_SHA256 => Some(Self::Sha256(Sha256State::new())),
            SSH_DIGEST_SHA384 => Some(Self::Sha384(Sha512State::new_sha384())),
            SSH_DIGEST_SHA512 => Some(Self::Sha512(Sha512State::new_sha512())),
            _ => None,
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(state) => state.update(data),
            Self::Sha384(state) | Self::Sha512(state) => state.update(data),
        }
    }

    fn finalize_to(&self, out: &mut [u8]) -> Result<(), ()> {
        match self.clone() {
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

    fn scrub(&mut self) {
        match self {
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

impl AesCipher {
    fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Some(Self::Aes128(Aes128::new_from_slice(key).ok()?)),
            24 => Some(Self::Aes192(Aes192::new_from_slice(key).ok()?)),
            32 => Some(Self::Aes256(Aes256::new_from_slice(key).ok()?)),
            _ => None,
        }
    }

    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(block),
            Self::Aes192(cipher) => cipher.encrypt_block(block),
            Self::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }
}

impl AesCtrState {
    fn new(key: &[u8], iv: [u8; AES_BLOCK_SIZE]) -> Option<Self> {
        Some(Self {
            cipher: AesCipher::new(key)?,
            ctr: iv,
        })
    }

    fn set_iv(&mut self, iv: [u8; AES_BLOCK_SIZE]) {
        self.ctr = iv;
    }

    fn get_iv(&self) -> [u8; AES_BLOCK_SIZE] {
        self.ctr
    }

    fn crypt(&mut self, src: *const u8, dst: *mut u8, len: usize) -> Result<(), ()> {
        if len == 0 {
            return Ok(());
        }
        if src.is_null() || dst.is_null() {
            return Err(());
        }

        let mut offset = 0usize;
        while offset < len {
            let mut keystream = self.ctr;
            self.cipher.encrypt_block(&mut keystream);
            aesctr_inc(&mut self.ctr);

            let take = core::cmp::min(AES_BLOCK_SIZE, len - offset);
            for i in 0..take {
                unsafe {
                    *dst.add(offset + i) = *src.add(offset + i) ^ keystream[i];
                }
            }
            offset += take;
        }
        Ok(())
    }
}

impl ChachaPolyState {
    fn new(key: &[u8]) -> Option<Self> {
        if key.len() != CHACHAPOLY_KEY_LENGTH {
            return None;
        }
        let mut main_key = [0u8; CHACHA_KEY_LENGTH];
        let mut header_key = [0u8; CHACHA_KEY_LENGTH];
        main_key.copy_from_slice(&key[..CHACHA_KEY_LENGTH]);
        header_key.copy_from_slice(&key[CHACHA_KEY_LENGTH..]);
        Some(Self {
            main_key,
            header_key,
        })
    }

    fn crypt(
        &self,
        seqnr: u32,
        dest: *mut u8,
        dest_len: usize,
        src: *const u8,
        src_len: usize,
        len: u32,
        aadlen: u32,
        authlen: u32,
        do_encrypt: bool,
    ) -> Result<(), ChachaPolyError> {
        let aadlen = aadlen as usize;
        let len = len as usize;
        let authlen = authlen as usize;
        let nonce = (seqnr as u64).to_be_bytes();
        let data_len = aadlen
            .checked_add(len)
            .ok_or(ChachaPolyError::Invalid)?;
        let need_src = data_len
            .checked_add(if do_encrypt { 0 } else { authlen })
            .ok_or(ChachaPolyError::Invalid)?;
        let need_dest = data_len
            .checked_add(authlen)
            .ok_or(ChachaPolyError::Invalid)?;
        let mut poly_key = [0u8; POLY1305_KEY_LENGTH];

        if authlen != POLY1305_TAG_LENGTH
            || dest_len < need_dest
            || src_len < need_src
            || (need_dest != 0 && dest.is_null())
            || (need_src != 0 && src.is_null())
        {
            return Err(ChachaPolyError::Invalid);
        }

        chacha20_xor(
            &self.main_key,
            &nonce,
            0,
            poly_key.as_ptr(),
            poly_key.as_mut_ptr(),
            poly_key.len(),
        )
        .map_err(|_| ChachaPolyError::Invalid)?;

        if !do_encrypt {
            let expected_tag = poly1305_auth(
                unsafe { slice::from_raw_parts(src, data_len) },
                &poly_key,
            );
            let tag = unsafe { slice::from_raw_parts(src.add(data_len), authlen) };
            if !constant_time_eq(&expected_tag, tag) {
                return Err(ChachaPolyError::Mac);
            }
        }

        if aadlen != 0 {
            chacha20_xor(&self.header_key, &nonce, 0, src, dest, aadlen)
                .map_err(|_| ChachaPolyError::Invalid)?;
        }
        if len != 0 {
            chacha20_xor(
                &self.main_key,
                &nonce,
                1,
                unsafe { src.add(aadlen) },
                unsafe { dest.add(aadlen) },
                len,
            )
            .map_err(|_| ChachaPolyError::Invalid)?;
        }

        if do_encrypt {
            let tag = poly1305_auth(
                unsafe { slice::from_raw_parts(dest, data_len) },
                &poly_key,
            );
            unsafe {
                core::ptr::copy_nonoverlapping(tag.as_ptr(), dest.add(data_len), authlen);
            }
        }
        Ok(())
    }

    fn get_length(&self, seqnr: u32, cp: *const u8, len: usize) -> Result<u32, ChachaPolyError> {
        if len < 4 || cp.is_null() {
            return Err(ChachaPolyError::Invalid);
        }
        let mut buf = [0u8; 4];
        let nonce = (seqnr as u64).to_be_bytes();
        chacha20_xor(&self.header_key, &nonce, 0, cp, buf.as_mut_ptr(), buf.len())
            .map_err(|_| ChachaPolyError::Invalid)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn scrub(&mut self) {
        self.main_key = [0; CHACHA_KEY_LENGTH];
        self.header_key = [0; CHACHA_KEY_LENGTH];
    }
}

impl EcdhCurve {
    fn from_id(curve_id: c_int) -> Option<Self> {
        match curve_id {
            OSSH_RUST_ECDH_NISTP256 => Some(Self::NistP256),
            OSSH_RUST_ECDH_NISTP384 => Some(Self::NistP384),
            OSSH_RUST_ECDH_NISTP521 => Some(Self::NistP521),
            _ => None,
        }
    }

    fn secret_len(self) -> usize {
        match self {
            Self::NistP256 => ECDH_NISTP256_SECRET_LENGTH,
            Self::NistP384 => ECDH_NISTP384_SECRET_LENGTH,
            Self::NistP521 => ECDH_NISTP521_SECRET_LENGTH,
        }
    }

    fn public_len(self) -> usize {
        match self {
            Self::NistP256 => ECDH_NISTP256_PUBLIC_LENGTH,
            Self::NistP384 => ECDH_NISTP384_PUBLIC_LENGTH,
            Self::NistP521 => ECDH_NISTP521_PUBLIC_LENGTH,
        }
    }

    fn shared_len(self) -> usize {
        self.secret_len()
    }

    fn generate_keypair(self, secret_out: &mut [u8], public_out: &mut [u8]) -> Result<(), ()> {
        if secret_out.len() != self.secret_len() || public_out.len() != self.public_len() {
            return Err(());
        }
        match self {
            Self::NistP256 => {
                let secret = P256SecretKey::random(&mut OsRng);
                let public = secret.public_key().to_encoded_point(false);
                secret_out.copy_from_slice(secret.to_bytes().as_slice());
                public_out.copy_from_slice(public.as_bytes());
            }
            Self::NistP384 => {
                let secret = P384SecretKey::random(&mut OsRng);
                let public = secret.public_key().to_encoded_point(false);
                secret_out.copy_from_slice(secret.to_bytes().as_slice());
                public_out.copy_from_slice(public.as_bytes());
            }
            Self::NistP521 => {
                let secret = P521SecretKey::random(&mut OsRng);
                let public = secret.public_key().to_encoded_point(false);
                secret_out.copy_from_slice(secret.to_bytes().as_slice());
                public_out.copy_from_slice(public.as_bytes());
            }
        }
        Ok(())
    }

    fn shared_secret(
        self,
        secret_key: &[u8],
        public_key: &[u8],
        shared_out: &mut [u8],
    ) -> Result<(), ()> {
        if secret_key.len() != self.secret_len()
            || public_key.len() != self.public_len()
            || shared_out.len() != self.shared_len()
        {
            return Err(());
        }
        match self {
            Self::NistP256 => {
                let secret = P256SecretKey::from_slice(secret_key).map_err(|_| ())?;
                let public = P256PublicKey::from_sec1_bytes(public_key).map_err(|_| ())?;
                let shared =
                    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                shared_out.copy_from_slice(shared.raw_secret_bytes().as_slice());
            }
            Self::NistP384 => {
                let secret = P384SecretKey::from_slice(secret_key).map_err(|_| ())?;
                let public = P384PublicKey::from_sec1_bytes(public_key).map_err(|_| ())?;
                let shared =
                    p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                shared_out.copy_from_slice(shared.raw_secret_bytes().as_slice());
            }
            Self::NistP521 => {
                let secret = P521SecretKey::from_slice(secret_key).map_err(|_| ())?;
                let public = P521PublicKey::from_sec1_bytes(public_key).map_err(|_| ())?;
                let shared =
                    p521::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                shared_out.copy_from_slice(shared.raw_secret_bytes().as_slice());
            }
        }
        Ok(())
    }
}

fn aesctr_inc(ctr: &mut [u8; AES_BLOCK_SIZE]) {
    for byte in ctr.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&lhs, &rhs) in a.iter().zip(b.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

fn chacha20_xor(
    key: &[u8; CHACHA_KEY_LENGTH],
    nonce: &[u8; CHACHA_NONCE_LENGTH],
    mut counter: u64,
    src: *const u8,
    dst: *mut u8,
    len: usize,
) -> Result<(), ()> {
    if len == 0 {
        return Ok(());
    }
    if src.is_null() || dst.is_null() {
        return Err(());
    }

    let mut offset = 0usize;
    while offset < len {
        let keystream = chacha20_block(key, nonce, counter);
        let take = core::cmp::min(CHACHA_BLOCK_SIZE, len - offset);
        for i in 0..take {
            unsafe {
                *dst.add(offset + i) = *src.add(offset + i) ^ keystream[i];
            }
        }
        counter = counter.wrapping_add(1);
        offset += take;
    }
    Ok(())
}

fn chacha20_block(
    key: &[u8; CHACHA_KEY_LENGTH],
    nonce: &[u8; CHACHA_NONCE_LENGTH],
    counter: u64,
) -> [u8; CHACHA_BLOCK_SIZE] {
    let constants = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    let mut working = [0u32; 16];
    let mut out = [0u8; CHACHA_BLOCK_SIZE];

    state[0] = u32::from_le_bytes(constants[0..4].try_into().unwrap());
    state[1] = u32::from_le_bytes(constants[4..8].try_into().unwrap());
    state[2] = u32::from_le_bytes(constants[8..12].try_into().unwrap());
    state[3] = u32::from_le_bytes(constants[12..16].try_into().unwrap());
    for i in 0..8 {
        let start = i * 4;
        state[4 + i] = u32::from_le_bytes(key[start..start + 4].try_into().unwrap());
    }
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[15] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());

    working.copy_from_slice(&state);
    for _ in 0..10 {
        quarterround_state(&mut working, 0, 4, 8, 12);
        quarterround_state(&mut working, 1, 5, 9, 13);
        quarterround_state(&mut working, 2, 6, 10, 14);
        quarterround_state(&mut working, 3, 7, 11, 15);
        quarterround_state(&mut working, 0, 5, 10, 15);
        quarterround_state(&mut working, 1, 6, 11, 12);
        quarterround_state(&mut working, 2, 7, 8, 13);
        quarterround_state(&mut working, 3, 4, 9, 14);
    }

    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&working[i].to_le_bytes());
    }
    out
}

fn quarterround_state(state: &mut [u32; 16], ai: usize, bi: usize, ci: usize, di: usize) {
    let mut a = state[ai];
    let mut b = state[bi];
    let mut c = state[ci];
    let mut d = state[di];

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    state[ai] = a;
    state[bi] = b;
    state[ci] = c;
    state[di] = d;
}

fn poly1305_auth(message: &[u8], key: &[u8; POLY1305_KEY_LENGTH]) -> [u8; POLY1305_TAG_LENGTH] {
    let tag = Poly1305::new_from_slice(key)
        .unwrap()
        .compute_unpadded(message);
    let mut out = [0u8; POLY1305_TAG_LENGTH];
    out.copy_from_slice(tag.as_slice());
    out
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

fn read_array<const N: usize>(ptr: *const u8, len: usize) -> Option<[u8; N]> {
    if ptr.is_null() || len != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(unsafe { slice::from_raw_parts(ptr, N) });
    Some(out)
}

fn write_prefix(out: *mut u8, out_len: usize, bytes: &[u8]) -> c_int {
    if out.is_null() || out_len < bytes.len() {
        return -1;
    }
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    out[..bytes.len()].copy_from_slice(bytes);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_crypto_abi_version() -> u32 {
    OSSH_RUST_CRYPTO_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_crypto_backend_label() -> *const c_char {
    BACKEND_LABEL.as_ptr().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_start(alg: c_int) -> *mut c_void {
    match DigestState::new(alg) {
        Some(state) => Box::into_raw(Box::new(state)).cast(),
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_copy(ctx: *const c_void) -> *mut c_void {
    if ctx.is_null() {
        return core::ptr::null_mut();
    }
    let ctx = unsafe { &*(ctx.cast::<DigestState>()) };
    Box::into_raw(Box::new(ctx.clone())).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_update(
    ctx: *mut c_void,
    data: *const u8,
    len: usize,
) -> c_int {
    if ctx.is_null() || (data.is_null() && len != 0) {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<DigestState>()) };
    let data = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    };
    ctx.update(data);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_final(
    ctx: *const c_void,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if ctx.is_null() || out.is_null() {
        return -1;
    }
    let ctx = unsafe { &*(ctx.cast::<DigestState>()) };
    let out = if out_len == 0 {
        &mut []
    } else {
        unsafe { slice::from_raw_parts_mut(out, out_len) }
    };
    if ctx.finalize_to(out).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_digest_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(ctx.cast::<DigestState>()) };
    boxed.scrub();
    drop(boxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ed25519_public_from_seed(
    seed: *const u8,
    seed_len: usize,
    public_key: *mut u8,
    public_key_len: usize,
) -> c_int {
    let seed = match read_array::<ED25519_SEED_LENGTH>(seed, seed_len) {
        Some(seed) => seed,
        None => return -1,
    };
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    write_prefix(public_key, public_key_len, &verifying_key.to_bytes())
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ed25519_sign(
    sig: *mut u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
) -> c_int {
    let secret_key = match read_array::<ED25519_SECRET_KEY_LENGTH>(secret_key, secret_key_len) {
        Some(secret_key) => secret_key,
        None => return -1,
    };
    let msg = if msg_len == 0 {
        &[]
    } else if msg.is_null() {
        return -1;
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    let mut seed = [0u8; ED25519_SEED_LENGTH];
    seed.copy_from_slice(&secret_key[..ED25519_SEED_LENGTH]);

    let signing_key = SigningKey::from_bytes(&seed);
    let derived_public = signing_key.verifying_key().to_bytes();
    if derived_public != secret_key[ED25519_SEED_LENGTH..] {
        return -1;
    }

    let signature = signing_key.sign(msg).to_bytes();
    write_prefix(sig, sig_len, &signature)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ed25519_verify(
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> c_int {
    let sig = match read_array::<ED25519_SIGNATURE_LENGTH>(sig, sig_len) {
        Some(sig) => sig,
        None => return -1,
    };
    let public_key = match read_array::<ED25519_PUBLIC_KEY_LENGTH>(public_key, public_key_len) {
        Some(public_key) => public_key,
        None => return -1,
    };
    let msg = if msg_len == 0 {
        &[]
    } else if msg.is_null() {
        return -1;
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key) {
        Ok(verifying_key) => verifying_key,
        Err(_) => return -1,
    };
    let signature = Signature::from_bytes(&sig);
    if verifying_key.verify_strict(msg, &signature).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_curve25519_public_from_secret(
    public_key: *mut u8,
    public_key_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
) -> c_int {
    let secret_key = match read_array::<CURVE25519_KEY_LENGTH>(secret_key, secret_key_len) {
        Some(secret_key) => secret_key,
        None => return -1,
    };
    let public = x25519(secret_key, X25519_BASEPOINT_BYTES);
    write_prefix(public_key, public_key_len, &public)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_curve25519_shared_secret(
    shared_secret: *mut u8,
    shared_secret_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> c_int {
    let secret_key = match read_array::<CURVE25519_KEY_LENGTH>(secret_key, secret_key_len) {
        Some(secret_key) => secret_key,
        None => return -1,
    };
    let public_key = match read_array::<CURVE25519_KEY_LENGTH>(public_key, public_key_len) {
        Some(public_key) => public_key,
        None => return -1,
    };
    let shared = x25519(secret_key, public_key);
    write_prefix(shared_secret, shared_secret_len, &shared)
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdh_keypair(
    curve_id: c_int,
    secret_key: *mut u8,
    secret_key_len: usize,
    public_key: *mut u8,
    public_key_len: usize,
) -> c_int {
    if secret_key.is_null() || public_key.is_null() {
        return -1;
    }
    let curve = match EcdhCurve::from_id(curve_id) {
        Some(curve) => curve,
        None => return -1,
    };
    if secret_key_len != curve.secret_len() || public_key_len != curve.public_len() {
        return -1;
    }
    let secret_key = unsafe { slice::from_raw_parts_mut(secret_key, secret_key_len) };
    let public_key = unsafe { slice::from_raw_parts_mut(public_key, public_key_len) };
    if curve.generate_keypair(secret_key, public_key).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_ecdh_shared_secret(
    curve_id: c_int,
    secret_key: *const u8,
    secret_key_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    shared_secret: *mut u8,
    shared_secret_len: usize,
) -> c_int {
    if secret_key.is_null() || public_key.is_null() || shared_secret.is_null() {
        return -1;
    }
    let curve = match EcdhCurve::from_id(curve_id) {
        Some(curve) => curve,
        None => return -1,
    };
    if secret_key_len != curve.secret_len()
        || public_key_len != curve.public_len()
        || shared_secret_len != curve.shared_len()
    {
        return -1;
    }
    let secret_key = unsafe { slice::from_raw_parts(secret_key, secret_key_len) };
    let public_key = unsafe { slice::from_raw_parts(public_key, public_key_len) };
    let shared_secret = unsafe { slice::from_raw_parts_mut(shared_secret, shared_secret_len) };
    if curve
        .shared_secret(secret_key, public_key, shared_secret)
        .is_err()
    {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_init(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
) -> *mut c_void {
    if key.is_null() {
        return core::ptr::null_mut();
    }
    let key = unsafe { slice::from_raw_parts(key, key_len) };
    let iv = match read_array::<AES_BLOCK_SIZE>(iv, iv_len) {
        Some(iv) => iv,
        None => return core::ptr::null_mut(),
    };
    match AesCtrState::new(key, iv) {
        Some(state) => Box::into_raw(Box::new(state)).cast(),
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_set_iv(
    ctx: *mut c_void,
    iv: *const u8,
    iv_len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let iv = match read_array::<AES_BLOCK_SIZE>(iv, iv_len) {
        Some(iv) => iv,
        None => return -1,
    };
    let ctx = unsafe { &mut *(ctx.cast::<AesCtrState>()) };
    ctx.set_iv(iv);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_get_iv(
    ctx: *const c_void,
    iv: *mut u8,
    iv_len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*(ctx.cast::<AesCtrState>()) };
    write_prefix(iv, iv_len, &ctx.get_iv())
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_crypt(
    ctx: *mut c_void,
    src: *const u8,
    dst: *mut u8,
    len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<AesCtrState>()) };
    if ctx.crypt(src, dst, len).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_aesctr_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let _ = unsafe { Box::from_raw(ctx.cast::<AesCtrState>()) };
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_new(
    key: *const u8,
    key_len: usize,
) -> *mut c_void {
    if key.is_null() {
        return core::ptr::null_mut();
    }
    let key = unsafe { slice::from_raw_parts(key, key_len) };
    match ChachaPolyState::new(key) {
        Some(state) => Box::into_raw(Box::new(state)).cast(),
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_crypt(
    ctx: *mut c_void,
    seqnr: u32,
    dest: *mut u8,
    dest_len: usize,
    src: *const u8,
    src_len: usize,
    len: u32,
    aadlen: u32,
    authlen: u32,
    do_encrypt: c_int,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*(ctx.cast::<ChachaPolyState>()) };
    match ctx.crypt(
        seqnr,
        dest,
        dest_len,
        src,
        src_len,
        len,
        aadlen,
        authlen,
        do_encrypt != 0,
    ) {
        Ok(()) => 0,
        Err(ChachaPolyError::Mac) => 1,
        Err(ChachaPolyError::Invalid) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_get_length(
    ctx: *mut c_void,
    plenp: *mut u32,
    seqnr: u32,
    cp: *const u8,
    len: usize,
) -> c_int {
    if ctx.is_null() || plenp.is_null() {
        return -1;
    }
    let ctx = unsafe { &*(ctx.cast::<ChachaPolyState>()) };
    match ctx.get_length(seqnr, cp, len) {
        Ok(plen) => {
            unsafe {
                *plenp = plen;
            }
            0
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_chachapoly_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(ctx.cast::<ChachaPolyState>()) };
    boxed.scrub();
    drop(boxed);
}

#[cfg(test)]
mod tests {
    use super::{
        x25519, ossh_rust_ecdh_keypair, ossh_rust_ecdh_shared_secret,
        AesCtrState, ChachaPolyError, ChachaPolyState, DigestState,
        Signature, SigningKey, VerifyingKey, X25519_BASEPOINT_BYTES,
        OSSH_RUST_ECDH_NISTP256, OSSH_RUST_ECDH_NISTP384,
        OSSH_RUST_ECDH_NISTP521, SHA256_DIGEST_LENGTH,
        SHA384_DIGEST_LENGTH, SHA512_DIGEST_LENGTH,
    };
    use ed25519_dalek::Signer;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let input: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();

        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((hi << 4) | lo) as u8);
        }
        out
    }

    fn assert_nist_ecdh_roundtrip(
        curve_id: i32,
        secret_len: usize,
        public_len: usize,
        shared_len: usize,
    ) {
        let mut alice_secret = vec![0u8; secret_len];
        let mut alice_public = vec![0u8; public_len];
        let mut bob_secret = vec![0u8; secret_len];
        let mut bob_public = vec![0u8; public_len];
        let mut alice_shared = vec![0u8; shared_len];
        let mut bob_shared = vec![0u8; shared_len];

        assert_eq!(
            ossh_rust_ecdh_keypair(
                curve_id,
                alice_secret.as_mut_ptr(),
                alice_secret.len(),
                alice_public.as_mut_ptr(),
                alice_public.len(),
            ),
            0
        );
        assert_eq!(
            ossh_rust_ecdh_keypair(
                curve_id,
                bob_secret.as_mut_ptr(),
                bob_secret.len(),
                bob_public.as_mut_ptr(),
                bob_public.len(),
            ),
            0
        );
        assert_eq!(
            ossh_rust_ecdh_shared_secret(
                curve_id,
                alice_secret.as_ptr(),
                alice_secret.len(),
                bob_public.as_ptr(),
                bob_public.len(),
                alice_shared.as_mut_ptr(),
                alice_shared.len(),
            ),
            0
        );
        assert_eq!(
            ossh_rust_ecdh_shared_secret(
                curve_id,
                bob_secret.as_ptr(),
                bob_secret.len(),
                alice_public.as_ptr(),
                alice_public.len(),
                bob_shared.as_mut_ptr(),
                bob_shared.len(),
            ),
            0
        );
        assert_eq!(alice_shared, bob_shared);
        assert!(alice_shared.iter().any(|byte| *byte != 0));
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

    #[test]
    fn ed25519_rfc8032_vector() {
        let seed = decode_hex(
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
        );
        let public = decode_hex(
            "d75a980182b10ab7d54bfed3c964073a\
             0ee172f3daa62325af021a68f707511a",
        );
        let signature = decode_hex(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        );

        let signing_key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
        let verifying_key = VerifyingKey::from_bytes(public.as_slice().try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(signature.as_slice().try_into().unwrap());

        assert_eq!(signing_key.verifying_key().to_bytes().as_slice(), public.as_slice());
        assert_eq!(signing_key.sign(&[]).to_bytes().as_slice(), signature.as_slice());
        assert!(verifying_key.verify_strict(&[], &sig).is_ok());
    }

    #[test]
    fn x25519_rfc7748_vector() {
        let alice_secret: [u8; 32] = decode_hex(
            "77076d0a7318a57d3c16c17251b26645\
             df4c2f87ebc0992ab177fba51db92c2a",
        )
        .try_into()
        .unwrap();
        let bob_secret: [u8; 32] = decode_hex(
            "5dab087e624a8a4b79e17f8b83800ee6\
             6f3bb1292618b6fd1c2f8b27ff88e0eb",
        )
        .try_into()
        .unwrap();
        let alice_public = decode_hex(
            "8520f0098930a754748b7ddcb43ef75a\
             0dbf3a0d26381af4eba4a98eaa9b4e6a",
        );
        let bob_public = decode_hex(
            "de9edb7d7b7dc1b4d35b61c2ece43537\
             3f8343c85b78674dadfc7e146f882b4f",
        );
        let shared = decode_hex(
            "4a5d9d5ba4ce2de1728e3bf480350f25\
             e07e21c947d19e3376f09b3c1e161742",
        );

        assert_eq!(x25519(alice_secret, X25519_BASEPOINT_BYTES).as_slice(), alice_public.as_slice());
        assert_eq!(x25519(bob_secret, X25519_BASEPOINT_BYTES).as_slice(), bob_public.as_slice());
        assert_eq!(x25519(alice_secret, bob_public.as_slice().try_into().unwrap()).as_slice(), shared.as_slice());
        assert_eq!(x25519(bob_secret, alice_public.as_slice().try_into().unwrap()).as_slice(), shared.as_slice());
    }

    #[test]
    fn nistp256_ecdh_roundtrip() {
        assert_nist_ecdh_roundtrip(OSSH_RUST_ECDH_NISTP256, 32, 65, 32);
    }

    #[test]
    fn nistp384_ecdh_roundtrip() {
        assert_nist_ecdh_roundtrip(OSSH_RUST_ECDH_NISTP384, 48, 97, 48);
    }

    #[test]
    fn nistp521_ecdh_roundtrip() {
        assert_nist_ecdh_roundtrip(OSSH_RUST_ECDH_NISTP521, 66, 133, 66);
    }

    #[test]
    fn chachapoly_matches_c_reference_vector() {
        let key: Vec<u8> = (0u8..64).collect();
        let mut src = vec![0u8; 4 + 16 + 16];
        let mut enc = vec![0u8; src.len()];
        let state = ChachaPolyState::new(&key).unwrap();

        src[3] = 0x10;
        for (i, byte) in src[4..20].iter_mut().enumerate() {
            *byte = 0xa0 + i as u8;
        }

        state
            .crypt(
                42,
                enc.as_mut_ptr(),
                enc.len(),
                src.as_ptr(),
                20,
                16,
                4,
                16,
                true,
            )
            .unwrap();
        assert_eq!(
            hex(&enc),
            "08ce98075ef00929de97eb5985c9d4c1a15c0660e269d46b90d8885841e874086a949866"
        );
        assert_eq!(state.get_length(42, enc.as_ptr(), 4).unwrap(), 16);
    }

    #[test]
    fn chachapoly_roundtrip_and_tag_verification() {
        let key: Vec<u8> = (0u8..64).rev().collect();
        let mut src = vec![0u8; 4 + 23 + 16];
        let mut enc = vec![0u8; src.len()];
        let mut dec = vec![0u8; src.len()];
        let state = ChachaPolyState::new(&key).unwrap();

        src[0..4].copy_from_slice(&23u32.to_be_bytes());
        for (i, byte) in src[4..27].iter_mut().enumerate() {
            *byte = 0x30 + i as u8;
        }

        state
            .crypt(
                7,
                enc.as_mut_ptr(),
                enc.len(),
                src.as_ptr(),
                27,
                23,
                4,
                16,
                true,
            )
            .unwrap();
        state
            .crypt(
                7,
                dec.as_mut_ptr(),
                dec.len(),
                enc.as_ptr(),
                enc.len(),
                23,
                4,
                16,
                false,
            )
            .unwrap();
        assert_eq!(&dec[..27], &src[..27]);

        enc[10] ^= 0x40;
        assert_eq!(
            state.crypt(
                7,
                dec.as_mut_ptr(),
                dec.len(),
                enc.as_ptr(),
                enc.len(),
                23,
                4,
                16,
                false,
            ),
            Err(ChachaPolyError::Mac)
        );
    }

    #[test]
    fn aes128_ctr_nist_vector() {
        let key = decode_hex(
            "2b7e151628aed2a6abf7158809cf4f3c",
        );
        let iv: [u8; 16] = decode_hex(
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .try_into()
        .unwrap();
        let plaintext = decode_hex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = decode_hex(
            "874d6191b620e3261bef6864990db6ce\
             9806f66b7970fdff8617187bb9fffdff\
             5ae4df3edbd5d35e5b4f09020db03eab\
             1e031dda2fbe03d1792170a0f3009cee",
        );
        let mut out = vec![0u8; plaintext.len()];
        let mut state = AesCtrState::new(&key, iv).unwrap();

        state.crypt(plaintext.as_ptr(), out.as_mut_ptr(), plaintext.len()).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn aes192_ctr_nist_vector() {
        let key = decode_hex(
            "8e73b0f7da0e6452c810f32b809079e5\
             62f8ead2522c6b7b",
        );
        let iv: [u8; 16] = decode_hex(
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .try_into()
        .unwrap();
        let plaintext = decode_hex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = decode_hex(
            "1abc932417521ca24f2b0459fe7e6e0b\
             090339ec0aa6faefd5ccc2c6f4ce8e94\
             1e36b26bd1ebc670d1bd1d665620abf7\
             4f78a7f6d29809585a97daec58c6b050",
        );
        let mut out = vec![0u8; plaintext.len()];
        let mut state = AesCtrState::new(&key, iv).unwrap();

        state.crypt(plaintext.as_ptr(), out.as_mut_ptr(), plaintext.len()).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn aes256_ctr_nist_vector() {
        let key = decode_hex(
            "603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4",
        );
        let iv: [u8; 16] = decode_hex(
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .try_into()
        .unwrap();
        let plaintext = decode_hex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = decode_hex(
            "601ec313775789a5b7a7f504bbf3d228\
             f443e3ca4d62b59aca84e990cacaf5c5\
             2b0930daa23de94ce87017ba2d84988d\
             dfc9c58db67aada613c2dd08457941a6",
        );
        let mut out = vec![0u8; plaintext.len()];
        let mut state = AesCtrState::new(&key, iv).unwrap();

        state.crypt(plaintext.as_ptr(), out.as_mut_ptr(), plaintext.len()).unwrap();
        assert_eq!(out, expected);
    }
}
