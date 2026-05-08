use core::ffi::{c_int, c_void};
use core::slice;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use poly1305::Poly1305;

use crate::util::{read_array, write_prefix};

pub(crate) const AES_BLOCK_SIZE: usize = 16;
const CHACHA_KEY_LENGTH: usize = 32;
const CHACHA_BLOCK_SIZE: usize = 64;
const CHACHA_NONCE_LENGTH: usize = 8;
const CHACHAPOLY_KEY_LENGTH: usize = 64;
const POLY1305_KEY_LENGTH: usize = 32;
const POLY1305_TAG_LENGTH: usize = 16;

enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

pub(crate) struct AesCtrState {
    cipher: AesCipher,
    ctr: [u8; AES_BLOCK_SIZE],
}

pub(crate) struct ChachaPolyState {
    main_key: [u8; CHACHA_KEY_LENGTH],
    header_key: [u8; CHACHA_KEY_LENGTH],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChachaPolyError {
    Invalid,
    Mac,
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
    pub(crate) fn new(key: &[u8], iv: [u8; AES_BLOCK_SIZE]) -> Option<Self> {
        Some(Self {
            cipher: AesCipher::new(key)?,
            ctr: iv,
        })
    }

    pub(crate) fn set_iv(&mut self, iv: [u8; AES_BLOCK_SIZE]) {
        self.ctr = iv;
    }

    pub(crate) fn get_iv(&self) -> [u8; AES_BLOCK_SIZE] {
        self.ctr
    }

    pub(crate) fn crypt(&mut self, src: *const u8, dst: *mut u8, len: usize) -> Result<(), ()> {
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
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
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

    pub(crate) fn crypt(
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
        let data_len = aadlen.checked_add(len).ok_or(ChachaPolyError::Invalid)?;
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
            let expected_tag =
                poly1305_auth(unsafe { slice::from_raw_parts(src, data_len) }, &poly_key);
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
            let tag = poly1305_auth(unsafe { slice::from_raw_parts(dest, data_len) }, &poly_key);
            unsafe {
                core::ptr::copy_nonoverlapping(tag.as_ptr(), dest.add(data_len), authlen);
            }
        }
        Ok(())
    }

    pub(crate) fn get_length(
        &self,
        seqnr: u32,
        cp: *const u8,
        len: usize,
    ) -> Result<u32, ChachaPolyError> {
        if len < 4 || cp.is_null() {
            return Err(ChachaPolyError::Invalid);
        }
        let mut buf = [0u8; 4];
        let nonce = (seqnr as u64).to_be_bytes();
        chacha20_xor(&self.header_key, &nonce, 0, cp, buf.as_mut_ptr(), buf.len())
            .map_err(|_| ChachaPolyError::Invalid)?;
        Ok(u32::from_be_bytes(buf))
    }

    pub(crate) fn scrub(&mut self) {
        self.main_key = [0; CHACHA_KEY_LENGTH];
        self.header_key = [0; CHACHA_KEY_LENGTH];
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
    fn read_le_u32(input: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ])
    }

    let constants = *b"expand 32-byte k";
    let mut state = [0u32; 16];
    let mut working = [0u32; 16];
    let mut out = [0u8; CHACHA_BLOCK_SIZE];

    state[0] = read_le_u32(&constants, 0);
    state[1] = read_le_u32(&constants, 4);
    state[2] = read_le_u32(&constants, 8);
    state[3] = read_le_u32(&constants, 12);
    for i in 0..8 {
        let start = i * 4;
        state[4 + i] = read_le_u32(key, start);
    }
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = read_le_u32(nonce, 0);
    state[15] = read_le_u32(nonce, 4);

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
    let Ok(mac) = Poly1305::new_from_slice(key) else {
        return [0u8; POLY1305_TAG_LENGTH];
    };
    let tag = mac.compute_unpadded(message);
    let mut out = [0u8; POLY1305_TAG_LENGTH];
    out.copy_from_slice(tag.as_slice());
    out
}

pub(crate) fn aesctr_init(
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

pub(crate) fn aesctr_set_iv(ctx: *mut c_void, iv: *const u8, iv_len: usize) -> c_int {
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

pub(crate) fn aesctr_get_iv(ctx: *const c_void, iv: *mut u8, iv_len: usize) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &*(ctx.cast::<AesCtrState>()) };
    write_prefix(iv, iv_len, &ctx.get_iv())
}

pub(crate) fn aesctr_crypt(ctx: *mut c_void, src: *const u8, dst: *mut u8, len: usize) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx.cast::<AesCtrState>()) };
    if ctx.crypt(src, dst, len).is_err() {
        return -1;
    }
    0
}

pub(crate) fn aesctr_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let _ = unsafe { Box::from_raw(ctx.cast::<AesCtrState>()) };
}

pub(crate) fn chachapoly_new(key: *const u8, key_len: usize) -> *mut c_void {
    if key.is_null() {
        return core::ptr::null_mut();
    }
    let key = unsafe { slice::from_raw_parts(key, key_len) };
    match ChachaPolyState::new(key) {
        Some(state) => Box::into_raw(Box::new(state)).cast(),
        None => core::ptr::null_mut(),
    }
}

pub(crate) fn chachapoly_crypt(
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

pub(crate) fn chachapoly_get_length(
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

pub(crate) fn chachapoly_free(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(ctx.cast::<ChachaPolyState>()) };
    boxed.scrub();
    drop(boxed);
}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;

    use super::{AesCtrState, ChachaPolyError, ChachaPolyState, AES_BLOCK_SIZE};

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
    fn chachapoly_randomized_roundtrips() {
        let mut rng = rand_core::OsRng;

        for seqnr in 0..24u32 {
            let payload_len = ((seqnr as usize) * 7) % 128;
            let mut key = [0u8; 64];
            let mut packet = vec![0u8; 4 + payload_len + 16];
            let mut enc = vec![0u8; packet.len()];
            let mut dec = vec![0u8; packet.len()];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut packet[4..4 + payload_len]);
            packet[0..4].copy_from_slice(&(payload_len as u32).to_be_bytes());

            let state = ChachaPolyState::new(&key).unwrap();
            state
                .crypt(
                    seqnr,
                    enc.as_mut_ptr(),
                    enc.len(),
                    packet.as_ptr(),
                    4 + payload_len,
                    payload_len as u32,
                    4,
                    16,
                    true,
                )
                .unwrap();
            state
                .crypt(
                    seqnr,
                    dec.as_mut_ptr(),
                    dec.len(),
                    enc.as_ptr(),
                    enc.len(),
                    payload_len as u32,
                    4,
                    16,
                    false,
                )
                .unwrap();
            assert_eq!(&dec[..4 + payload_len], &packet[..4 + payload_len]);

            let last = enc.len() - 1;
            enc[last] ^= 0x01;
            assert_eq!(
                state.crypt(
                    seqnr,
                    dec.as_mut_ptr(),
                    dec.len(),
                    enc.as_ptr(),
                    enc.len(),
                    payload_len as u32,
                    4,
                    16,
                    false,
                ),
                Err(ChachaPolyError::Mac)
            );
        }
    }

    #[test]
    fn aes128_ctr_nist_vector() {
        let key = decode_hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = decode_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
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

        state
            .crypt(plaintext.as_ptr(), out.as_mut_ptr(), plaintext.len())
            .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn aes192_ctr_nist_vector() {
        let key = decode_hex(
            "8e73b0f7da0e6452c810f32b809079e5\
             62f8ead2522c6b7b",
        );
        let iv: [u8; 16] = decode_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
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

        state
            .crypt(plaintext.as_ptr(), out.as_mut_ptr(), plaintext.len())
            .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn aes256_ctr_nist_vector() {
        let key = decode_hex(
            "603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4",
        );
        let iv: [u8; 16] = decode_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
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

        state
            .crypt(plaintext.as_ptr(), out.as_mut_ptr(), plaintext.len())
            .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn aesctr_randomized_chunking_roundtrips() {
        let mut rng = rand_core::OsRng;

        for &key_len in &[16usize, 24, 32] {
            for iter in 0..16usize {
                let msg_len = (iter * 19) % 257;
                let mut key = vec![0u8; key_len];
                let mut iv = [0u8; 16];
                let mut plaintext = vec![0u8; msg_len];
                let mut one_shot = vec![0u8; msg_len];
                let mut chunked = vec![0u8; msg_len];
                let mut roundtrip = vec![0u8; msg_len];
                rng.fill_bytes(&mut key);
                rng.fill_bytes(&mut iv);
                rng.fill_bytes(&mut plaintext);

                let mut state_one = AesCtrState::new(&key, iv).unwrap();
                state_one
                    .crypt(plaintext.as_ptr(), one_shot.as_mut_ptr(), plaintext.len())
                    .unwrap();

                let mut state_chunked = AesCtrState::new(&key, iv).unwrap();
                let mut offset = 0usize;
                while offset < plaintext.len() {
                    let remaining = plaintext.len() - offset;
                    let take = if remaining <= AES_BLOCK_SIZE {
                        remaining
                    } else {
                        let blocks = ((offset + iter) % 4) + 1;
                        core::cmp::min(blocks * AES_BLOCK_SIZE, remaining)
                    };
                    state_chunked
                        .crypt(
                            plaintext[offset..].as_ptr(),
                            chunked[offset..].as_mut_ptr(),
                            take,
                        )
                        .unwrap();
                    offset += take;
                }
                assert_eq!(one_shot, chunked);

                let mut state_dec = AesCtrState::new(&key, iv).unwrap();
                state_dec
                    .crypt(one_shot.as_ptr(), roundtrip.as_mut_ptr(), one_shot.len())
                    .unwrap();
                assert_eq!(roundtrip, plaintext);
            }
        }
    }
}
