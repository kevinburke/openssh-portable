use core::ffi::c_int;

use crate::digest::{
    DigestState, MD5_DIGEST_LENGTH, SHA1_DIGEST_LENGTH, SHA256_DIGEST_LENGTH, SHA384_DIGEST_LENGTH,
    SHA512_DIGEST_LENGTH, SSH_DIGEST_MD5, SSH_DIGEST_SHA1, SSH_DIGEST_SHA256, SSH_DIGEST_SHA384,
    SSH_DIGEST_SHA512,
};
use crate::util::{read_slice, read_slice_mut};

pub(crate) struct HmacState {
    alg: c_int,
    inner_base: DigestState,
    outer_base: DigestState,
    digest: DigestState,
    buf: Vec<u8>,
}

fn digest_len(alg: c_int) -> Option<usize> {
    match alg {
        SSH_DIGEST_MD5 => Some(MD5_DIGEST_LENGTH),
        SSH_DIGEST_SHA1 => Some(SHA1_DIGEST_LENGTH),
        SSH_DIGEST_SHA256 => Some(SHA256_DIGEST_LENGTH),
        SSH_DIGEST_SHA384 => Some(SHA384_DIGEST_LENGTH),
        SSH_DIGEST_SHA512 => Some(SHA512_DIGEST_LENGTH),
        _ => None,
    }
}

fn block_len(alg: c_int) -> Option<usize> {
    match alg {
        SSH_DIGEST_MD5 | SSH_DIGEST_SHA1 | SSH_DIGEST_SHA256 => Some(64),
        SSH_DIGEST_SHA384 | SSH_DIGEST_SHA512 => Some(128),
        _ => None,
    }
}

impl HmacState {
    pub(crate) fn new(alg: c_int) -> Option<Self> {
        let inner_base = DigestState::new(alg)?;
        let outer_base = DigestState::new(alg)?;
        let digest = DigestState::new(alg)?;
        let buf = vec![0u8; block_len(alg)?];
        Some(Self {
            alg,
            inner_base,
            outer_base,
            digest,
            buf,
        })
    }

    fn reset_bases(&mut self) -> Result<(), ()> {
        self.inner_base = DigestState::new(self.alg).ok_or(())?;
        self.outer_base = DigestState::new(self.alg).ok_or(())?;
        self.digest = DigestState::new(self.alg).ok_or(())?;
        self.buf.fill(0);
        Ok(())
    }

    pub(crate) fn init(&mut self, key: *const u8, key_len: usize) -> Result<(), ()> {
        if key_len != 0 || !key.is_null() {
            let key = read_slice(key, key_len).ok_or(())?;
            self.reset_bases()?;
            if key.len() <= self.buf.len() {
                self.buf[..key.len()].copy_from_slice(key);
            } else {
                let mut digest = DigestState::new(self.alg).ok_or(())?;
                let mut hashed = [0u8; SHA512_DIGEST_LENGTH];
                let hashed_len = digest_len(self.alg).ok_or(())?;
                digest.update(key);
                digest
                    .finalize_to(&mut hashed[..hashed_len])
                    .map_err(|_| ())?;
                self.buf[..hashed_len].copy_from_slice(&hashed[..hashed_len]);
            }
            for byte in &mut self.buf {
                *byte ^= 0x36;
            }
            self.inner_base.update(&self.buf);
            for byte in &mut self.buf {
                *byte ^= 0x36 ^ 0x5c;
            }
            self.outer_base.update(&self.buf);
            self.buf.fill(0);
        }
        self.digest = self.inner_base.clone();
        Ok(())
    }

    pub(crate) fn update(&mut self, data: *const u8, data_len: usize) -> Result<(), ()> {
        let data = read_slice(data, data_len).ok_or(())?;
        self.digest.update(data);
        Ok(())
    }

    pub(crate) fn finalise(&mut self, out: *mut u8, out_len: usize) -> Result<(), ()> {
        let out = read_slice_mut(out, out_len).ok_or(())?;
        let len = digest_len(self.alg).ok_or(())?;
        if out.len() < len {
            return Err(());
        }
        let mut inner = [0u8; SHA512_DIGEST_LENGTH];
        self.digest.finalize_to(&mut inner[..len]).map_err(|_| ())?;
        self.digest = self.outer_base.clone();
        self.digest.update(&inner[..len]);
        self.digest.finalize_to(out).map_err(|_| ())?;
        inner.fill(0);
        Ok(())
    }

    pub(crate) fn scrub(&mut self) {
        self.inner_base.scrub();
        self.outer_base.scrub();
        self.digest.scrub();
        self.buf.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::HmacState;
    use crate::digest::{SSH_DIGEST_MD5, SSH_DIGEST_SHA1, SSH_DIGEST_SHA256};

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn hmac_hex(alg: i32, key: &[u8], data: &[u8], out_len: usize) -> String {
        let mut state = HmacState::new(alg).unwrap();
        let mut out = vec![0u8; out_len];
        state.init(key.as_ptr(), key.len()).unwrap();
        state.update(data.as_ptr(), data.len()).unwrap();
        state.finalise(out.as_mut_ptr(), out.len()).unwrap();
        hex(&out)
    }

    #[test]
    fn md5_matches_rfc2104_vector() {
        let key = [0x0b_u8; 16];
        assert_eq!(
            hmac_hex(SSH_DIGEST_MD5, &key, b"Hi There", 16),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
    }

    #[test]
    fn sha1_matches_rfc2202_vector() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            hmac_hex(SSH_DIGEST_SHA1, &key, b"Hi There", 20),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn sha256_matches_rfc4231_vector() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            hmac_hex(SSH_DIGEST_SHA256, &key, b"Hi There", 32),
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn init_with_null_key_resets_digest_state() {
        let key = [0x0b_u8; 20];
        let mut state = HmacState::new(SSH_DIGEST_SHA1).unwrap();
        let mut first = [0u8; 20];
        let mut second = [0u8; 20];

        state.init(key.as_ptr(), key.len()).unwrap();
        state.update(b"abc".as_ptr(), 3).unwrap();
        state.finalise(first.as_mut_ptr(), first.len()).unwrap();

        state.init(core::ptr::null(), 0).unwrap();
        state.update(b"abc".as_ptr(), 3).unwrap();
        state.finalise(second.as_mut_ptr(), second.len()).unwrap();

        assert_eq!(first, second);
    }
}
