use core::ffi::c_int;

use crate::digest::{
    MD5_DIGEST_LENGTH, SHA1_DIGEST_LENGTH, SHA256_DIGEST_LENGTH, SHA384_DIGEST_LENGTH,
    SHA512_DIGEST_LENGTH, SSH_DIGEST_MD5, SSH_DIGEST_SHA1, SSH_DIGEST_SHA256, SSH_DIGEST_SHA384,
    SSH_DIGEST_SHA512,
};
use crate::hmac::HmacState;
use crate::util::{read_slice, read_slice_mut};

pub(crate) struct PacketMacState {
    mac_len: usize,
    hmac: HmacState,
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

impl PacketMacState {
    pub(crate) fn new(alg: c_int, truncate_bits: c_int) -> Option<Self> {
        let digest_len = digest_len(alg)?;
        let mac_len = if truncate_bits == 0 {
            digest_len
        } else if truncate_bits < 0 || (truncate_bits as usize) % 8 != 0 {
            return None;
        } else {
            let truncated = (truncate_bits as usize) / 8;
            if truncated == 0 || truncated > digest_len {
                return None;
            }
            truncated
        };
        Some(Self {
            mac_len,
            hmac: HmacState::new(alg)?,
        })
    }

    pub(crate) fn init(&mut self, key: *const u8, key_len: usize) -> Result<(), ()> {
        self.hmac.init(key, key_len)
    }

    pub(crate) fn compute(
        &mut self,
        seqno: u32,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: usize,
    ) -> Result<(), ()> {
        let data = read_slice(data, data_len).ok_or(())?;
        let out = if out.is_null() && out_len == 0 {
            &mut []
        } else {
            read_slice_mut(out, out_len).ok_or(())?
        };
        let seqno = seqno.to_be_bytes();
        let mut digest = [0u8; SHA512_DIGEST_LENGTH];

        self.hmac.init(core::ptr::null(), 0)?;
        self.hmac.update(seqno.as_ptr(), seqno.len())?;
        self.hmac.update(data.as_ptr(), data.len())?;
        self.hmac.finalise(digest.as_mut_ptr(), digest.len())?;

        if !out.is_empty() {
            let copy_len = core::cmp::min(out.len(), self.mac_len);
            out[..copy_len].copy_from_slice(&digest[..copy_len]);
        }
        digest.fill(0);
        Ok(())
    }

    pub(crate) fn check(
        &mut self,
        seqno: u32,
        data: *const u8,
        data_len: usize,
        their_mac: *const u8,
        their_mac_len: usize,
    ) -> Result<bool, ()> {
        if their_mac_len < self.mac_len {
            return Err(());
        }
        let their_mac = read_slice(their_mac, their_mac_len).ok_or(())?;
        let mut ours = [0u8; SHA512_DIGEST_LENGTH];
        self.compute(seqno, data, data_len, ours.as_mut_ptr(), ours.len())?;
        let ok = ours[..self.mac_len] == their_mac[..self.mac_len];
        ours.fill(0);
        Ok(ok)
    }

    pub(crate) fn scrub(&mut self) {
        self.hmac.scrub();
    }
}

#[cfg(test)]
mod tests {
    use super::PacketMacState;
    use crate::digest::{SSH_DIGEST_SHA1, SSH_DIGEST_SHA256};
    use crate::hmac::HmacState;

    fn direct_hmac(alg: i32, key: &[u8], seqno: u32, data: &[u8], out_len: usize) -> Vec<u8> {
        let mut hmac = HmacState::new(alg).unwrap();
        let mut out = vec![0u8; out_len];
        let seq = seqno.to_be_bytes();
        hmac.init(key.as_ptr(), key.len()).unwrap();
        hmac.init(core::ptr::null(), 0).unwrap();
        hmac.update(seq.as_ptr(), seq.len()).unwrap();
        hmac.update(data.as_ptr(), data.len()).unwrap();
        hmac.finalise(out.as_mut_ptr(), out.len()).unwrap();
        out
    }

    #[test]
    fn packet_mac_matches_hmac_sequence() {
        let key = [0x0b_u8; 20];
        let data = b"packet payload";
        let seqno = 7_u32;
        let mut state = PacketMacState::new(SSH_DIGEST_SHA1, 0).unwrap();
        let mut out = [0u8; 20];

        state.init(key.as_ptr(), key.len()).unwrap();
        state
            .compute(
                seqno,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                out.len(),
            )
            .unwrap();

        assert_eq!(
            out.to_vec(),
            direct_hmac(SSH_DIGEST_SHA1, &key, seqno, data, 20)
        );
    }

    #[test]
    fn truncated_mac_checks_and_rejects_bitflips() {
        let key = [0x11_u8; 32];
        let data = b"ciphertext bytes";
        let seqno = 42_u32;
        let mut state = PacketMacState::new(SSH_DIGEST_SHA256, 96).unwrap();
        let mut out = [0u8; 32];

        state.init(key.as_ptr(), key.len()).unwrap();
        state
            .compute(
                seqno,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                out.len(),
            )
            .unwrap();
        assert!(state
            .check(seqno, data.as_ptr(), data.len(), out.as_ptr(), 12)
            .unwrap());
        out[0] ^= 1;
        assert!(!state
            .check(seqno, data.as_ptr(), data.len(), out.as_ptr(), 12)
            .unwrap());
    }
}
