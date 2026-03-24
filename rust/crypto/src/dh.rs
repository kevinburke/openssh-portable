use core::ffi::{c_int, c_void};
use core::slice;

use num_bigint_dig::BigUint;
use rand_core::{OsRng, RngCore};

pub(crate) const OSSH_RUST_DH_GROUP14: c_int = 14;

const GROUP14_MODULUS_HEX: &str = concat!(
    "FFFFFFFF", "FFFFFFFF", "C90FDAA2", "2168C234", "C4C6628B", "80DC1CD1",
    "29024E08", "8A67CC74", "020BBEA6", "3B139B22", "514A0879", "8E3404DD",
    "EF9519B3", "CD3A431B", "302B0A6D", "F25F1437", "4FE1356D", "6D51C245",
    "E485B576", "625E7EC6", "F44C42E9", "A637ED6B", "0BFF5CB6", "F406B7ED",
    "EE386BFB", "5A899FA5", "AE9F2411", "7C4B1FE6", "49286651", "ECE45B3D",
    "C2007CB8", "A163BF05", "98DA4836", "1C55D39A", "69163FA8", "FD24CF5F",
    "83655D23", "DCA3AD96", "1C62F356", "208552BB", "9ED52907", "7096966D",
    "670C354E", "4ABC9804", "F1746C08", "CA18217C", "32905E46", "2E36CE3B",
    "E39E772C", "180E8603", "9B2783A2", "EC07A28F", "B5C55DF0", "6F4C52C9",
    "DE2BCBF6", "95581718", "3995497C", "EA956AE5", "15D22618", "98FA0510",
    "15728E5A", "8AACAA68", "FFFFFFFF", "FFFFFFFF",
);

struct RustDhGroup {
    modulus: BigUint,
    generator: BigUint,
    private_key: Option<BigUint>,
    public_key: Option<BigUint>,
    modulus_len: usize,
}

impl RustDhGroup {
    fn new(group_id: c_int) -> Option<Self> {
        match group_id {
            OSSH_RUST_DH_GROUP14 => {
                let modulus = decode_hex_biguint(GROUP14_MODULUS_HEX)?;
                let modulus_len = modulus.to_bytes_be().len();
                Some(Self {
                    modulus,
                    generator: BigUint::from(2u8),
                    private_key: None,
                    public_key: None,
                    modulus_len,
                })
            }
            _ => None,
        }
    }

    fn generate_key(&mut self, need_bits: usize) -> Result<(), ()> {
        let pbits = biguint_bits(&self.modulus);
        if need_bits == 0 || pbits <= 1 {
            return Err(());
        }
        let mut secret_bits = need_bits.checked_mul(2).ok_or(())?;
        if secret_bits < 256 {
            secret_bits = 256;
        }
        if secret_bits >= pbits {
            secret_bits = pbits - 1;
        }
        let upper_bound = &self.modulus - BigUint::from(1u8);
        let mut private_key = None;
        for _ in 0..128 {
            let candidate = random_biguint(secret_bits);
            if candidate > BigUint::from(1u8) && candidate < upper_bound {
                private_key = Some(candidate);
                break;
            }
        }
        let private_key = private_key.ok_or(())?;
        let public_key = self.generator.modpow(&private_key, &self.modulus);
        if !self.public_value_is_valid(&public_key) {
            return Err(());
        }
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        Ok(())
    }

    fn public_value_is_valid(&self, public_key: &BigUint) -> bool {
        let p_minus_one = &self.modulus - BigUint::from(1u8);
        if public_key <= &BigUint::from(1u8) || public_key >= &p_minus_one {
            return false;
        }
        bit_count(public_key) >= 4
    }

    fn export_public(&self, out: &mut [u8]) -> Result<(), ()> {
        if out.len() != self.modulus_len {
            return Err(());
        }
        let public_key = self.public_key.as_ref().ok_or(())?;
        write_biguint_padded(public_key, out)
    }

    fn shared_secret(&self, peer_public: &[u8], out: &mut [u8]) -> Result<(), ()> {
        if out.len() != self.modulus_len {
            return Err(());
        }
        let private_key = self.private_key.as_ref().ok_or(())?;
        let peer_public = BigUint::from_bytes_be(peer_public);
        if !self.public_value_is_valid(&peer_public) {
            return Err(());
        }
        let shared_secret = peer_public.modpow(private_key, &self.modulus);
        if shared_secret == BigUint::from(0u8) {
            return Err(());
        }
        write_biguint_padded(&shared_secret, out)
    }
}

fn decode_hex_biguint(hex: &str) -> Option<BigUint> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = nibble(chunk[0])?;
        let lo = nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(BigUint::from_bytes_be(&out))
}

fn biguint_bits(value: &BigUint) -> usize {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() {
        return 0;
    }
    (bytes.len() - 1) * 8 + (8 - bytes[0].leading_zeros() as usize)
}

fn bit_count(value: &BigUint) -> usize {
    value
        .to_bytes_be()
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum()
}

fn random_biguint(bits: usize) -> BigUint {
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    OsRng.fill_bytes(&mut bytes);
    let excess_bits = bytes.len() * 8 - bits;
    if excess_bits != 0 {
        bytes[0] &= 0xff >> excess_bits;
    }
    BigUint::from_bytes_be(&bytes)
}

fn write_biguint_padded(value: &BigUint, out: &mut [u8]) -> Result<(), ()> {
    let encoded = value.to_bytes_be();
    let out_len = out.len();
    if encoded.len() > out.len() {
        return Err(());
    }
    out.fill(0);
    out[out_len - encoded.len()..].copy_from_slice(&encoded);
    Ok(())
}

pub(crate) fn dh_group_new(group_id: c_int) -> *mut c_void {
    match RustDhGroup::new(group_id) {
        Some(group) => Box::into_raw(Box::new(group)).cast(),
        None => core::ptr::null_mut(),
    }
}

pub(crate) fn dh_generate_key(group: *mut c_void, need_bits: usize) -> c_int {
    if group.is_null() {
        return -1;
    }
    let group = unsafe { &mut *group.cast::<RustDhGroup>() };
    match group.generate_key(need_bits) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

pub(crate) fn dh_public_len(group: *const c_void) -> usize {
    if group.is_null() {
        return 0;
    }
    let group = unsafe { &*group.cast::<RustDhGroup>() };
    group.modulus_len
}

pub(crate) fn dh_export_public(group: *const c_void, out: *mut u8, out_len: usize) -> c_int {
    if group.is_null() || out.is_null() {
        return -1;
    }
    let group = unsafe { &*group.cast::<RustDhGroup>() };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match group.export_public(out) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

pub(crate) fn dh_shared_secret(
    group: *const c_void,
    peer_public: *const u8,
    peer_public_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if group.is_null() || peer_public.is_null() || out.is_null() {
        return -1;
    }
    let group = unsafe { &*group.cast::<RustDhGroup>() };
    let peer_public = unsafe { slice::from_raw_parts(peer_public, peer_public_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match group.shared_secret(peer_public, out) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

pub(crate) fn dh_free(group: *mut c_void) {
    if group.is_null() {
        return;
    }
    let mut group = unsafe { Box::from_raw(group.cast::<RustDhGroup>()) };
    group.private_key = None;
    group.public_key = None;
    drop(group);
}

#[cfg(test)]
mod tests {
    use super::{
        dh_export_public, dh_free, dh_generate_key, dh_group_new, dh_public_len, dh_shared_secret,
        OSSH_RUST_DH_GROUP14,
    };

    #[test]
    fn group14_roundtrip() {
        let client = dh_group_new(OSSH_RUST_DH_GROUP14);
        let server = dh_group_new(OSSH_RUST_DH_GROUP14);
        assert!(!client.is_null());
        assert!(!server.is_null());
        assert_eq!(0, dh_generate_key(client, 32));
        assert_eq!(0, dh_generate_key(server, 32));

        let client_len = dh_public_len(client);
        let server_len = dh_public_len(server);
        assert_eq!(client_len, server_len);

        let mut client_pub = vec![0u8; client_len];
        let mut server_pub = vec![0u8; server_len];
        assert_eq!(0, dh_export_public(client, client_pub.as_mut_ptr(), client_pub.len()));
        assert_eq!(0, dh_export_public(server, server_pub.as_mut_ptr(), server_pub.len()));

        let mut client_shared = vec![0u8; client_len];
        let mut server_shared = vec![0u8; server_len];
        assert_eq!(
            0,
            dh_shared_secret(
                client,
                server_pub.as_ptr(),
                server_pub.len(),
                client_shared.as_mut_ptr(),
                client_shared.len(),
            )
        );
        assert_eq!(
            0,
            dh_shared_secret(
                server,
                client_pub.as_ptr(),
                client_pub.len(),
                server_shared.as_mut_ptr(),
                server_shared.len(),
            )
        );
        assert_eq!(client_shared, server_shared);

        server_pub[0] = 0;
        server_pub[1] = 0;
        assert_eq!(
            0,
            dh_shared_secret(
                client,
                server_pub.as_ptr(),
                server_pub.len(),
                client_shared.as_mut_ptr(),
                client_shared.len(),
            )
        );

        dh_free(client);
        dh_free(server);
    }
}
