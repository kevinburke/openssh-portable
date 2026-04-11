use core::ffi::{c_int, c_void};
use core::slice;
use std::sync::OnceLock;

use num_bigint_dig::BigUint;
use rand_core::{OsRng, RngCore};

use crate::util::read_slice;

pub(crate) const OSSH_RUST_DH_GROUP14: c_int = 14;
pub(crate) const OSSH_RUST_DH_GROUP16: c_int = 16;
pub(crate) const OSSH_RUST_DH_GROUP18: c_int = 18;

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

const GROUP16_MODULUS_HEX: &str = concat!(
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
    "15728E5A", "8AAAC42D", "AD33170D", "04507A33", "A85521AB", "DF1CBA64",
    "ECFB8504", "58DBEF0A", "8AEA7157", "5D060C7D", "B3970F85", "A6E1E4C7",
    "ABF5AE8C", "DB0933D7", "1E8C94E0", "4A25619D", "CEE3D226", "1AD2EE6B",
    "F12FFA06", "D98A0864", "D8760273", "3EC86A64", "521F2B18", "177B200C",
    "BBE11757", "7A615D6C", "770988C0", "BAD946E2", "08E24FA0", "74E5AB31",
    "43DB5BFC", "E0FD108E", "4B82D120", "A9210801", "1A723C12", "A787E6D7",
    "88719A10", "BDBA5B26", "99C32718", "6AF4E23C", "1A946834", "B6150BDA",
    "2583E9CA", "2AD44CE8", "DBBBC2DB", "04DE8EF9", "2E8EFC14", "1FBECAA6",
    "287C5947", "4E6BC05D", "99B2964F", "A090C3A2", "233BA186", "515BE7ED",
    "1F612970", "CEE2D7AF", "B81BDD76", "2170481C", "D0069127", "D5B05AA9",
    "93B4EA98", "8D8FDDC1", "86FFB7DC", "90A6C08F", "4DF435C9", "34063199",
    "FFFFFFFF", "FFFFFFFF",
);

const GROUP18_MODULUS_HEX: &str = concat!(
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
    "15728E5A", "8AAAC42D", "AD33170D", "04507A33", "A85521AB", "DF1CBA64",
    "ECFB8504", "58DBEF0A", "8AEA7157", "5D060C7D", "B3970F85", "A6E1E4C7",
    "ABF5AE8C", "DB0933D7", "1E8C94E0", "4A25619D", "CEE3D226", "1AD2EE6B",
    "F12FFA06", "D98A0864", "D8760273", "3EC86A64", "521F2B18", "177B200C",
    "BBE11757", "7A615D6C", "770988C0", "BAD946E2", "08E24FA0", "74E5AB31",
    "43DB5BFC", "E0FD108E", "4B82D120", "A9210801", "1A723C12", "A787E6D7",
    "88719A10", "BDBA5B26", "99C32718", "6AF4E23C", "1A946834", "B6150BDA",
    "2583E9CA", "2AD44CE8", "DBBBC2DB", "04DE8EF9", "2E8EFC14", "1FBECAA6",
    "287C5947", "4E6BC05D", "99B2964F", "A090C3A2", "233BA186", "515BE7ED",
    "1F612970", "CEE2D7AF", "B81BDD76", "2170481C", "D0069127", "D5B05AA9",
    "93B4EA98", "8D8FDDC1", "86FFB7DC", "90A6C08F", "4DF435C9", "34028492",
    "36C3FAB4", "D27C7026", "C1D4DCB2", "602646DE", "C9751E76", "3DBA37BD",
    "F8FF9406", "AD9E530E", "E5DB382F", "413001AE", "B06A53ED", "9027D831",
    "179727B0", "865A8918", "DA3EDBEB", "CF9B14ED", "44CE6CBA", "CED4BB1B",
    "DB7F1447", "E6CC254B", "33205151", "2BD7AF42", "6FB8F401", "378CD2BF",
    "5983CA01", "C64B92EC", "F032EA15", "D1721D03", "F482D7CE", "6E74FEF6",
    "D55E702F", "46980C82", "B5A84031", "900B1C9E", "59E7C97F", "BEC7E8F3",
    "23A97A7E", "36CC88BE", "0F1D45B7", "FF585AC5", "4BD407B2", "2B4154AA",
    "CC8F6D7E", "BF48E1D8", "14CC5ED2", "0F8037E0", "A79715EE", "F29BE328",
    "06A1D58B", "B7C5DA76", "F550AA3D", "8A1FBFF0", "EB19CCB1", "A313D55C",
    "DA56C9EC", "2EF29632", "387FE8D7", "6E3C0468", "043E8F66", "3F4860EE",
    "12BF2D5B", "0B7474D6", "E694F91E", "6DBE1159", "74A3926F", "12FEE5E4",
    "38777CB6", "A932DF8C", "D8BEC4D0", "73B931BA", "3BC832B6", "8D9DD300",
    "741FA7BF", "8AFC47ED", "2576F693", "6BA42466", "3AAB639C", "5AE4F568",
    "3423B474", "2BF1C978", "238F16CB", "E39D652D", "E3FDB8BE", "FC848AD9",
    "22222E04", "A4037C07", "13EB57A8", "1A23F0C7", "3473FC64", "6CEA306B",
    "4BCBC886", "2F8385DD", "FA9D4B7F", "A2C087E8", "79683303", "ED5BDD3A",
    "062B3CF5", "B3A278A6", "6D2A13F8", "3F44F82D", "DF310EE0", "74AB6A36",
    "4597E899", "A0255DC1", "64F31CC5", "0846851D", "F9AB4819", "5DED7EA1",
    "B1D510BD", "7EE74D73", "FAF36BC3", "1ECFA268", "359046F4", "EB879F92",
    "4009438B", "481C6CD7", "889A002E", "D5EE382B", "C9190DA6", "FC026E47",
    "9558E447", "5677E9AA", "9E3050E2", "765694DF", "C81F56E8", "80B96E71",
    "60C980DD", "98EDD3DF", "FFFFFFFF", "FFFFFFFF",
);

#[derive(Clone)]
struct RustDhGroup {
    modulus: BigUint,
    generator: BigUint,
    private_key: Option<BigUint>,
    public_key: Option<BigUint>,
    modulus_len: usize,
    modulus_bytes: Box<[u8]>,
    generator_bytes: Box<[u8]>,
}

impl RustDhGroup {
    fn from_parts(generator: BigUint, modulus: BigUint) -> Option<Self> {
        let modulus_bytes = modulus.to_bytes_be().into_boxed_slice();
        let generator_bytes = generator.to_bytes_be().into_boxed_slice();
        let modulus_len = modulus_bytes.len();
        if modulus_len == 0 || generator <= BigUint::from(1u8) || generator >= modulus {
            return None;
        }
        Some(Self {
            modulus,
            generator,
            private_key: None,
            public_key: None,
            modulus_len,
            modulus_bytes,
            generator_bytes,
        })
    }

    fn from_modulus_hex(modulus_hex: &str) -> Option<Self> {
        let modulus = decode_hex_biguint(modulus_hex)?;
        Self::from_parts(BigUint::from(2u8), modulus)
    }

    fn from_params(generator: &[u8], modulus: &[u8]) -> Option<Self> {
        if let Some(group) = standard_group_from_params(generator, modulus) {
            return Some(group.clone());
        }
        let generator = BigUint::from_bytes_be(generator);
        let modulus = BigUint::from_bytes_be(modulus);
        Self::from_parts(generator, modulus)
    }

    fn new(group_id: c_int) -> Option<Self> {
        match group_id {
            OSSH_RUST_DH_GROUP14 => Self::from_modulus_hex(GROUP14_MODULUS_HEX),
            OSSH_RUST_DH_GROUP16 => Self::from_modulus_hex(GROUP16_MODULUS_HEX),
            OSSH_RUST_DH_GROUP18 => Self::from_modulus_hex(GROUP18_MODULUS_HEX),
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

    fn export_modulus(&self, out: &mut [u8]) -> Result<(), ()> {
        if out.len() != self.modulus_len {
            return Err(());
        }
        out.copy_from_slice(self.modulus_bytes.as_ref());
        Ok(())
    }

    fn generator_len(&self) -> usize {
        self.generator_bytes.len()
    }

    fn export_generator(&self, out: &mut [u8]) -> Result<(), ()> {
        if self.generator_bytes.len() != out.len() {
            return Err(());
        }
        out.copy_from_slice(self.generator_bytes.as_ref());
        Ok(())
    }
}

fn standard_group_from_params(generator: &[u8], modulus: &[u8]) -> Option<&'static RustDhGroup> {
    let groups = [
        standard_group(OSSH_RUST_DH_GROUP14),
        standard_group(OSSH_RUST_DH_GROUP16),
        standard_group(OSSH_RUST_DH_GROUP18),
    ];

    groups.into_iter().find(|group| {
        generator == group.generator_bytes.as_ref() && modulus == group.modulus_bytes.as_ref()
    })
}

fn standard_group(group_id: c_int) -> &'static RustDhGroup {
    match group_id {
        OSSH_RUST_DH_GROUP14 => {
            static GROUP: OnceLock<RustDhGroup> = OnceLock::new();
            GROUP.get_or_init(|| RustDhGroup::new(OSSH_RUST_DH_GROUP14).expect("group14"))
        }
        OSSH_RUST_DH_GROUP16 => {
            static GROUP: OnceLock<RustDhGroup> = OnceLock::new();
            GROUP.get_or_init(|| RustDhGroup::new(OSSH_RUST_DH_GROUP16).expect("group16"))
        }
        OSSH_RUST_DH_GROUP18 => {
            static GROUP: OnceLock<RustDhGroup> = OnceLock::new();
            GROUP.get_or_init(|| RustDhGroup::new(OSSH_RUST_DH_GROUP18).expect("group18"))
        }
        _ => panic!("unsupported standard DH group"),
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

pub(crate) fn dh_group_from_params(
    generator: *const u8,
    generator_len: usize,
    modulus: *const u8,
    modulus_len: usize,
) -> *mut c_void {
    let Some(generator) = read_slice(generator, generator_len) else {
        return core::ptr::null_mut();
    };
    let Some(modulus) = read_slice(modulus, modulus_len) else {
        return core::ptr::null_mut();
    };
    match RustDhGroup::from_params(generator, modulus) {
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

pub(crate) fn dh_modulus_len(group: *const c_void) -> usize {
    if group.is_null() {
        return 0;
    }
    let group = unsafe { &*group.cast::<RustDhGroup>() };
    group.modulus_len
}

pub(crate) fn dh_export_modulus(group: *const c_void, out: *mut u8, out_len: usize) -> c_int {
    if group.is_null() || out.is_null() {
        return -1;
    }
    let group = unsafe { &*group.cast::<RustDhGroup>() };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match group.export_modulus(out) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

pub(crate) fn dh_generator_len(group: *const c_void) -> usize {
    if group.is_null() {
        return 0;
    }
    let group = unsafe { &*group.cast::<RustDhGroup>() };
    group.generator_len()
}

pub(crate) fn dh_export_generator(group: *const c_void, out: *mut u8, out_len: usize) -> c_int {
    if group.is_null() || out.is_null() {
        return -1;
    }
    let group = unsafe { &*group.cast::<RustDhGroup>() };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match group.export_generator(out) {
        Ok(()) => 0,
        Err(()) => -1,
    }
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
    use core::ffi::c_int;

    use super::{
        dh_export_generator, dh_export_modulus, dh_export_public, dh_free, dh_generate_key,
        dh_generator_len, dh_group_from_params, dh_group_new, dh_modulus_len, dh_public_len,
        dh_shared_secret, OSSH_RUST_DH_GROUP14, OSSH_RUST_DH_GROUP16, OSSH_RUST_DH_GROUP18,
    };

    fn dh_roundtrip(group_id: c_int) {
        let client = dh_group_new(group_id);
        let server = dh_group_new(group_id);
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

    #[test]
    fn group14_roundtrip() {
        dh_roundtrip(OSSH_RUST_DH_GROUP14);
    }

    #[test]
    fn group16_roundtrip() {
        dh_roundtrip(OSSH_RUST_DH_GROUP16);
    }

    #[test]
    fn group18_roundtrip() {
        dh_roundtrip(OSSH_RUST_DH_GROUP18);
    }

    #[test]
    fn construct_group_from_params() {
        let group = dh_group_new(OSSH_RUST_DH_GROUP14);
        assert!(!group.is_null());

        let mut modulus = vec![0u8; dh_modulus_len(group)];
        let mut generator = vec![0u8; dh_generator_len(group)];
        assert_eq!(0, dh_export_modulus(group, modulus.as_mut_ptr(), modulus.len()));
        assert_eq!(
            0,
            dh_export_generator(group, generator.as_mut_ptr(), generator.len())
        );
        dh_free(group);

        let parsed = dh_group_from_params(
            generator.as_ptr(),
            generator.len(),
            modulus.as_ptr(),
            modulus.len(),
        );
        assert!(!parsed.is_null());
        assert_eq!(0, dh_generate_key(parsed, 32));
        dh_free(parsed);
    }
}
