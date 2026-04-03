use core::ffi::{c_int, c_void};
use core::str;

use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::private_pem::{decrypt_encrypted_pkcs8_pem, decrypt_legacy_private_pem, LegacyPemLabel, PrivatePemError};
use crate::util::{read_slice, slice_ptr, write_prefix, SshWireReader};

const SSH_DIGEST_SHA1: c_int = 1;
const SSH_DIGEST_SHA256: c_int = 2;
const SSH_DIGEST_SHA512: c_int = 4;

const OSSH_RUST_RSA_COMPONENT_N: c_int = 1;
const OSSH_RUST_RSA_COMPONENT_E: c_int = 2;
const OSSH_RUST_RSA_COMPONENT_D: c_int = 3;
const OSSH_RUST_RSA_COMPONENT_IQMP: c_int = 4;
const OSSH_RUST_RSA_COMPONENT_P: c_int = 5;
const OSSH_RUST_RSA_COMPONENT_Q: c_int = 6;
const SSHKEY_PRIVATE_PEM: c_int = 1;
const SSHKEY_PRIVATE_PKCS8: c_int = 2;

// Mirrors SSHBUF_MAX_BIGNUM * 8 on the C side.
const OSSH_RUST_RSA_MAX_BITS: usize = 16_384;

struct RustRsaKey {
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
    private_exponent: Option<Vec<u8>>,
    iqmp: Option<Vec<u8>>,
    prime_p: Option<Vec<u8>>,
    prime_q: Option<Vec<u8>>,
    bits: usize,
}

impl RustRsaKey {
    fn from_public_key(public_key: RsaPublicKey) -> Self {
        Self {
            modulus: public_key.n().to_bytes_be(),
            public_exponent: public_key.e().to_bytes_be(),
            private_exponent: None,
            iqmp: None,
            prime_p: None,
            prime_q: None,
            bits: public_key.n().bits(),
        }
    }

    fn from_private_key(mut private_key: RsaPrivateKey) -> Result<Self, ()> {
        private_key.precompute().map_err(|_| ())?;
        let iqmp = private_key.crt_coefficient().ok_or(())?;
        Ok(Self {
            modulus: private_key.n().to_bytes_be(),
            public_exponent: private_key.e().to_bytes_be(),
            private_exponent: Some(private_key.d().to_bytes_be()),
            iqmp: Some(iqmp.to_bytes_be()),
            prime_p: Some(private_key.primes()[0].to_bytes_be()),
            prime_q: Some(private_key.primes()[1].to_bytes_be()),
            bits: private_key.n().bits(),
        })
    }

    fn public_key(&self) -> Result<RsaPublicKey, ()> {
        RsaPublicKey::new_with_max_size(
            BigUint::from_bytes_be(&self.modulus),
            BigUint::from_bytes_be(&self.public_exponent),
            OSSH_RUST_RSA_MAX_BITS,
        )
        .map_err(|_| ())
    }

    fn private_key(&self) -> Result<RsaPrivateKey, ()> {
        let d = self.private_exponent.as_ref().ok_or(())?;
        let p = self.prime_p.as_ref().ok_or(())?;
        let q = self.prime_q.as_ref().ok_or(())?;
        let mut private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&self.modulus),
            BigUint::from_bytes_be(&self.public_exponent),
            BigUint::from_bytes_be(d),
            vec![BigUint::from_bytes_be(p), BigUint::from_bytes_be(q)],
        )
        .map_err(|_| ())?;
        private_key.precompute().map_err(|_| ())?;
        if self
            .iqmp
            .as_ref()
            .zip(private_key.crt_coefficient())
            .map(|(iqmp, coeff)| coeff.to_bytes_be() == *iqmp)
            != Some(true)
        {
            return Err(());
        }
        Ok(private_key)
    }

    fn copy_public(&self) -> Self {
        Self {
            modulus: self.modulus.clone(),
            public_exponent: self.public_exponent.clone(),
            private_exponent: None,
            iqmp: None,
            prime_p: None,
            prime_q: None,
            bits: self.bits,
        }
    }

    fn component(&self, component: c_int) -> Option<&[u8]> {
        match component {
            OSSH_RUST_RSA_COMPONENT_N => Some(&self.modulus),
            OSSH_RUST_RSA_COMPONENT_E => Some(&self.public_exponent),
            OSSH_RUST_RSA_COMPONENT_D => self.private_exponent.as_deref(),
            OSSH_RUST_RSA_COMPONENT_IQMP => self.iqmp.as_deref(),
            OSSH_RUST_RSA_COMPONENT_P => self.prime_p.as_deref(),
            OSSH_RUST_RSA_COMPONENT_Q => self.prime_q.as_deref(),
            _ => None,
        }
    }

    fn sign_prehash(&self, hash_alg: c_int, digest: &[u8]) -> Result<Vec<u8>, ()> {
        let private_key = self.private_key()?;
        let signature = match hash_alg {
            SSH_DIGEST_SHA1 => private_key
                .sign_with_rng(&mut OsRng, Pkcs1v15Sign::new::<Sha1>(), digest)
                .map_err(|_| ())?,
            SSH_DIGEST_SHA256 => private_key
                .sign_with_rng(&mut OsRng, Pkcs1v15Sign::new::<Sha256>(), digest)
                .map_err(|_| ())?,
            SSH_DIGEST_SHA512 => private_key
                .sign_with_rng(&mut OsRng, Pkcs1v15Sign::new::<Sha512>(), digest)
                .map_err(|_| ())?,
            _ => return Err(()),
        };
        Ok(signature)
    }

    fn verify_prehash(&self, hash_alg: c_int, digest: &[u8], signature: &[u8]) -> Result<bool, ()> {
        let public_key = self.public_key()?;
        let valid = match hash_alg {
            SSH_DIGEST_SHA1 => public_key.verify(Pkcs1v15Sign::new::<Sha1>(), digest, signature),
            SSH_DIGEST_SHA256 => {
                public_key.verify(Pkcs1v15Sign::new::<Sha256>(), digest, signature)
            }
            SSH_DIGEST_SHA512 => {
                public_key.verify(Pkcs1v15Sign::new::<Sha512>(), digest, signature)
            }
            _ => return Err(()),
        }
        .is_ok();
        Ok(valid)
    }

    fn scrub(&mut self) {
        self.modulus.fill(0);
        self.public_exponent.fill(0);
        if let Some(private_exponent) = self.private_exponent.as_mut() {
            private_exponent.fill(0);
        }
        if let Some(iqmp) = self.iqmp.as_mut() {
            iqmp.fill(0);
        }
        if let Some(prime_p) = self.prime_p.as_mut() {
            prime_p.fill(0);
        }
        if let Some(prime_q) = self.prime_q.as_mut() {
            prime_q.fill(0);
        }
    }
}

fn key_ref<'a>(key: *const c_void) -> Option<&'a RustRsaKey> {
    if key.is_null() {
        None
    } else {
        Some(unsafe { &*(key.cast::<RustRsaKey>()) })
    }
}

pub(crate) fn rsa_generate(bits: usize) -> *mut c_void {
    match RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|_| ())
        .and_then(RustRsaKey::from_private_key)
    {
        Ok(key) => Box::into_raw(Box::new(key)).cast(),
        Err(_) => core::ptr::null_mut(),
    }
}

pub(crate) fn rsa_parse_public_blob(
    blob: *const u8,
    blob_len: usize,
    consumed_len: *mut usize,
) -> *mut c_void {
    let blob = match read_slice(blob, blob_len) {
        Some(blob) => blob,
        None => return core::ptr::null_mut(),
    };
    let mut reader = SshWireReader::new(blob);
    let exponent = match reader.get_mpint() {
        Some(exponent) => exponent,
        None => return core::ptr::null_mut(),
    };
    let modulus = match reader.get_mpint() {
        Some(modulus) => modulus,
        None => return core::ptr::null_mut(),
    };
    let key = rsa_from_public(
        slice_ptr(modulus),
        modulus.len(),
        slice_ptr(exponent),
        exponent.len(),
    );
    if !key.is_null() && !consumed_len.is_null() {
        unsafe { *consumed_len = reader.consumed() };
    }
    key
}

pub(crate) fn rsa_from_public(
    modulus: *const u8,
    modulus_len: usize,
    exponent: *const u8,
    exponent_len: usize,
) -> *mut c_void {
    let modulus = match read_slice(modulus, modulus_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let exponent = match read_slice(exponent, exponent_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let public_key = match RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(modulus),
        BigUint::from_bytes_be(exponent),
        OSSH_RUST_RSA_MAX_BITS,
    ) {
        Ok(key) => key,
        Err(_) => return core::ptr::null_mut(),
    };
    Box::into_raw(Box::new(RustRsaKey::from_public_key(public_key))).cast()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rsa_from_private(
    modulus: *const u8,
    modulus_len: usize,
    exponent: *const u8,
    exponent_len: usize,
    private_exponent: *const u8,
    private_exponent_len: usize,
    iqmp: *const u8,
    iqmp_len: usize,
    prime_p: *const u8,
    prime_p_len: usize,
    prime_q: *const u8,
    prime_q_len: usize,
) -> *mut c_void {
    let modulus = match read_slice(modulus, modulus_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let exponent = match read_slice(exponent, exponent_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let private_exponent = match read_slice(private_exponent, private_exponent_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let iqmp = match read_slice(iqmp, iqmp_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let prime_p = match read_slice(prime_p, prime_p_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let prime_q = match read_slice(prime_q, prime_q_len) {
        Some(bytes) => bytes,
        None => return core::ptr::null_mut(),
    };
    let mut private_key = match RsaPrivateKey::from_components(
        BigUint::from_bytes_be(modulus),
        BigUint::from_bytes_be(exponent),
        BigUint::from_bytes_be(private_exponent),
        vec![
            BigUint::from_bytes_be(prime_p),
            BigUint::from_bytes_be(prime_q),
        ],
    ) {
        Ok(key) => key,
        Err(_) => return core::ptr::null_mut(),
    };
    if private_key.precompute().is_err() {
        return core::ptr::null_mut();
    }
    if private_key
        .crt_coefficient()
        .map(|coeff| coeff.to_bytes_be() == iqmp)
        != Some(true)
    {
        return core::ptr::null_mut();
    }
    match RustRsaKey::from_private_key(private_key) {
        Ok(key) => Box::into_raw(Box::new(key)).cast(),
        Err(_) => core::ptr::null_mut(),
    }
}

pub(crate) fn rsa_copy_public(key: *const c_void) -> *mut c_void {
    match key_ref(key) {
        Some(key) => Box::into_raw(Box::new(key.copy_public())).cast(),
        None => core::ptr::null_mut(),
    }
}

pub(crate) fn rsa_equal_public(a: *const c_void, b: *const c_void) -> c_int {
    match (key_ref(a), key_ref(b)) {
        (Some(a), Some(b)) if a.modulus == b.modulus && a.public_exponent == b.public_exponent => 1,
        _ => 0,
    }
}

pub(crate) fn rsa_bits(key: *const c_void) -> usize {
    key_ref(key).map_or(0, |key| key.bits)
}

pub(crate) fn rsa_component_len(key: *const c_void, component: c_int) -> usize {
    key_ref(key)
        .and_then(|key| key.component(component))
        .map_or(0, |component| component.len())
}

pub(crate) fn rsa_export_component(
    key: *const c_void,
    component: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let key = match key_ref(key) {
        Some(key) => key,
        None => return -1,
    };
    let component = match key.component(component) {
        Some(component) => component,
        None => return -1,
    };
    write_prefix(out, out_len, component)
}

pub(crate) fn rsa_parse_private_pem(blob: *const u8, blob_len: usize) -> *mut c_void {
    match rsa_parse_private_pem_with_passphrase(blob, blob_len, core::ptr::null(), 0) {
        Ok(key) => key,
        Err(_) => core::ptr::null_mut(),
    }
}

pub(crate) fn rsa_parse_private_pem_with_passphrase(
    blob: *const u8,
    blob_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
) -> Result<*mut c_void, PrivatePemError> {
    let pem = match read_slice(blob, blob_len).and_then(|blob| str::from_utf8(blob).ok()) {
        Some(pem) => pem,
        None => return Err(PrivatePemError::InvalidFormat),
    };
    let passphrase = if passphrase_len == 0 {
        &[][..]
    } else {
        read_slice(passphrase, passphrase_len).ok_or(PrivatePemError::InvalidFormat)?
    };

    let key = if pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        let der = decrypt_encrypted_pkcs8_pem(pem, passphrase)?;
        RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| PrivatePemError::InvalidFormat)?
    } else if pem.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        match decrypt_legacy_private_pem(pem, passphrase) {
            Ok((LegacyPemLabel::RsaPrivateKey, der)) => {
                RsaPrivateKey::from_pkcs1_der(&der).map_err(|_| PrivatePemError::InvalidFormat)?
            }
            Ok((LegacyPemLabel::EcPrivateKey, _)) => return Err(PrivatePemError::InvalidFormat),
            Err(PrivatePemError::WrongPassphrase) => return Err(PrivatePemError::WrongPassphrase),
            Err(PrivatePemError::InvalidFormat) => {
                RsaPrivateKey::from_pkcs1_pem(pem).map_err(|_| PrivatePemError::InvalidFormat)?
            }
        }
    } else if pem.starts_with("-----BEGIN PRIVATE KEY-----") {
        RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| PrivatePemError::InvalidFormat)?
    } else {
        return Err(PrivatePemError::InvalidFormat);
    };
    match RustRsaKey::from_private_key(key) {
        Ok(key) => Ok(Box::into_raw(Box::new(key)).cast()),
        Err(()) => Err(PrivatePemError::InvalidFormat),
    }
}

fn rsa_serialize_private_pem(key: &RustRsaKey, format: c_int) -> Result<Vec<u8>, ()> {
    let private_key = key.private_key()?;
    match format {
        SSHKEY_PRIVATE_PEM => Ok(private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|_| ())?
            .to_string()
            .into_bytes()),
        SSHKEY_PRIVATE_PKCS8 => Ok(private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|_| ())?
            .to_string()
            .into_bytes()),
        _ => Err(()),
    }
}

pub(crate) fn rsa_private_pem_len(key: *const c_void, format: c_int) -> usize {
    let Some(key) = key_ref(key) else {
        return 0;
    };
    rsa_serialize_private_pem(key, format).map_or(0, |pem| pem.len())
}

pub(crate) fn rsa_private_pem_write(
    key: *const c_void,
    format: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let Some(key) = key_ref(key) else {
        return -1;
    };
    let pem = match rsa_serialize_private_pem(key, format) {
        Ok(pem) => pem,
        Err(()) => return -1,
    };
    write_prefix(out, out_len, &pem)
}

pub(crate) fn rsa_sign_prehashed(
    key: *const c_void,
    hash_alg: c_int,
    digest: *const u8,
    digest_len: usize,
    signature: *mut u8,
    signature_len: usize,
) -> c_int {
    let key = match key_ref(key) {
        Some(key) => key,
        None => return -1,
    };
    let digest = match read_slice(digest, digest_len) {
        Some(bytes) => bytes,
        None => return -1,
    };
    let signed = match key.sign_prehash(hash_alg, digest) {
        Ok(signature_bytes) => signature_bytes,
        Err(_) => return -1,
    };
    if signed.len() != signature_len {
        return -1;
    }
    write_prefix(signature, signature_len, &signed)
}

pub(crate) fn rsa_verify_prehashed(
    key: *const c_void,
    hash_alg: c_int,
    digest: *const u8,
    digest_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let key = match key_ref(key) {
        Some(key) => key,
        None => return -1,
    };
    let digest = match read_slice(digest, digest_len) {
        Some(bytes) => bytes,
        None => return -1,
    };
    let signature = match read_slice(signature, signature_len) {
        Some(bytes) => bytes,
        None => return -1,
    };
    match key.verify_prehash(hash_alg, digest, signature) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

pub(crate) fn rsa_free(key: *mut c_void) {
    if key.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(key.cast::<RustRsaKey>()) };
    boxed.scrub();
    drop(boxed);
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_int, c_void};

    use super::{
        OSSH_RUST_RSA_COMPONENT_D, OSSH_RUST_RSA_COMPONENT_E, OSSH_RUST_RSA_COMPONENT_IQMP,
        OSSH_RUST_RSA_COMPONENT_N, OSSH_RUST_RSA_COMPONENT_P, OSSH_RUST_RSA_COMPONENT_Q,
        SSH_DIGEST_SHA1, SSH_DIGEST_SHA256, SSH_DIGEST_SHA512, rsa_bits, rsa_component_len,
        rsa_export_component, rsa_free, rsa_from_private, rsa_generate,
        rsa_parse_private_pem_with_passphrase, rsa_parse_public_blob, rsa_sign_prehashed,
        rsa_verify_prehashed,
    };
    use crate::private_pem::PrivatePemError;
    use pkcs8::{EncodePrivateKey, LineEnding};
    use rand_core::OsRng;
    use rsa::RsaPrivateKey;

    fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    fn put_mpint(buf: &mut Vec<u8>, bytes: &[u8]) {
        let mut start = 0usize;
        while start < bytes.len() && bytes[start] == 0 {
            start += 1;
        }
        let trimmed = &bytes[start..];
        if !trimmed.is_empty() && (trimmed[0] & 0x80) != 0 {
            buf.extend_from_slice(&((trimmed.len() + 1) as u32).to_be_bytes());
            buf.push(0);
            buf.extend_from_slice(trimmed);
        } else {
            put_string(buf, trimmed);
        }
    }

    fn export_component(key: *const c_void, component: c_int) -> Vec<u8> {
        let len = rsa_component_len(key, component);
        assert!(len > 0);
        let mut out = vec![0u8; len];
        assert_eq!(0, rsa_export_component(key, component, out.as_mut_ptr(), out.len()));
        out
    }

    fn rsa_roundtrip_for_hash(hash_alg: c_int) {
        let digest = match hash_alg {
            SSH_DIGEST_SHA1 => vec![0x11; 20],
            SSH_DIGEST_SHA256 => vec![0x22; 32],
            SSH_DIGEST_SHA512 => vec![0x33; 64],
            _ => unreachable!(),
        };
        let key = rsa_generate(1024);
        assert!(!key.is_null());
        assert!(rsa_bits(key) >= 1024);

        let n = export_component(key, OSSH_RUST_RSA_COMPONENT_N);
        let e = export_component(key, OSSH_RUST_RSA_COMPONENT_E);
        let d = export_component(key, OSSH_RUST_RSA_COMPONENT_D);
        let iqmp = export_component(key, OSSH_RUST_RSA_COMPONENT_IQMP);
        let p = export_component(key, OSSH_RUST_RSA_COMPONENT_P);
        let q = export_component(key, OSSH_RUST_RSA_COMPONENT_Q);

        let mut sig = vec![0u8; n.len()];
        assert_eq!(
            0,
            rsa_sign_prehashed(
                key,
                hash_alg,
                digest.as_ptr(),
                digest.len(),
                sig.as_mut_ptr(),
                sig.len(),
            )
        );
        assert_eq!(
            1,
            rsa_verify_prehashed(key, hash_alg, digest.as_ptr(), digest.len(), sig.as_ptr(), sig.len())
        );

        let rebuilt = rsa_from_private(
            n.as_ptr(),
            n.len(),
            e.as_ptr(),
            e.len(),
            d.as_ptr(),
            d.len(),
            iqmp.as_ptr(),
            iqmp.len(),
            p.as_ptr(),
            p.len(),
            q.as_ptr(),
            q.len(),
        );
        assert!(!rebuilt.is_null());
        assert_eq!(
            1,
            rsa_verify_prehashed(
                rebuilt,
                hash_alg,
                digest.as_ptr(),
                digest.len(),
                sig.as_ptr(),
                sig.len(),
            )
        );

        sig[0] ^= 0x01;
        assert_eq!(
            0,
            rsa_verify_prehashed(rebuilt, hash_alg, digest.as_ptr(), digest.len(), sig.as_ptr(), sig.len())
        );

        rsa_free(rebuilt);
        rsa_free(key);
    }

    #[test]
    fn rsa_sha1_roundtrip() {
        rsa_roundtrip_for_hash(SSH_DIGEST_SHA1);
    }

    #[test]
    fn rsa_sha256_roundtrip() {
        rsa_roundtrip_for_hash(SSH_DIGEST_SHA256);
    }

    #[test]
    fn rsa_sha512_roundtrip() {
        rsa_roundtrip_for_hash(SSH_DIGEST_SHA512);
    }

    #[test]
    fn public_blob_parse_consumes_public_section() {
        let key = rsa_generate(1024);
        let n = export_component(key, OSSH_RUST_RSA_COMPONENT_N);
        let e = export_component(key, OSSH_RUST_RSA_COMPONENT_E);
        let mut blob = Vec::new();
        let mut consumed = 0usize;
        let trailer = b"certificate-trailer";

        put_mpint(&mut blob, &e);
        put_mpint(&mut blob, &n);
        put_string(&mut blob, trailer);

        let parsed = rsa_parse_public_blob(blob.as_ptr(), blob.len(), &mut consumed);
        assert!(!parsed.is_null());
        assert_eq!(consumed, blob.len() - (4 + trailer.len()));
        rsa_free(parsed);
        rsa_free(key);
    }

    #[test]
    fn parses_rsa_public_fixture_blob() {
        let blob = [
            0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x81, 0x00, 0xcb,
            0x57, 0x99, 0x54, 0x4e, 0xde, 0xc5, 0xac, 0x00, 0xec, 0x78, 0x1f, 0xc2, 0x1a,
            0x11, 0x19, 0xce, 0x9a, 0x28, 0x8e, 0x31, 0x16, 0xe7, 0x2f, 0x3e, 0x78, 0xfb,
            0xcb, 0xa6, 0x99, 0x8a, 0xdc, 0xc9, 0x8c, 0x23, 0x5f, 0x2e, 0x77, 0xab, 0xf1,
            0xce, 0x92, 0xb7, 0x6f, 0x06, 0x4b, 0x62, 0x45, 0x52, 0xc9, 0xf2, 0x58, 0x23,
            0x41, 0xe6, 0x22, 0xe1, 0xa1, 0x76, 0xee, 0xf2, 0x32, 0xb5, 0xba, 0xc1, 0xbf,
            0x38, 0x81, 0xba, 0xbc, 0x0b, 0x7d, 0x57, 0xa1, 0xef, 0x44, 0x39, 0x17, 0x08,
            0x52, 0xe1, 0x92, 0xbc, 0x32, 0x9d, 0x35, 0x23, 0x35, 0x4a, 0x39, 0x61, 0x0e,
            0xab, 0x91, 0x6e, 0x50, 0xc5, 0x07, 0xc9, 0x13, 0xa2, 0xa5, 0xf2, 0xc7, 0x59,
            0x6a, 0xad, 0x77, 0x9c, 0x5f, 0x29, 0x71, 0x21, 0x43, 0x8b, 0xd2, 0x31, 0x3e,
            0xbb, 0x4a, 0xd4, 0xd7, 0xde, 0xbb, 0xa4, 0x32, 0x71, 0xfb,
        ];
        let mut consumed = 0usize;

        let parsed = rsa_parse_public_blob(blob.as_ptr(), blob.len(), &mut consumed);
        assert!(!parsed.is_null());
        assert_eq!(consumed, blob.len());
        rsa_free(parsed);
    }

    #[test]
    fn parses_encrypted_pkcs8() {
        let key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let pem = key
            .to_pkcs8_encrypted_pem(&mut OsRng, b"password", LineEnding::LF)
            .unwrap();
        let parsed = rsa_parse_private_pem_with_passphrase(
            pem.as_bytes().as_ptr(),
            pem.len(),
            b"password".as_ptr(),
            b"password".len(),
        )
        .unwrap();
        assert!(!parsed.is_null());
        rsa_free(parsed);
    }

    #[test]
    fn encrypted_pkcs8_reports_wrong_passphrase() {
        let key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let pem = key
            .to_pkcs8_encrypted_pem(&mut OsRng, b"password", LineEnding::LF)
            .unwrap();
        let err = rsa_parse_private_pem_with_passphrase(
            pem.as_bytes().as_ptr(),
            pem.len(),
            b"wrong".as_ptr(),
            b"wrong".len(),
        )
        .unwrap_err();
        assert_eq!(err, PrivatePemError::WrongPassphrase);
    }
}
