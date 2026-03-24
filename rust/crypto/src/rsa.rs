use core::ffi::{c_int, c_void};
use core::str;

use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

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
    let pem = match read_slice(blob, blob_len).and_then(|blob| str::from_utf8(blob).ok()) {
        Some(pem) => pem,
        None => return core::ptr::null_mut(),
    };
    let key = if pem.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        RsaPrivateKey::from_pkcs1_pem(pem).map_err(|_| ())
    } else if pem.starts_with("-----BEGIN PRIVATE KEY-----") {
        RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| ())
    } else {
        return core::ptr::null_mut();
    };
    match key.and_then(RustRsaKey::from_private_key) {
        Ok(key) => Box::into_raw(Box::new(key)).cast(),
        Err(()) => core::ptr::null_mut(),
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
        rsa_export_component, rsa_free, rsa_from_private, rsa_generate, rsa_parse_public_blob,
        rsa_sign_prehashed, rsa_verify_prehashed,
    };

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
}
