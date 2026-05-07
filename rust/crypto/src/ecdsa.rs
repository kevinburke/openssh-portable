use core::ffi::{c_int, c_void};
use core::slice;
use core::str;

use p256::ecdsa::{
    signature::hazmat::{
        PrehashSigner as P256PrehashSigner, PrehashVerifier as P256PrehashVerifier,
    },
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey as P256SecretKey;
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use p384::SecretKey as P384SecretKey;
use p521::ecdsa::{
    signature::hazmat::RandomizedPrehashSigner as P521RandomizedPrehashSigner,
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use p521::SecretKey as P521SecretKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;

use crate::private_pem::{
    decrypt_encrypted_pkcs8_pem, decrypt_legacy_private_pem, LegacyPemLabel, PrivatePemError,
};
use crate::util::{read_slice, slice_ptr, write_prefix, SshWireReader};

const NID_X9_62_PRIME256V1: c_int = 415;
const NID_SECP384R1: c_int = 715;
const NID_SECP521R1: c_int = 716;
const SSHKEY_PRIVATE_PEM: c_int = 1;
const SSHKEY_PRIVATE_PKCS8: c_int = 2;
pub(crate) const OSSH_RUST_ECDSA_PARSE_OK: c_int = 0;
pub(crate) const OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT: c_int = 1;
pub(crate) const OSSH_RUST_ECDSA_PARSE_CURVE_MISMATCH: c_int = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EcdsaCurve {
    NistP256,
    NistP384,
    NistP521,
}

impl EcdsaCurve {
    fn from_nid(curve_nid: c_int) -> Option<Self> {
        match curve_nid {
            NID_X9_62_PRIME256V1 => Some(Self::NistP256),
            NID_SECP384R1 => Some(Self::NistP384),
            NID_SECP521R1 => Some(Self::NistP521),
            _ => None,
        }
    }

    fn scalar_len(self) -> usize {
        match self {
            Self::NistP256 => 32,
            Self::NistP384 => 48,
            Self::NistP521 => 66,
        }
    }

    fn public_len(self) -> usize {
        1 + 2 * self.scalar_len()
    }

    fn ssh_name(self) -> &'static [u8] {
        match self {
            Self::NistP256 => b"nistp256",
            Self::NistP384 => b"nistp384",
            Self::NistP521 => b"nistp521",
        }
    }

    fn signature_len(self) -> usize {
        2 * self.scalar_len()
    }

    fn generate(self) -> RustEcdsaKey {
        match self {
            Self::NistP256 => {
                let signing = P256SigningKey::random(&mut OsRng);
                let verifying = P256VerifyingKey::from(&signing);
                RustEcdsaKey {
                    curve: self,
                    public_key: verifying.to_encoded_point(false).as_bytes().to_vec(),
                    private_key: Some(signing.to_bytes().as_slice().to_vec()),
                }
            }
            Self::NistP384 => {
                let signing = P384SigningKey::random(&mut OsRng);
                let verifying = P384VerifyingKey::from(&signing);
                RustEcdsaKey {
                    curve: self,
                    public_key: verifying.to_encoded_point(false).as_bytes().to_vec(),
                    private_key: Some(signing.to_bytes().as_slice().to_vec()),
                }
            }
            Self::NistP521 => {
                let signing = P521SigningKey::random(&mut OsRng);
                let verifying = P521VerifyingKey::from(&signing);
                RustEcdsaKey {
                    curve: self,
                    public_key: verifying.to_encoded_point(false).as_bytes().to_vec(),
                    private_key: Some(signing.to_bytes().as_slice().to_vec()),
                }
            }
        }
    }

    fn validate_public(self, public_key: &[u8]) -> Result<(), ()> {
        if public_key.len() != self.public_len() {
            return Err(());
        }
        match self {
            Self::NistP256 => {
                P256VerifyingKey::from_sec1_bytes(public_key).map_err(|_| ())?;
            }
            Self::NistP384 => {
                P384VerifyingKey::from_sec1_bytes(public_key).map_err(|_| ())?;
            }
            Self::NistP521 => {
                P521VerifyingKey::from_sec1_bytes(public_key).map_err(|_| ())?;
            }
        }
        Ok(())
    }

    fn from_public(self, public_key: &[u8]) -> Result<RustEcdsaKey, ()> {
        self.validate_public(public_key)?;
        Ok(RustEcdsaKey {
            curve: self,
            public_key: public_key.to_vec(),
            private_key: None,
        })
    }

    fn from_private(self, public_key: &[u8], private_key: &[u8]) -> Result<RustEcdsaKey, ()> {
        self.validate_public(public_key)?;
        if private_key.len() != self.scalar_len() {
            return Err(());
        }
        let derived_public = match self {
            Self::NistP256 => {
                let signing = P256SigningKey::from_slice(private_key).map_err(|_| ())?;
                P256VerifyingKey::from(&signing)
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
            }
            Self::NistP384 => {
                let signing = P384SigningKey::from_slice(private_key).map_err(|_| ())?;
                P384VerifyingKey::from(&signing)
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
            }
            Self::NistP521 => {
                let signing = P521SigningKey::from_slice(private_key).map_err(|_| ())?;
                P521VerifyingKey::from(&signing)
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
            }
        };
        if derived_public != public_key {
            return Err(());
        }
        Ok(RustEcdsaKey {
            curve: self,
            public_key: public_key.to_vec(),
            private_key: Some(private_key.to_vec()),
        })
    }

    fn sign_prehash(
        self,
        private_key: &[u8],
        digest: &[u8],
        signature: &mut [u8],
    ) -> Result<(), ()> {
        if private_key.len() != self.scalar_len() || signature.len() != self.signature_len() {
            return Err(());
        }
        match self {
            Self::NistP256 => {
                let signing = P256SigningKey::from_slice(private_key).map_err(|_| ())?;
                let sig: P256Signature = signing.sign_prehash(digest).map_err(|_| ())?;
                signature.copy_from_slice(sig.to_bytes().as_slice());
            }
            Self::NistP384 => {
                let signing = P384SigningKey::from_slice(private_key).map_err(|_| ())?;
                let sig: P384Signature = signing.sign_prehash(digest).map_err(|_| ())?;
                signature.copy_from_slice(sig.to_bytes().as_slice());
            }
            Self::NistP521 => {
                let signing = P521SigningKey::from_slice(private_key).map_err(|_| ())?;
                let sig: P521Signature = signing
                    .sign_prehash_with_rng(&mut OsRng, digest)
                    .map_err(|_| ())?;
                signature.copy_from_slice(sig.to_bytes().as_slice());
            }
        }
        Ok(())
    }

    fn verify_prehash(
        self,
        public_key: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, ()> {
        if public_key.len() != self.public_len() || signature.len() != self.signature_len() {
            return Err(());
        }
        let valid = match self {
            Self::NistP256 => {
                let verifying = P256VerifyingKey::from_sec1_bytes(public_key).map_err(|_| ())?;
                let signature = P256Signature::from_slice(signature).map_err(|_| ())?;
                verifying.verify_prehash(digest, &signature).is_ok()
            }
            Self::NistP384 => {
                let verifying = P384VerifyingKey::from_sec1_bytes(public_key).map_err(|_| ())?;
                let signature = P384Signature::from_slice(signature).map_err(|_| ())?;
                verifying.verify_prehash(digest, &signature).is_ok()
            }
            Self::NistP521 => {
                let verifying = P521VerifyingKey::from_sec1_bytes(public_key).map_err(|_| ())?;
                let signature = P521Signature::from_slice(signature).map_err(|_| ())?;
                verifying.verify_prehash(digest, &signature).is_ok()
            }
        };
        Ok(valid)
    }

    fn parse_private_pem(self, pem: &str, format: c_int) -> Result<RustEcdsaKey, ()> {
        match (self, format) {
            (Self::NistP256, SSHKEY_PRIVATE_PEM) => Ok(Self::from_secret_p256(
                P256SecretKey::from_sec1_pem(pem).map_err(|_| ())?,
            )),
            (Self::NistP384, SSHKEY_PRIVATE_PEM) => Ok(Self::from_secret_p384(
                P384SecretKey::from_sec1_pem(pem).map_err(|_| ())?,
            )),
            (Self::NistP521, SSHKEY_PRIVATE_PEM) => Ok(Self::from_secret_p521(
                P521SecretKey::from_sec1_pem(pem).map_err(|_| ())?,
            )),
            (Self::NistP256, SSHKEY_PRIVATE_PKCS8) => Ok(Self::from_secret_p256(
                P256SecretKey::from_pkcs8_pem(pem).map_err(|_| ())?,
            )),
            (Self::NistP384, SSHKEY_PRIVATE_PKCS8) => Ok(Self::from_secret_p384(
                P384SecretKey::from_pkcs8_pem(pem).map_err(|_| ())?,
            )),
            (Self::NistP521, SSHKEY_PRIVATE_PKCS8) => Ok(Self::from_secret_p521(
                P521SecretKey::from_pkcs8_pem(pem).map_err(|_| ())?,
            )),
            _ => Err(()),
        }
    }

    fn parse_private_der(self, der: &[u8], format: c_int) -> Result<RustEcdsaKey, ()> {
        match (self, format) {
            (Self::NistP256, SSHKEY_PRIVATE_PEM) => Ok(Self::from_secret_p256(
                P256SecretKey::from_sec1_der(der).map_err(|_| ())?,
            )),
            (Self::NistP384, SSHKEY_PRIVATE_PEM) => Ok(Self::from_secret_p384(
                P384SecretKey::from_sec1_der(der).map_err(|_| ())?,
            )),
            (Self::NistP521, SSHKEY_PRIVATE_PEM) => Ok(Self::from_secret_p521(
                P521SecretKey::from_sec1_der(der).map_err(|_| ())?,
            )),
            (Self::NistP256, SSHKEY_PRIVATE_PKCS8) => Ok(Self::from_secret_p256(
                P256SecretKey::from_pkcs8_der(der).map_err(|_| ())?,
            )),
            (Self::NistP384, SSHKEY_PRIVATE_PKCS8) => Ok(Self::from_secret_p384(
                P384SecretKey::from_pkcs8_der(der).map_err(|_| ())?,
            )),
            (Self::NistP521, SSHKEY_PRIVATE_PKCS8) => Ok(Self::from_secret_p521(
                P521SecretKey::from_pkcs8_der(der).map_err(|_| ())?,
            )),
            _ => Err(()),
        }
    }

    fn serialize_private_pem(self, private_key: &[u8], format: c_int) -> Result<Vec<u8>, ()> {
        match (self, format) {
            (Self::NistP256, SSHKEY_PRIVATE_PEM) => {
                let secret = P256SecretKey::from_slice(private_key).map_err(|_| ())?;
                Ok(secret
                    .to_sec1_pem(LineEnding::LF)
                    .map_err(|_| ())?
                    .to_string()
                    .into_bytes())
            }
            (Self::NistP384, SSHKEY_PRIVATE_PEM) => {
                let secret = P384SecretKey::from_slice(private_key).map_err(|_| ())?;
                Ok(secret
                    .to_sec1_pem(LineEnding::LF)
                    .map_err(|_| ())?
                    .to_string()
                    .into_bytes())
            }
            (Self::NistP521, SSHKEY_PRIVATE_PEM) => {
                let secret = P521SecretKey::from_slice(private_key).map_err(|_| ())?;
                Ok(secret
                    .to_sec1_pem(LineEnding::LF)
                    .map_err(|_| ())?
                    .to_string()
                    .into_bytes())
            }
            (Self::NistP256, SSHKEY_PRIVATE_PKCS8) => {
                let secret = P256SecretKey::from_slice(private_key).map_err(|_| ())?;
                Ok(secret
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|_| ())?
                    .to_string()
                    .into_bytes())
            }
            (Self::NistP384, SSHKEY_PRIVATE_PKCS8) => {
                let secret = P384SecretKey::from_slice(private_key).map_err(|_| ())?;
                Ok(secret
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|_| ())?
                    .to_string()
                    .into_bytes())
            }
            (Self::NistP521, SSHKEY_PRIVATE_PKCS8) => {
                let secret = P521SecretKey::from_slice(private_key).map_err(|_| ())?;
                Ok(secret
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|_| ())?
                    .to_string()
                    .into_bytes())
            }
            _ => Err(()),
        }
    }

    fn from_secret_p256(secret: P256SecretKey) -> RustEcdsaKey {
        RustEcdsaKey {
            curve: Self::NistP256,
            public_key: secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            private_key: Some(secret.to_bytes().as_slice().to_vec()),
        }
    }

    fn from_secret_p384(secret: P384SecretKey) -> RustEcdsaKey {
        RustEcdsaKey {
            curve: Self::NistP384,
            public_key: secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            private_key: Some(secret.to_bytes().as_slice().to_vec()),
        }
    }

    fn from_secret_p521(secret: P521SecretKey) -> RustEcdsaKey {
        RustEcdsaKey {
            curve: Self::NistP521,
            public_key: secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            private_key: Some(secret.to_bytes().as_slice().to_vec()),
        }
    }
}

struct RustEcdsaKey {
    curve: EcdsaCurve,
    public_key: Vec<u8>,
    private_key: Option<Vec<u8>>,
}

impl RustEcdsaKey {
    fn scrub(&mut self) {
        self.public_key.fill(0);
        if let Some(private_key) = self.private_key.as_mut() {
            private_key.fill(0);
        }
    }
}

fn key_ref<'a>(key: *const c_void) -> Option<&'a RustEcdsaKey> {
    if key.is_null() {
        None
    } else {
        Some(unsafe { &*(key.cast::<RustEcdsaKey>()) })
    }
}

pub(crate) fn ecdsa_generate(curve_nid: c_int) -> *mut c_void {
    let curve = match EcdsaCurve::from_nid(curve_nid) {
        Some(curve) => curve,
        None => return core::ptr::null_mut(),
    };
    Box::into_raw(Box::new(curve.generate())).cast()
}

pub(crate) fn ecdsa_parse_public_blob(
    curve_nid: c_int,
    blob: *const u8,
    blob_len: usize,
    consumed_len: *mut usize,
) -> Result<*mut c_void, c_int> {
    let curve = match EcdsaCurve::from_nid(curve_nid) {
        Some(curve) => curve,
        None => return Err(OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT),
    };
    let blob = match read_slice(blob, blob_len) {
        Some(blob) => blob,
        None => return Err(OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT),
    };
    let mut reader = SshWireReader::new(blob);
    let curve_name = match reader.get_cstring() {
        Some(curve_name) => curve_name,
        None => return Err(OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT),
    };
    if curve_name != curve.ssh_name() {
        return Err(OSSH_RUST_ECDSA_PARSE_CURVE_MISMATCH);
    }
    let public_key = match reader.get_string() {
        Some(public_key) => public_key,
        None => return Err(OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT),
    };
    let key = ecdsa_from_public(curve_nid, slice_ptr(public_key), public_key.len());
    if key.is_null() {
        return Err(OSSH_RUST_ECDSA_PARSE_INVALID_FORMAT);
    }
    if !consumed_len.is_null() {
        unsafe { *consumed_len = reader.consumed() };
    }
    Ok(key)
}

pub(crate) fn ecdsa_from_public(
    curve_nid: c_int,
    public_key: *const u8,
    public_key_len: usize,
) -> *mut c_void {
    let curve = match EcdsaCurve::from_nid(curve_nid) {
        Some(curve) => curve,
        None => return core::ptr::null_mut(),
    };
    let public_key = match read_slice(public_key, public_key_len) {
        Some(public_key) => public_key,
        None => return core::ptr::null_mut(),
    };
    match curve.from_public(public_key) {
        Ok(key) => Box::into_raw(Box::new(key)).cast(),
        Err(_) => core::ptr::null_mut(),
    }
}

pub(crate) fn ecdsa_from_private(
    curve_nid: c_int,
    public_key: *const u8,
    public_key_len: usize,
    private_key: *const u8,
    private_key_len: usize,
) -> *mut c_void {
    let curve = match EcdsaCurve::from_nid(curve_nid) {
        Some(curve) => curve,
        None => return core::ptr::null_mut(),
    };
    let public_key = match read_slice(public_key, public_key_len) {
        Some(public_key) => public_key,
        None => return core::ptr::null_mut(),
    };
    let private_key = match read_slice(private_key, private_key_len) {
        Some(private_key) => private_key,
        None => return core::ptr::null_mut(),
    };
    match curve.from_private(public_key, private_key) {
        Ok(key) => Box::into_raw(Box::new(key)).cast(),
        Err(_) => core::ptr::null_mut(),
    }
}

pub(crate) fn ecdsa_copy_public(key: *const c_void) -> *mut c_void {
    let key = match key_ref(key) {
        Some(key) => key,
        None => return core::ptr::null_mut(),
    };
    Box::into_raw(Box::new(RustEcdsaKey {
        curve: key.curve,
        public_key: key.public_key.clone(),
        private_key: None,
    }))
    .cast()
}

pub(crate) fn ecdsa_equal_public(a: *const c_void, b: *const c_void) -> c_int {
    let a = match key_ref(a) {
        Some(key) => key,
        None => return 0,
    };
    let b = match key_ref(b) {
        Some(key) => key,
        None => return 0,
    };
    if a.curve == b.curve && a.public_key == b.public_key {
        1
    } else {
        0
    }
}

pub(crate) fn ecdsa_export_public(
    key: *const c_void,
    public_key: *mut u8,
    public_key_len: usize,
) -> c_int {
    let key = match key_ref(key) {
        Some(key) => key,
        None => return -1,
    };
    write_prefix(public_key, public_key_len, &key.public_key)
}

pub(crate) fn ecdsa_export_private(
    key: *const c_void,
    private_key: *mut u8,
    private_key_len: usize,
) -> c_int {
    let key = match key_ref(key) {
        Some(key) => key,
        None => return -1,
    };
    let private_key_bytes = match key.private_key.as_ref() {
        Some(private_key_bytes) => private_key_bytes,
        None => return -1,
    };
    write_prefix(private_key, private_key_len, private_key_bytes)
}

pub(crate) fn ecdsa_sign_prehashed(
    key: *const c_void,
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
        Some(digest) => digest,
        None => return -1,
    };
    let private_key = match key.private_key.as_ref() {
        Some(private_key) => private_key,
        None => return -1,
    };
    if signature.is_null() || signature_len != key.curve.signature_len() {
        return -1;
    }
    let signature = unsafe { slice::from_raw_parts_mut(signature, signature_len) };
    if key
        .curve
        .sign_prehash(private_key, digest, signature)
        .is_err()
    {
        return -1;
    }
    0
}

pub(crate) fn ecdsa_curve_nid(key: *const c_void) -> c_int {
    match key_ref(key) {
        Some(key) => match key.curve {
            EcdsaCurve::NistP256 => NID_X9_62_PRIME256V1,
            EcdsaCurve::NistP384 => NID_SECP384R1,
            EcdsaCurve::NistP521 => NID_SECP521R1,
        },
        None => 0,
    }
}

pub(crate) fn ecdsa_parse_private_pem(blob: *const u8, blob_len: usize) -> *mut c_void {
    match ecdsa_parse_private_pem_with_passphrase(blob, blob_len, core::ptr::null(), 0) {
        Ok(key) => key,
        Err(_) => core::ptr::null_mut(),
    }
}

pub(crate) fn ecdsa_parse_private_pem_with_passphrase(
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
    let curves = [
        EcdsaCurve::NistP256,
        EcdsaCurve::NistP384,
        EcdsaCurve::NistP521,
    ];

    if pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        let der = decrypt_encrypted_pkcs8_pem(pem, passphrase)?;
        for curve in curves {
            if let Ok(key) = curve.parse_private_der(&der, SSHKEY_PRIVATE_PKCS8) {
                return Ok(Box::into_raw(Box::new(key)).cast());
            }
        }
        return Err(PrivatePemError::InvalidFormat);
    }

    if pem.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        match decrypt_legacy_private_pem(pem, passphrase) {
            Ok((LegacyPemLabel::EcPrivateKey, der)) => {
                for curve in curves {
                    if let Ok(key) = curve.parse_private_der(&der, SSHKEY_PRIVATE_PEM) {
                        return Ok(Box::into_raw(Box::new(key)).cast());
                    }
                }
                return Err(PrivatePemError::InvalidFormat);
            }
            Ok((LegacyPemLabel::RsaPrivateKey, _)) => return Err(PrivatePemError::InvalidFormat),
            Err(PrivatePemError::WrongPassphrase) => return Err(PrivatePemError::WrongPassphrase),
            Err(PrivatePemError::InvalidFormat) => {}
        }
        for curve in curves {
            if let Ok(key) = curve.parse_private_pem(pem, SSHKEY_PRIVATE_PEM) {
                return Ok(Box::into_raw(Box::new(key)).cast());
            }
        }
        return Err(PrivatePemError::InvalidFormat);
    }

    if pem.starts_with("-----BEGIN PRIVATE KEY-----") {
        for curve in curves {
            if let Ok(key) = curve.parse_private_pem(pem, SSHKEY_PRIVATE_PKCS8) {
                return Ok(Box::into_raw(Box::new(key)).cast());
            }
        }
        return Err(PrivatePemError::InvalidFormat);
    }

    Err(PrivatePemError::InvalidFormat)
}

pub(crate) fn ecdsa_private_pem_len(key: *const c_void, format: c_int) -> usize {
    let Some(key) = key_ref(key) else {
        return 0;
    };
    let Some(private_key) = key.private_key.as_deref() else {
        return 0;
    };
    key.curve
        .serialize_private_pem(private_key, format)
        .map_or(0, |pem| pem.len())
}

pub(crate) fn ecdsa_private_pem_write(
    key: *const c_void,
    format: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let Some(key) = key_ref(key) else {
        return -1;
    };
    let Some(private_key) = key.private_key.as_deref() else {
        return -1;
    };
    let pem = match key.curve.serialize_private_pem(private_key, format) {
        Ok(pem) => pem,
        Err(()) => return -1,
    };
    write_prefix(out, out_len, &pem)
}

pub(crate) fn ecdsa_verify_prehashed(
    key: *const c_void,
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
        Some(digest) => digest,
        None => return -1,
    };
    let signature = match read_slice(signature, signature_len) {
        Some(signature) => signature,
        None => return -1,
    };
    match key.curve.verify_prehash(&key.public_key, digest, signature) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => -1,
    }
}

pub(crate) fn ecdsa_free(key: *mut c_void) {
    if key.is_null() {
        return;
    }
    let mut key = unsafe { Box::from_raw(key.cast::<RustEcdsaKey>()) };
    key.scrub();
    drop(key);
}

#[cfg(test)]
mod tests {
    use core::ffi::c_int;

    use super::{
        ecdsa_copy_public, ecdsa_equal_public, ecdsa_export_private, ecdsa_export_public,
        ecdsa_free, ecdsa_from_private, ecdsa_generate, ecdsa_parse_private_pem_with_passphrase,
        ecdsa_parse_public_blob, ecdsa_sign_prehashed, ecdsa_verify_prehashed, EcdsaCurve,
        NID_SECP384R1, NID_SECP521R1, NID_X9_62_PRIME256V1, OSSH_RUST_ECDSA_PARSE_CURVE_MISMATCH,
    };
    use crate::private_pem::PrivatePemError;
    use p256::SecretKey as P256SecretKey;
    use pkcs8::{EncodePrivateKey, LineEnding};
    use rand_core::OsRng;

    fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    fn roundtrip_for_curve(curve_nid: c_int, digest_len: usize) {
        let curve = EcdsaCurve::from_nid(curve_nid).unwrap();
        let digest = vec![0x5a; digest_len];
        let mut public_key = vec![0u8; curve.public_len()];
        let mut private_key = vec![0u8; curve.scalar_len()];
        let mut signature = vec![0u8; curve.signature_len()];

        let key = ecdsa_generate(curve_nid);
        assert!(!key.is_null());
        assert_eq!(
            0,
            ecdsa_export_public(key, public_key.as_mut_ptr(), public_key.len())
        );
        assert_eq!(
            0,
            ecdsa_export_private(key, private_key.as_mut_ptr(), private_key.len())
        );
        assert_eq!(
            0,
            ecdsa_sign_prehashed(
                key,
                digest.as_ptr(),
                digest.len(),
                signature.as_mut_ptr(),
                signature.len(),
            )
        );
        assert_eq!(
            0,
            ecdsa_verify_prehashed(
                key,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
                signature.len(),
            )
        );

        let public_copy = ecdsa_copy_public(key);
        assert!(!public_copy.is_null());
        assert_eq!(1, ecdsa_equal_public(key, public_copy));
        assert_eq!(
            0,
            ecdsa_verify_prehashed(
                public_copy,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
                signature.len(),
            )
        );

        let rebuilt = ecdsa_from_private(
            curve_nid,
            public_key.as_ptr(),
            public_key.len(),
            private_key.as_ptr(),
            private_key.len(),
        );
        assert!(!rebuilt.is_null());
        assert_eq!(1, ecdsa_equal_public(key, rebuilt));
        assert_eq!(
            0,
            ecdsa_verify_prehashed(
                rebuilt,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
                signature.len(),
            )
        );

        signature[0] ^= 0x01;
        assert_eq!(
            1,
            ecdsa_verify_prehashed(
                rebuilt,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
                signature.len(),
            )
        );

        ecdsa_free(rebuilt);
        ecdsa_free(public_copy);
        ecdsa_free(key);
    }

    #[test]
    fn p256_roundtrip() {
        roundtrip_for_curve(NID_X9_62_PRIME256V1, 32);
    }

    #[test]
    fn p384_roundtrip() {
        roundtrip_for_curve(NID_SECP384R1, 48);
    }

    #[test]
    fn p521_roundtrip() {
        roundtrip_for_curve(NID_SECP521R1, 64);
    }

    #[test]
    fn reject_mismatched_private_key() {
        let curve = EcdsaCurve::NistP256;
        let mut public_key = vec![0u8; curve.public_len()];
        let mut private_key = vec![0u8; curve.scalar_len()];
        let key = ecdsa_generate(NID_X9_62_PRIME256V1);
        assert!(!key.is_null());
        assert_eq!(
            0,
            ecdsa_export_public(key, public_key.as_mut_ptr(), public_key.len())
        );
        assert_eq!(
            0,
            ecdsa_export_private(key, private_key.as_mut_ptr(), private_key.len())
        );
        private_key[0] ^= 0x80;
        let rebuilt = ecdsa_from_private(
            NID_X9_62_PRIME256V1,
            public_key.as_ptr(),
            public_key.len(),
            private_key.as_ptr(),
            private_key.len(),
        );
        assert!(rebuilt.is_null());
        ecdsa_free(key);
    }

    #[test]
    fn public_blob_parse_consumes_public_section() {
        let curve = EcdsaCurve::NistP256;
        let key = ecdsa_generate(NID_X9_62_PRIME256V1);
        let mut public_key = vec![0u8; curve.public_len()];
        let mut consumed = 0usize;
        assert!(!key.is_null());
        assert_eq!(
            0,
            ecdsa_export_public(key, public_key.as_mut_ptr(), public_key.len())
        );

        let mut blob = Vec::new();
        put_string(&mut blob, curve.ssh_name());
        put_string(&mut blob, &public_key);
        put_string(&mut blob, b"certificate-trailer");

        let parsed = ecdsa_parse_public_blob(
            NID_X9_62_PRIME256V1,
            blob.as_ptr(),
            blob.len(),
            &mut consumed,
        );
        let parsed = parsed.expect("valid ECDSA public blob");
        assert!(!parsed.is_null());
        assert_eq!(consumed, 4 + curve.ssh_name().len() + 4 + public_key.len());
        ecdsa_free(parsed);
        ecdsa_free(key);
    }

    #[test]
    fn public_blob_parse_reports_curve_mismatch() {
        let curve = EcdsaCurve::NistP256;
        let key = ecdsa_generate(NID_X9_62_PRIME256V1);
        let mut public_key = vec![0u8; curve.public_len()];

        assert!(!key.is_null());
        assert_eq!(
            0,
            ecdsa_export_public(key, public_key.as_mut_ptr(), public_key.len())
        );

        let mut blob = Vec::new();
        put_string(&mut blob, curve.ssh_name());
        put_string(&mut blob, &public_key);

        let parsed = ecdsa_parse_public_blob(
            NID_SECP384R1,
            blob.as_ptr(),
            blob.len(),
            core::ptr::null_mut(),
        );
        assert_eq!(parsed, Err(OSSH_RUST_ECDSA_PARSE_CURVE_MISMATCH));
        ecdsa_free(key);
    }

    #[test]
    fn parses_encrypted_pkcs8_p256() {
        let secret = P256SecretKey::random(&mut OsRng);
        let pem = secret
            .to_pkcs8_encrypted_pem(&mut OsRng, b"password", LineEnding::LF)
            .unwrap();
        let parsed = ecdsa_parse_private_pem_with_passphrase(
            pem.as_bytes().as_ptr(),
            pem.len(),
            b"password".as_ptr(),
            b"password".len(),
        )
        .unwrap();
        assert!(!parsed.is_null());
        ecdsa_free(parsed);
    }

    #[test]
    fn encrypted_pkcs8_reports_wrong_passphrase() {
        let secret = P256SecretKey::random(&mut OsRng);
        let pem = secret
            .to_pkcs8_encrypted_pem(&mut OsRng, b"password", LineEnding::LF)
            .unwrap();
        let err = ecdsa_parse_private_pem_with_passphrase(
            pem.as_bytes().as_ptr(),
            pem.len(),
            b"wrong".as_ptr(),
            b"wrong".len(),
        )
        .unwrap_err();
        assert_eq!(err, PrivatePemError::WrongPassphrase);
    }
}
