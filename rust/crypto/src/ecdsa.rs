use core::ffi::{c_int, c_void};
use core::slice;

use p256::ecdsa::{
    signature::hazmat::{PrehashSigner as P256PrehashSigner, PrehashVerifier as P256PrehashVerifier},
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use p521::ecdsa::{
    signature::hazmat::RandomizedPrehashSigner as P521RandomizedPrehashSigner,
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use rand_core::OsRng;

use crate::util::write_prefix;

const NID_X9_62_PRIME256V1: c_int = 415;
const NID_SECP384R1: c_int = 715;
const NID_SECP521R1: c_int = 716;

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
                P256VerifyingKey::from(&signing).to_encoded_point(false).as_bytes().to_vec()
            }
            Self::NistP384 => {
                let signing = P384SigningKey::from_slice(private_key).map_err(|_| ())?;
                P384VerifyingKey::from(&signing).to_encoded_point(false).as_bytes().to_vec()
            }
            Self::NistP521 => {
                let signing = P521SigningKey::from_slice(private_key).map_err(|_| ())?;
                P521VerifyingKey::from(&signing).to_encoded_point(false).as_bytes().to_vec()
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

    fn sign_prehash(self, private_key: &[u8], digest: &[u8], signature: &mut [u8]) -> Result<(), ()> {
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

    fn verify_prehash(self, public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool, ()> {
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

fn read_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(ptr, len) })
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

pub(crate) fn ecdsa_export_public(key: *const c_void, public_key: *mut u8, public_key_len: usize) -> c_int {
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
    if key.curve.sign_prehash(private_key, digest, signature).is_err() {
        return -1;
    }
    0
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
        EcdsaCurve, NID_SECP384R1, NID_SECP521R1, NID_X9_62_PRIME256V1, ecdsa_copy_public,
        ecdsa_equal_public, ecdsa_export_private, ecdsa_export_public, ecdsa_free,
        ecdsa_from_private, ecdsa_generate, ecdsa_sign_prehashed, ecdsa_verify_prehashed,
    };

    fn roundtrip_for_curve(curve_nid: c_int, digest_len: usize) {
        let curve = EcdsaCurve::from_nid(curve_nid).unwrap();
        let digest = vec![0x5a; digest_len];
        let mut public_key = vec![0u8; curve.public_len()];
        let mut private_key = vec![0u8; curve.scalar_len()];
        let mut signature = vec![0u8; curve.signature_len()];

        let key = ecdsa_generate(curve_nid);
        assert!(!key.is_null());
        assert_eq!(0, ecdsa_export_public(key, public_key.as_mut_ptr(), public_key.len()));
        assert_eq!(0, ecdsa_export_private(key, private_key.as_mut_ptr(), private_key.len()));
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
        assert_eq!(0, ecdsa_export_public(key, public_key.as_mut_ptr(), public_key.len()));
        assert_eq!(0, ecdsa_export_private(key, private_key.as_mut_ptr(), private_key.len()));
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
}
