use core::ffi::c_int;
use core::slice;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use p521::{PublicKey as P521PublicKey, SecretKey as P521SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use sntrup761::{
    generate_key as sntrup761_generate_key, Ciphertext as Sntrup761Ciphertext,
    DecapsulationKey as Sntrup761DecapsulationKey, EncapsulationKey as Sntrup761EncapsulationKey,
    CIPHERTEXT_SIZE as SNTRUP761_CIPHERTEXT_LENGTH, PUBLIC_KEY_SIZE as SNTRUP761_PUBLIC_KEY_LENGTH,
    SECRET_KEY_SIZE as SNTRUP761_SECRET_KEY_LENGTH,
    SHARED_SECRET_SIZE as SNTRUP761_SHARED_SECRET_LENGTH,
};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::util::{read_array, read_slice, write_prefix, SshWireReader};

pub(crate) const OSSH_RUST_ECDH_NISTP256: c_int = 1;
pub(crate) const OSSH_RUST_ECDH_NISTP384: c_int = 2;
pub(crate) const OSSH_RUST_ECDH_NISTP521: c_int = 3;

const ED25519_SEED_LENGTH: usize = 32;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SECRET_KEY_LENGTH: usize = 64;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const CURVE25519_KEY_LENGTH: usize = 32;
const MLKEM768_PUBLIC_KEY_LENGTH: usize = ml_kem_768::EK_LEN;
const MLKEM768_SECRET_KEY_LENGTH: usize = ml_kem_768::DK_LEN;
const MLKEM768_CIPHERTEXT_LENGTH: usize = ml_kem_768::CT_LEN;
const MLKEM768_SHARED_SECRET_LENGTH: usize = 32;
const MLKEM768X25519_CLIENT_BLOB_LENGTH: usize = MLKEM768_PUBLIC_KEY_LENGTH + CURVE25519_KEY_LENGTH;
const MLKEM768X25519_SERVER_BLOB_LENGTH: usize = MLKEM768_CIPHERTEXT_LENGTH + CURVE25519_KEY_LENGTH;
const SNTRUP761X25519_CLIENT_BLOB_LENGTH: usize =
    SNTRUP761_PUBLIC_KEY_LENGTH + CURVE25519_KEY_LENGTH;
const SNTRUP761X25519_SERVER_BLOB_LENGTH: usize =
    SNTRUP761_CIPHERTEXT_LENGTH + CURVE25519_KEY_LENGTH;
const ECDH_NISTP256_SECRET_LENGTH: usize = 32;
const ECDH_NISTP256_PUBLIC_LENGTH: usize = 65;
const ECDH_NISTP384_SECRET_LENGTH: usize = 48;
const ECDH_NISTP384_PUBLIC_LENGTH: usize = 97;
const ECDH_NISTP521_SECRET_LENGTH: usize = 66;
const ECDH_NISTP521_PUBLIC_LENGTH: usize = 133;

fn slice_array<const N: usize>(input: &[u8]) -> Result<[u8; N], ()> {
    input.try_into().map_err(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EcdhCurve {
    NistP256,
    NistP384,
    NistP521,
}

impl EcdhCurve {
    pub(crate) fn from_id(curve_id: c_int) -> Option<Self> {
        match curve_id {
            OSSH_RUST_ECDH_NISTP256 => Some(Self::NistP256),
            OSSH_RUST_ECDH_NISTP384 => Some(Self::NistP384),
            OSSH_RUST_ECDH_NISTP521 => Some(Self::NistP521),
            _ => None,
        }
    }

    pub(crate) fn secret_len(self) -> usize {
        match self {
            Self::NistP256 => ECDH_NISTP256_SECRET_LENGTH,
            Self::NistP384 => ECDH_NISTP384_SECRET_LENGTH,
            Self::NistP521 => ECDH_NISTP521_SECRET_LENGTH,
        }
    }

    pub(crate) fn public_len(self) -> usize {
        match self {
            Self::NistP256 => ECDH_NISTP256_PUBLIC_LENGTH,
            Self::NistP384 => ECDH_NISTP384_PUBLIC_LENGTH,
            Self::NistP521 => ECDH_NISTP521_PUBLIC_LENGTH,
        }
    }

    pub(crate) fn shared_len(self) -> usize {
        self.secret_len()
    }

    pub(crate) fn generate_keypair(
        self,
        secret_out: &mut [u8],
        public_out: &mut [u8],
    ) -> Result<(), ()> {
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

    pub(crate) fn shared_secret(
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

pub(crate) fn ed25519_public_from_seed(
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

pub(crate) fn ed25519_sign(
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

pub(crate) fn ed25519_verify(
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

pub(crate) fn ed25519_parse_public_blob(
    blob: *const u8,
    blob_len: usize,
    public_key: *mut u8,
    public_key_len: usize,
    consumed_len: *mut usize,
) -> c_int {
    let blob = match read_slice(blob, blob_len) {
        Some(blob) => blob,
        None => return -1,
    };
    let mut reader = SshWireReader::new(blob);
    let parsed_public = match reader.get_string() {
        Some(public_key_blob) if public_key_blob.len() == ED25519_PUBLIC_KEY_LENGTH => {
            public_key_blob
        }
        _ => return -1,
    };
    if write_prefix(public_key, public_key_len, parsed_public) != 0 {
        return -1;
    }
    if !consumed_len.is_null() {
        unsafe { *consumed_len = reader.consumed() };
    }
    0
}

pub(crate) fn curve25519_public_from_secret(
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

pub(crate) fn curve25519_shared_secret(
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

fn checked_x25519_shared_secret(secret_key: &[u8], public_key: &[u8]) -> Result<[u8; 32], ()> {
    if secret_key.len() != CURVE25519_KEY_LENGTH || public_key.len() != CURVE25519_KEY_LENGTH {
        return Err(());
    }
    let mut secret = [0u8; CURVE25519_KEY_LENGTH];
    secret.copy_from_slice(secret_key);
    let mut public = [0u8; CURVE25519_KEY_LENGTH];
    public.copy_from_slice(public_key);
    let shared = x25519(secret, public);
    if shared.iter().all(|byte| *byte == 0) {
        return Err(());
    }
    Ok(shared)
}

fn hash_mlkem768x25519_shared(
    mlkem_shared: &[u8],
    x25519_shared: &[u8],
    out: &mut [u8],
) -> Result<(), ()> {
    if mlkem_shared.len() != MLKEM768_SHARED_SECRET_LENGTH
        || x25519_shared.len() != CURVE25519_KEY_LENGTH
        || out.len() != 32
    {
        return Err(());
    }
    let mut digest = Sha256::new();
    digest.update(mlkem_shared);
    digest.update(x25519_shared);
    out.copy_from_slice(&digest.finalize());
    Ok(())
}

fn hash_sntrup761x25519_shared(
    sntrup_shared: &[u8],
    x25519_shared: &[u8],
    out: &mut [u8],
) -> Result<(), ()> {
    if sntrup_shared.len() != SNTRUP761_SHARED_SECRET_LENGTH
        || x25519_shared.len() != CURVE25519_KEY_LENGTH
        || out.len() != 64
    {
        return Err(());
    }
    let mut digest = Sha512::new();
    digest.update(sntrup_shared);
    digest.update(x25519_shared);
    out.copy_from_slice(&digest.finalize());
    Ok(())
}

pub(crate) fn mlkem768x25519_keypair(
    client_blob: *mut u8,
    client_blob_len: usize,
    mlkem_secret: *mut u8,
    mlkem_secret_len: usize,
    curve25519_secret: *mut u8,
    curve25519_secret_len: usize,
) -> c_int {
    if client_blob.is_null() || mlkem_secret.is_null() || curve25519_secret.is_null() {
        return -1;
    }
    if client_blob_len != MLKEM768X25519_CLIENT_BLOB_LENGTH
        || mlkem_secret_len != MLKEM768_SECRET_KEY_LENGTH
        || curve25519_secret_len != CURVE25519_KEY_LENGTH
    {
        return -1;
    }
    let client_blob = unsafe { slice::from_raw_parts_mut(client_blob, client_blob_len) };
    let mlkem_secret = unsafe { slice::from_raw_parts_mut(mlkem_secret, mlkem_secret_len) };
    let curve25519_secret =
        unsafe { slice::from_raw_parts_mut(curve25519_secret, curve25519_secret_len) };

    let (encaps_key, decaps_key): (ml_kem_768::EncapsKey, ml_kem_768::DecapsKey) =
        match ml_kem_768::KG::try_keygen_with_rng(&mut OsRng) {
            Ok(pair) => pair,
            Err(_) => return -1,
        };
    let public_bytes = encaps_key.into_bytes();
    let secret_bytes = decaps_key.into_bytes();
    client_blob[..MLKEM768_PUBLIC_KEY_LENGTH].copy_from_slice(&public_bytes);
    mlkem_secret.copy_from_slice(&secret_bytes);

    let mut curve_secret = [0u8; CURVE25519_KEY_LENGTH];
    OsRng.fill_bytes(&mut curve_secret);
    curve25519_secret.copy_from_slice(&curve_secret);
    let curve_public = x25519(curve_secret, X25519_BASEPOINT_BYTES);
    client_blob[MLKEM768_PUBLIC_KEY_LENGTH..].copy_from_slice(&curve_public);
    0
}

pub(crate) fn mlkem768x25519_enc(
    client_blob: *const u8,
    client_blob_len: usize,
    server_blob: *mut u8,
    server_blob_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    if client_blob.is_null() || server_blob.is_null() || shared_hash.is_null() {
        return -1;
    }
    if client_blob_len != MLKEM768X25519_CLIENT_BLOB_LENGTH
        || server_blob_len != MLKEM768X25519_SERVER_BLOB_LENGTH
        || shared_hash_len != 32
    {
        return -1;
    }
    let client_blob = unsafe { slice::from_raw_parts(client_blob, client_blob_len) };
    let server_blob = unsafe { slice::from_raw_parts_mut(server_blob, server_blob_len) };
    let shared_hash = unsafe { slice::from_raw_parts_mut(shared_hash, shared_hash_len) };
    let (mlkem_public, curve25519_public) = client_blob.split_at(MLKEM768_PUBLIC_KEY_LENGTH);
    let Ok(mlkem_public) = slice_array::<MLKEM768_PUBLIC_KEY_LENGTH>(mlkem_public) else {
        return -1;
    };

    let encaps_key: ml_kem_768::EncapsKey =
        match ml_kem_768::EncapsKey::try_from_bytes(mlkem_public) {
            Ok(key) => key,
            Err(_) => return -1,
        };
    let (mlkem_shared, ciphertext): (fips203::SharedSecretKey, ml_kem_768::CipherText) =
        match encaps_key.try_encaps_with_rng(&mut OsRng) {
            Ok(result) => result,
            Err(_) => return -1,
        };
    let ciphertext_bytes = ciphertext.into_bytes();
    server_blob[..MLKEM768_CIPHERTEXT_LENGTH].copy_from_slice(&ciphertext_bytes);

    let (_, server_curve_secret) = {
        let mut secret = [0u8; CURVE25519_KEY_LENGTH];
        OsRng.fill_bytes(&mut secret);
        let public = x25519(secret, X25519_BASEPOINT_BYTES);
        (public, secret)
    };
    let server_curve_public = x25519(server_curve_secret, X25519_BASEPOINT_BYTES);
    server_blob[MLKEM768_CIPHERTEXT_LENGTH..].copy_from_slice(&server_curve_public);

    let x25519_shared = match checked_x25519_shared_secret(&server_curve_secret, curve25519_public)
    {
        Ok(shared) => shared,
        Err(_) => return -1,
    };
    if hash_mlkem768x25519_shared(&mlkem_shared.into_bytes(), &x25519_shared, shared_hash).is_err()
    {
        return -1;
    }
    0
}

pub(crate) fn mlkem768x25519_dec(
    server_blob: *const u8,
    server_blob_len: usize,
    mlkem_secret: *const u8,
    mlkem_secret_len: usize,
    curve25519_secret: *const u8,
    curve25519_secret_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    if server_blob.is_null()
        || mlkem_secret.is_null()
        || curve25519_secret.is_null()
        || shared_hash.is_null()
    {
        return -1;
    }
    if server_blob_len != MLKEM768X25519_SERVER_BLOB_LENGTH
        || mlkem_secret_len != MLKEM768_SECRET_KEY_LENGTH
        || curve25519_secret_len != CURVE25519_KEY_LENGTH
        || shared_hash_len != 32
    {
        return -1;
    }
    let server_blob = unsafe { slice::from_raw_parts(server_blob, server_blob_len) };
    let mlkem_secret = unsafe { slice::from_raw_parts(mlkem_secret, mlkem_secret_len) };
    let curve25519_secret =
        unsafe { slice::from_raw_parts(curve25519_secret, curve25519_secret_len) };
    let shared_hash = unsafe { slice::from_raw_parts_mut(shared_hash, shared_hash_len) };
    let (ciphertext, server_curve_public) = server_blob.split_at(MLKEM768_CIPHERTEXT_LENGTH);
    let Ok(mlkem_secret) = slice_array::<MLKEM768_SECRET_KEY_LENGTH>(mlkem_secret) else {
        return -1;
    };
    let Ok(ciphertext) = slice_array::<MLKEM768_CIPHERTEXT_LENGTH>(ciphertext) else {
        return -1;
    };

    let decaps_key: ml_kem_768::DecapsKey =
        match ml_kem_768::DecapsKey::try_from_bytes(mlkem_secret) {
            Ok(key) => key,
            Err(_) => return -1,
        };
    let ciphertext = match ml_kem_768::CipherText::try_from_bytes(ciphertext) {
        Ok(ct) => ct,
        Err(_) => return -1,
    };
    let mlkem_shared: fips203::SharedSecretKey = match decaps_key.try_decaps(&ciphertext) {
        Ok(shared) => shared,
        Err(_) => return -1,
    };
    let x25519_shared = match checked_x25519_shared_secret(curve25519_secret, server_curve_public) {
        Ok(shared) => shared,
        Err(_) => return -1,
    };
    if hash_mlkem768x25519_shared(&mlkem_shared.into_bytes(), &x25519_shared, shared_hash).is_err()
    {
        return -1;
    }
    0
}

pub(crate) fn sntrup761x25519_keypair(
    client_blob: *mut u8,
    client_blob_len: usize,
    sntrup_secret: *mut u8,
    sntrup_secret_len: usize,
    curve25519_secret: *mut u8,
    curve25519_secret_len: usize,
) -> c_int {
    if client_blob.is_null() || sntrup_secret.is_null() || curve25519_secret.is_null() {
        return -1;
    }
    if client_blob_len != SNTRUP761X25519_CLIENT_BLOB_LENGTH
        || sntrup_secret_len != SNTRUP761_SECRET_KEY_LENGTH
        || curve25519_secret_len != CURVE25519_KEY_LENGTH
    {
        return -1;
    }
    let client_blob = unsafe { slice::from_raw_parts_mut(client_blob, client_blob_len) };
    let sntrup_secret = unsafe { slice::from_raw_parts_mut(sntrup_secret, sntrup_secret_len) };
    let curve25519_secret =
        unsafe { slice::from_raw_parts_mut(curve25519_secret, curve25519_secret_len) };

    let (encapsulation_key, decapsulation_key) = sntrup761_generate_key(sntrup761::rand::rng());
    client_blob[..SNTRUP761_PUBLIC_KEY_LENGTH].copy_from_slice(encapsulation_key.as_ref());
    sntrup_secret.copy_from_slice(decapsulation_key.as_ref());

    let mut curve_secret = [0u8; CURVE25519_KEY_LENGTH];
    OsRng.fill_bytes(&mut curve_secret);
    curve25519_secret.copy_from_slice(&curve_secret);
    let curve_public = x25519(curve_secret, X25519_BASEPOINT_BYTES);
    client_blob[SNTRUP761_PUBLIC_KEY_LENGTH..].copy_from_slice(&curve_public);
    0
}

pub(crate) fn sntrup761x25519_enc(
    client_blob: *const u8,
    client_blob_len: usize,
    server_blob: *mut u8,
    server_blob_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    if client_blob.is_null() || server_blob.is_null() || shared_hash.is_null() {
        return -1;
    }
    if client_blob_len != SNTRUP761X25519_CLIENT_BLOB_LENGTH
        || server_blob_len != SNTRUP761X25519_SERVER_BLOB_LENGTH
        || shared_hash_len != 64
    {
        return -1;
    }
    let client_blob = unsafe { slice::from_raw_parts(client_blob, client_blob_len) };
    let server_blob = unsafe { slice::from_raw_parts_mut(server_blob, server_blob_len) };
    let shared_hash = unsafe { slice::from_raw_parts_mut(shared_hash, shared_hash_len) };
    let (sntrup_public, curve25519_public) = client_blob.split_at(SNTRUP761_PUBLIC_KEY_LENGTH);

    let encapsulation_key: Sntrup761EncapsulationKey = match sntrup_public.try_into() {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let (ciphertext, sntrup_shared) = encapsulation_key.encapsulate(sntrup761::rand::rng());
    server_blob[..SNTRUP761_CIPHERTEXT_LENGTH].copy_from_slice(ciphertext.as_ref());

    let server_curve_secret = {
        let mut secret = [0u8; CURVE25519_KEY_LENGTH];
        OsRng.fill_bytes(&mut secret);
        secret
    };
    let server_curve_public = x25519(server_curve_secret, X25519_BASEPOINT_BYTES);
    server_blob[SNTRUP761_CIPHERTEXT_LENGTH..].copy_from_slice(&server_curve_public);

    let x25519_shared = match checked_x25519_shared_secret(&server_curve_secret, curve25519_public)
    {
        Ok(shared) => shared,
        Err(_) => return -1,
    };
    if hash_sntrup761x25519_shared(sntrup_shared.as_ref(), &x25519_shared, shared_hash).is_err() {
        return -1;
    }
    0
}

pub(crate) fn sntrup761x25519_dec(
    server_blob: *const u8,
    server_blob_len: usize,
    sntrup_secret: *const u8,
    sntrup_secret_len: usize,
    curve25519_secret: *const u8,
    curve25519_secret_len: usize,
    shared_hash: *mut u8,
    shared_hash_len: usize,
) -> c_int {
    if server_blob.is_null()
        || sntrup_secret.is_null()
        || curve25519_secret.is_null()
        || shared_hash.is_null()
    {
        return -1;
    }
    if server_blob_len != SNTRUP761X25519_SERVER_BLOB_LENGTH
        || sntrup_secret_len != SNTRUP761_SECRET_KEY_LENGTH
        || curve25519_secret_len != CURVE25519_KEY_LENGTH
        || shared_hash_len != 64
    {
        return -1;
    }
    let server_blob = unsafe { slice::from_raw_parts(server_blob, server_blob_len) };
    let sntrup_secret = unsafe { slice::from_raw_parts(sntrup_secret, sntrup_secret_len) };
    let curve25519_secret =
        unsafe { slice::from_raw_parts(curve25519_secret, curve25519_secret_len) };
    let shared_hash = unsafe { slice::from_raw_parts_mut(shared_hash, shared_hash_len) };
    let (ciphertext, server_curve_public) = server_blob.split_at(SNTRUP761_CIPHERTEXT_LENGTH);

    let decapsulation_key: Sntrup761DecapsulationKey = match sntrup_secret.try_into() {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let ciphertext: Sntrup761Ciphertext = match ciphertext.try_into() {
        Ok(ct) => ct,
        Err(_) => return -1,
    };
    let sntrup_shared = decapsulation_key.decapsulate(&ciphertext);
    let x25519_shared = match checked_x25519_shared_secret(curve25519_secret, server_curve_public) {
        Ok(shared) => shared,
        Err(_) => return -1,
    };
    if hash_sntrup761x25519_shared(sntrup_shared.as_ref(), &x25519_shared, shared_hash).is_err() {
        return -1;
    }
    0
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer;
    use rand_core::RngCore;

    use super::{
        curve25519_public_from_secret, curve25519_shared_secret, ed25519_parse_public_blob,
        ed25519_public_from_seed, ed25519_sign, ed25519_verify, mlkem768x25519_dec,
        mlkem768x25519_enc, mlkem768x25519_keypair, sntrup761x25519_dec, sntrup761x25519_enc,
        sntrup761x25519_keypair, x25519, EcdhCurve, Signature, SigningKey, VerifyingKey,
        CURVE25519_KEY_LENGTH, MLKEM768X25519_CLIENT_BLOB_LENGTH,
        MLKEM768X25519_SERVER_BLOB_LENGTH, MLKEM768_SECRET_KEY_LENGTH, OSSH_RUST_ECDH_NISTP256,
        OSSH_RUST_ECDH_NISTP384, OSSH_RUST_ECDH_NISTP521, SNTRUP761X25519_CLIENT_BLOB_LENGTH,
        SNTRUP761X25519_SERVER_BLOB_LENGTH, SNTRUP761_SECRET_KEY_LENGTH, X25519_BASEPOINT_BYTES,
    };

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
        let curve = EcdhCurve::from_id(curve_id).unwrap();
        let mut alice_secret = vec![0u8; secret_len];
        let mut alice_public = vec![0u8; public_len];
        let mut bob_secret = vec![0u8; secret_len];
        let mut bob_public = vec![0u8; public_len];
        let mut alice_shared = vec![0u8; shared_len];
        let mut bob_shared = vec![0u8; shared_len];

        curve
            .generate_keypair(&mut alice_secret, &mut alice_public)
            .unwrap();
        curve
            .generate_keypair(&mut bob_secret, &mut bob_public)
            .unwrap();
        curve
            .shared_secret(&alice_secret, &bob_public, &mut alice_shared)
            .unwrap();
        curve
            .shared_secret(&bob_secret, &alice_public, &mut bob_shared)
            .unwrap();

        assert_eq!(alice_shared, bob_shared);
        assert!(alice_shared.iter().any(|byte| *byte != 0));
    }

    fn assert_nist_ecdh_invalid_public_rejected(
        curve_id: i32,
        secret_len: usize,
        public_len: usize,
        shared_len: usize,
    ) {
        let curve = EcdhCurve::from_id(curve_id).unwrap();
        let mut secret = vec![0u8; secret_len];
        let mut public = vec![0u8; public_len];
        let mut shared = vec![0u8; shared_len];

        curve.generate_keypair(&mut secret, &mut public).unwrap();
        public[0] ^= 0x01;
        assert_eq!(curve.shared_secret(&secret, &public, &mut shared), Err(()));
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
        let verifying_key =
            VerifyingKey::from_bytes(public.as_slice().try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(signature.as_slice().try_into().unwrap());

        assert_eq!(
            signing_key.verifying_key().to_bytes().as_slice(),
            public.as_slice()
        );
        assert_eq!(
            signing_key.sign(&[]).to_bytes().as_slice(),
            signature.as_slice()
        );
        assert!(verifying_key.verify_strict(&[], &sig).is_ok());
    }

    #[test]
    fn ed25519_ffi_roundtrip() {
        let mut seed = [0u8; 32];
        let msg = b"ffi roundtrip";
        let mut public = [0u8; 32];
        let mut sig = [0u8; 64];
        let mut secret = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }

        assert_eq!(
            ed25519_public_from_seed(seed.as_ptr(), seed.len(), public.as_mut_ptr(), public.len()),
            0
        );
        secret[..32].copy_from_slice(&seed);
        secret[32..].copy_from_slice(&public);
        assert_eq!(
            ed25519_sign(
                sig.as_mut_ptr(),
                sig.len(),
                msg.as_ptr(),
                msg.len(),
                secret.as_ptr(),
                secret.len()
            ),
            0
        );
        assert_eq!(
            ed25519_verify(
                sig.as_ptr(),
                sig.len(),
                msg.as_ptr(),
                msg.len(),
                public.as_ptr(),
                public.len()
            ),
            0
        );
    }

    fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    #[test]
    fn ed25519_public_blob_parse_consumes_public_section() {
        let mut seed = [0u8; 32];
        let mut public = [0u8; 32];
        let mut parsed = [0u8; 32];
        let mut consumed = 0usize;
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }

        assert_eq!(
            ed25519_public_from_seed(seed.as_ptr(), seed.len(), public.as_mut_ptr(), public.len()),
            0
        );

        let mut blob = Vec::new();
        put_string(&mut blob, &public);
        put_string(&mut blob, b"certificate-trailer");

        assert_eq!(
            ed25519_parse_public_blob(
                blob.as_ptr(),
                blob.len(),
                parsed.as_mut_ptr(),
                parsed.len(),
                &mut consumed,
            ),
            0
        );
        assert_eq!(parsed, public);
        assert_eq!(consumed, 4 + public.len());
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

        assert_eq!(
            x25519(alice_secret, X25519_BASEPOINT_BYTES).as_slice(),
            alice_public.as_slice()
        );
        assert_eq!(
            x25519(bob_secret, X25519_BASEPOINT_BYTES).as_slice(),
            bob_public.as_slice()
        );
        assert_eq!(
            x25519(alice_secret, bob_public.as_slice().try_into().unwrap()).as_slice(),
            shared.as_slice()
        );
        assert_eq!(
            x25519(bob_secret, alice_public.as_slice().try_into().unwrap()).as_slice(),
            shared.as_slice()
        );
    }

    #[test]
    fn curve25519_ffi_roundtrip() {
        let alice_secret = [7u8; 32];
        let bob_secret = [11u8; 32];
        let mut alice_public = [0u8; 32];
        let mut bob_public = [0u8; 32];
        let mut alice_shared = [0u8; 32];
        let mut bob_shared = [0u8; 32];

        assert_eq!(
            curve25519_public_from_secret(
                alice_public.as_mut_ptr(),
                alice_public.len(),
                alice_secret.as_ptr(),
                alice_secret.len()
            ),
            0
        );
        assert_eq!(
            curve25519_public_from_secret(
                bob_public.as_mut_ptr(),
                bob_public.len(),
                bob_secret.as_ptr(),
                bob_secret.len()
            ),
            0
        );
        assert_eq!(
            curve25519_shared_secret(
                alice_shared.as_mut_ptr(),
                alice_shared.len(),
                alice_secret.as_ptr(),
                alice_secret.len(),
                bob_public.as_ptr(),
                bob_public.len()
            ),
            0
        );
        assert_eq!(
            curve25519_shared_secret(
                bob_shared.as_mut_ptr(),
                bob_shared.len(),
                bob_secret.as_ptr(),
                bob_secret.len(),
                alice_public.as_ptr(),
                alice_public.len()
            ),
            0
        );
        assert_eq!(alice_shared, bob_shared);
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
    fn x25519_randomized_roundtrips() {
        let mut rng = rand_core::OsRng;

        for _ in 0..32 {
            let mut alice_secret = [0u8; 32];
            let mut bob_secret = [0u8; 32];
            rng.fill_bytes(&mut alice_secret);
            rng.fill_bytes(&mut bob_secret);

            let alice_public = x25519(alice_secret, X25519_BASEPOINT_BYTES);
            let bob_public = x25519(bob_secret, X25519_BASEPOINT_BYTES);
            let alice_shared = x25519(alice_secret, bob_public);
            let bob_shared = x25519(bob_secret, alice_public);

            assert_eq!(alice_shared, bob_shared);
            assert!(alice_shared.iter().any(|byte| *byte != 0));
        }
    }

    #[test]
    fn nist_ecdh_randomized_roundtrips() {
        for _ in 0..16 {
            assert_nist_ecdh_roundtrip(OSSH_RUST_ECDH_NISTP256, 32, 65, 32);
            assert_nist_ecdh_roundtrip(OSSH_RUST_ECDH_NISTP384, 48, 97, 48);
            assert_nist_ecdh_roundtrip(OSSH_RUST_ECDH_NISTP521, 66, 133, 66);
        }
    }

    #[test]
    fn nist_ecdh_rejects_invalid_public_points() {
        assert_nist_ecdh_invalid_public_rejected(OSSH_RUST_ECDH_NISTP256, 32, 65, 32);
        assert_nist_ecdh_invalid_public_rejected(OSSH_RUST_ECDH_NISTP384, 48, 97, 48);
        assert_nist_ecdh_invalid_public_rejected(OSSH_RUST_ECDH_NISTP521, 66, 133, 66);
    }

    #[test]
    fn mlkem768x25519_roundtrip() {
        let mut client_blob = [0u8; MLKEM768X25519_CLIENT_BLOB_LENGTH];
        let mut client_mlkem_secret = [0u8; MLKEM768_SECRET_KEY_LENGTH];
        let mut client_curve_secret = [0u8; CURVE25519_KEY_LENGTH];
        let mut server_blob = [0u8; MLKEM768X25519_SERVER_BLOB_LENGTH];
        let mut server_shared = [0u8; 32];
        let mut client_shared = [0u8; 32];

        assert_eq!(
            mlkem768x25519_keypair(
                client_blob.as_mut_ptr(),
                client_blob.len(),
                client_mlkem_secret.as_mut_ptr(),
                client_mlkem_secret.len(),
                client_curve_secret.as_mut_ptr(),
                client_curve_secret.len(),
            ),
            0
        );
        assert_eq!(
            mlkem768x25519_enc(
                client_blob.as_ptr(),
                client_blob.len(),
                server_blob.as_mut_ptr(),
                server_blob.len(),
                server_shared.as_mut_ptr(),
                server_shared.len(),
            ),
            0
        );
        assert_eq!(
            mlkem768x25519_dec(
                server_blob.as_ptr(),
                server_blob.len(),
                client_mlkem_secret.as_ptr(),
                client_mlkem_secret.len(),
                client_curve_secret.as_ptr(),
                client_curve_secret.len(),
                client_shared.as_mut_ptr(),
                client_shared.len(),
            ),
            0
        );
        assert_eq!(client_shared, server_shared);
    }

    #[test]
    fn sntrup761x25519_roundtrip() {
        let mut client_blob = [0u8; SNTRUP761X25519_CLIENT_BLOB_LENGTH];
        let mut client_sntrup_secret = [0u8; SNTRUP761_SECRET_KEY_LENGTH];
        let mut client_curve_secret = [0u8; CURVE25519_KEY_LENGTH];
        let mut server_blob = [0u8; SNTRUP761X25519_SERVER_BLOB_LENGTH];
        let mut server_shared = [0u8; 64];
        let mut client_shared = [0u8; 64];

        assert_eq!(
            sntrup761x25519_keypair(
                client_blob.as_mut_ptr(),
                client_blob.len(),
                client_sntrup_secret.as_mut_ptr(),
                client_sntrup_secret.len(),
                client_curve_secret.as_mut_ptr(),
                client_curve_secret.len(),
            ),
            0
        );
        assert_eq!(
            sntrup761x25519_enc(
                client_blob.as_ptr(),
                client_blob.len(),
                server_blob.as_mut_ptr(),
                server_blob.len(),
                server_shared.as_mut_ptr(),
                server_shared.len(),
            ),
            0
        );
        assert_eq!(
            sntrup761x25519_dec(
                server_blob.as_ptr(),
                server_blob.len(),
                client_sntrup_secret.as_ptr(),
                client_sntrup_secret.len(),
                client_curve_secret.as_ptr(),
                client_curve_secret.len(),
                client_shared.as_mut_ptr(),
                client_shared.len(),
            ),
            0
        );
        assert_eq!(client_shared, server_shared);
    }
}
