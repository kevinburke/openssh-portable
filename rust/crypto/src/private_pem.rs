use aes::{Aes128, Aes192, Aes256};
use base64ct::{Base64, Encoding};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use des::{Des, TdesEde3};
use md5::{Digest, Md5};
use pkcs8::{
    der::{pem::PemLabel, SecretDocument},
    EncryptedPrivateKeyInfo,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivatePemError {
    InvalidFormat,
    WrongPassphrase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyPemLabel {
    RsaPrivateKey,
    EcPrivateKey,
}

struct PemEnvelope {
    label: String,
    body: String,
    proc_type: Option<String>,
    dek_info: Option<String>,
}

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes192CbcDec = cbc::Decryptor<Aes192>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type DesCbcDec = cbc::Decryptor<Des>;
type TdesCbcDec = cbc::Decryptor<TdesEde3>;

pub(crate) fn decrypt_legacy_private_pem(
    pem: &str,
    passphrase: &[u8],
) -> Result<(LegacyPemLabel, Vec<u8>), PrivatePemError> {
    let env = parse_pem_envelope(pem)?;
    let label = match env.label.as_str() {
        "RSA PRIVATE KEY" => LegacyPemLabel::RsaPrivateKey,
        "EC PRIVATE KEY" => LegacyPemLabel::EcPrivateKey,
        _ => return Err(PrivatePemError::InvalidFormat),
    };
    let proc_type = env
        .proc_type
        .as_deref()
        .ok_or(PrivatePemError::InvalidFormat)?;
    if proc_type != "4,ENCRYPTED" {
        return Err(PrivatePemError::InvalidFormat);
    }
    let dek_info = env
        .dek_info
        .as_deref()
        .ok_or(PrivatePemError::InvalidFormat)?;
    if passphrase.is_empty() {
        return Err(PrivatePemError::WrongPassphrase);
    }
    let ciphertext = Base64::decode_vec(&env.body).map_err(|_| PrivatePemError::InvalidFormat)?;
    let (alg, iv) = parse_dek_info(dek_info)?;
    let plaintext = decrypt_legacy_cipher(alg, passphrase, &iv, &ciphertext)?;
    Ok((label, plaintext))
}

pub(crate) fn decrypt_encrypted_pkcs8_pem(
    pem: &str,
    passphrase: &[u8],
) -> Result<Vec<u8>, PrivatePemError> {
    if passphrase.is_empty() {
        return Err(PrivatePemError::WrongPassphrase);
    }
    let (label, doc) = SecretDocument::from_pem(pem).map_err(|_| PrivatePemError::InvalidFormat)?;
    EncryptedPrivateKeyInfo::validate_pem_label(&label)
        .map_err(|_| PrivatePemError::InvalidFormat)?;
    let encrypted = EncryptedPrivateKeyInfo::try_from(doc.as_bytes())
        .map_err(|_| PrivatePemError::InvalidFormat)?;
    let decrypted = encrypted
        .decrypt(passphrase)
        .map_err(|_| PrivatePemError::WrongPassphrase)?;
    Ok(decrypted.as_bytes().to_vec())
}

fn parse_pem_envelope(pem: &str) -> Result<PemEnvelope, PrivatePemError> {
    let mut lines = pem.lines().map(|line| line.trim_end_matches('\r'));
    let begin = lines.next().ok_or(PrivatePemError::InvalidFormat)?;
    let label = begin
        .strip_prefix("-----BEGIN ")
        .and_then(|line| line.strip_suffix("-----"))
        .ok_or(PrivatePemError::InvalidFormat)?;
    let end_marker = format!("-----END {label}-----");
    let mut proc_type = None;
    let mut dek_info = None;
    let mut body = String::new();
    let mut in_headers = true;
    let mut saw_blank = false;

    for line in lines {
        if line == end_marker {
            if body.is_empty() {
                return Err(PrivatePemError::InvalidFormat);
            }
            return Ok(PemEnvelope {
                label: label.to_string(),
                body,
                proc_type,
                dek_info,
            });
        }
        if in_headers {
            if line.is_empty() {
                in_headers = false;
                saw_blank = true;
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                match name.trim() {
                    "Proc-Type" => proc_type = Some(value.trim().to_string()),
                    "DEK-Info" => dek_info = Some(value.trim().to_string()),
                    _ => {}
                }
                continue;
            }
            in_headers = false;
        }
        if line.is_empty() {
            continue;
        }
        if !saw_blank && (proc_type.is_some() || dek_info.is_some()) {
            return Err(PrivatePemError::InvalidFormat);
        }
        body.push_str(line.trim());
    }
    Err(PrivatePemError::InvalidFormat)
}

#[derive(Clone, Copy)]
enum LegacyCipher {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    DesCbc,
    TdesEde3Cbc,
}

impl LegacyCipher {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes192Cbc => 24,
            Self::Aes256Cbc => 32,
            Self::DesCbc => 8,
            Self::TdesEde3Cbc => 24,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => 16,
            Self::DesCbc | Self::TdesEde3Cbc => 8,
        }
    }
}

fn parse_dek_info(input: &str) -> Result<(LegacyCipher, Vec<u8>), PrivatePemError> {
    let (alg, iv_hex) = input
        .split_once(',')
        .ok_or(PrivatePemError::InvalidFormat)?;
    let cipher = match alg.trim() {
        "AES-128-CBC" => LegacyCipher::Aes128Cbc,
        "AES-192-CBC" => LegacyCipher::Aes192Cbc,
        "AES-256-CBC" => LegacyCipher::Aes256Cbc,
        "DES-CBC" => LegacyCipher::DesCbc,
        "DES-EDE3-CBC" => LegacyCipher::TdesEde3Cbc,
        _ => return Err(PrivatePemError::InvalidFormat),
    };
    let iv = decode_hex(iv_hex.trim())?;
    if iv.len() != cipher.iv_len() {
        return Err(PrivatePemError::InvalidFormat);
    }
    Ok((cipher, iv))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, PrivatePemError> {
    if input.len() % 2 != 0 {
        return Err(PrivatePemError::InvalidFormat);
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0]).ok_or(PrivatePemError::InvalidFormat)?;
        let lo = hex_nibble(chunk[1]).ok_or(PrivatePemError::InvalidFormat)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn evp_bytes_to_key_md5(passphrase: &[u8], salt: &[u8], key_len: usize, iv_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(key_len + iv_len);
    let mut prev = Vec::new();
    while material.len() < key_len + iv_len {
        let mut digest = Md5::new();
        if !prev.is_empty() {
            digest.update(&prev);
        }
        digest.update(passphrase);
        digest.update(salt);
        prev = digest.finalize().to_vec();
        material.extend_from_slice(&prev);
    }
    material.truncate(key_len + iv_len);
    material
}

fn decrypt_legacy_cipher(
    cipher: LegacyCipher,
    passphrase: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PrivatePemError> {
    let key_iv = evp_bytes_to_key_md5(passphrase, &iv[..8], cipher.key_len(), cipher.iv_len());
    let (key, _) = key_iv.split_at(cipher.key_len());
    let mut buf = ciphertext.to_vec();
    let plaintext = match cipher {
        LegacyCipher::Aes128Cbc => Aes128CbcDec::new_from_slices(key, iv)
            .map_err(|_| PrivatePemError::InvalidFormat)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| PrivatePemError::WrongPassphrase)?,
        LegacyCipher::Aes192Cbc => Aes192CbcDec::new_from_slices(key, iv)
            .map_err(|_| PrivatePemError::InvalidFormat)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| PrivatePemError::WrongPassphrase)?,
        LegacyCipher::Aes256Cbc => Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|_| PrivatePemError::InvalidFormat)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| PrivatePemError::WrongPassphrase)?,
        LegacyCipher::DesCbc => DesCbcDec::new_from_slices(key, iv)
            .map_err(|_| PrivatePemError::InvalidFormat)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| PrivatePemError::WrongPassphrase)?,
        LegacyCipher::TdesEde3Cbc => TdesCbcDec::new_from_slices(key, iv)
            .map_err(|_| PrivatePemError::InvalidFormat)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| PrivatePemError::WrongPassphrase)?,
    };
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::{decrypt_legacy_private_pem, LegacyPemLabel, PrivatePemError};

    const RSA_1_PW: &str = include_str!("../../../regress/unittests/sshkey/testdata/rsa_1_pw");
    const ECDSA_1_PW: &str = include_str!("../../../regress/unittests/sshkey/testdata/ecdsa_1_pw");
    const PASSWORD: &[u8] = b"mekmitasdigoat";

    #[test]
    fn decrypts_rsa_fixture() {
        let (label, der) = decrypt_legacy_private_pem(RSA_1_PW, PASSWORD).unwrap();
        assert_eq!(label, LegacyPemLabel::RsaPrivateKey);
        assert!(!der.is_empty());
    }

    #[test]
    fn decrypts_ecdsa_fixture() {
        let (label, der) = decrypt_legacy_private_pem(ECDSA_1_PW, PASSWORD).unwrap();
        assert_eq!(label, LegacyPemLabel::EcPrivateKey);
        assert!(!der.is_empty());
    }

    #[test]
    fn wrong_passphrase_is_reported() {
        let err = decrypt_legacy_private_pem(RSA_1_PW, b"wrong").unwrap_err();
        assert_eq!(err, PrivatePemError::WrongPassphrase);
    }
}
