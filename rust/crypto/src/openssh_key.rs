use base64ct::{Base64, Base64Unpadded, Encoding};

use crate::util::{read_slice, write_prefix, SshWireReader};

const MARK_BEGIN: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
const MARK_END: &[u8] = b"-----END OPENSSH PRIVATE KEY-----\n";
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
const KDF_NONE: &[u8] = b"none";
const KDF_BCRYPT: &[u8] = b"bcrypt";

pub(crate) const OSSH_RUST_PRIVATE2_KDF_NONE: u32 = 0;
pub(crate) const OSSH_RUST_PRIVATE2_KDF_BCRYPT: u32 = 1;
pub(crate) const OSSH_RUST_PRIVATE2_KEY_UNSUPPORTED: u32 = 0;
pub(crate) const OSSH_RUST_PRIVATE2_KEY_ED25519: u32 = 1;
pub(crate) const OSSH_RUST_PRIVATE2_KEY_ECDSA: u32 = 2;
pub(crate) const OSSH_RUST_PRIVATE2_KEY_RSA: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenSshPrivate2Parse {
    pub(crate) ciphername_offset: usize,
    pub(crate) ciphername_len: usize,
    pub(crate) kdfname_offset: usize,
    pub(crate) kdfname_len: usize,
    pub(crate) kdf_offset: usize,
    pub(crate) kdf_len: usize,
    pub(crate) public_key_offset: usize,
    pub(crate) public_key_len: usize,
    pub(crate) encrypted_offset: usize,
    pub(crate) encrypted_len: usize,
    pub(crate) bcrypt_salt_offset: usize,
    pub(crate) bcrypt_salt_len: usize,
    pub(crate) bcrypt_rounds: u32,
    pub(crate) kdf_kind: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenSshPrivate2PlaintextParse {
    pub(crate) key_kind: u32,
    pub(crate) curve_nid: i32,
    pub(crate) is_cert: u32,
    pub(crate) cert_offset: usize,
    pub(crate) cert_len: usize,
    pub(crate) comment_offset: usize,
    pub(crate) comment_len: usize,
    pub(crate) part1_offset: usize,
    pub(crate) part1_len: usize,
    pub(crate) part2_offset: usize,
    pub(crate) part2_len: usize,
    pub(crate) part3_offset: usize,
    pub(crate) part3_len: usize,
    pub(crate) part4_offset: usize,
    pub(crate) part4_len: usize,
    pub(crate) part5_offset: usize,
    pub(crate) part5_len: usize,
    pub(crate) part6_offset: usize,
    pub(crate) part6_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenSshPublicLineParse {
    pub(crate) key_type_offset: usize,
    pub(crate) key_type_len: usize,
    pub(crate) key_blob_offset: usize,
    pub(crate) key_blob_len: usize,
    pub(crate) comment_offset: usize,
}

pub(crate) fn openssh_private2_decode_len(input: *const u8, input_len: usize) -> usize {
    let Some(input) = read_slice(input, input_len) else {
        return 0;
    };
    decode_private2_armored(input).map_or(0, |decoded| decoded.len())
}

pub(crate) fn openssh_public_line_parse(
    input: *const u8,
    input_len: usize,
) -> Option<OpenSshPublicLineParse> {
    let input = read_slice(input, input_len)?;
    parse_public_key_line(input)
}

pub(crate) fn openssh_public_blob_decode_len(input: *const u8, input_len: usize) -> usize {
    let Some(input) = read_slice(input, input_len) else {
        return 0;
    };
    decode_public_blob(input).map_or(0, |decoded| decoded.len())
}

pub(crate) fn openssh_public_blob_decode_write(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let Some(input) = read_slice(input, input_len) else {
        return -1;
    };
    let decoded = match decode_public_blob(input) {
        Some(decoded) => decoded,
        None => return -1,
    };
    write_prefix(out, out_len, &decoded)
}

pub(crate) fn openssh_private2_decode_write(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let Some(input) = read_slice(input, input_len) else {
        return -1;
    };
    let decoded = match decode_private2_armored(input) {
        Some(decoded) => decoded,
        None => return -1,
    };
    write_prefix(out, out_len, &decoded)
}

pub(crate) fn openssh_private2_parse(
    decoded: *const u8,
    decoded_len: usize,
) -> Option<OpenSshPrivate2Parse> {
    let decoded = read_slice(decoded, decoded_len)?;
    parse_private2_header(decoded)
}

pub(crate) fn openssh_private2_parse_plaintext(
    decrypted: *const u8,
    decrypted_len: usize,
) -> Option<OpenSshPrivate2PlaintextParse> {
    let decrypted = read_slice(decrypted, decrypted_len)?;
    parse_private2_plaintext(decrypted)
}

fn decode_private2_armored(input: &[u8]) -> Option<Vec<u8>> {
    if !input.starts_with(MARK_BEGIN) {
        return None;
    }
    let mut encoded = Vec::new();
    let mut cp = &input[MARK_BEGIN.len()..];

    while !cp.is_empty() {
        if cp[0] != b'\n' && cp[0] != b'\r' {
            encoded.push(cp[0]);
        }
        let last = cp[0];
        cp = &cp[1..];
        if last == b'\n' && cp.starts_with(MARK_END) {
            let decoded = Base64::decode_vec(core::str::from_utf8(&encoded).ok()?).ok()?;
            if !decoded.starts_with(AUTH_MAGIC) {
                return None;
            }
            return Some(decoded);
        }
    }
    None
}

fn parse_private2_header(decoded: &[u8]) -> Option<OpenSshPrivate2Parse> {
    if !decoded.starts_with(AUTH_MAGIC) {
        return None;
    }
    let mut reader = SshWireReader::new(&decoded[AUTH_MAGIC.len()..]);
    let base = AUTH_MAGIC.len();

    let (ciphername_offset, ciphername) = reader.get_string_with_offset()?;
    let (kdfname_offset, kdfname) = reader.get_string_with_offset()?;
    let (kdf_offset, kdf) = reader.get_string_with_offset()?;
    let nkeys = reader.get_u32()?;
    if nkeys != 1 {
        return None;
    }
    let (public_key_offset, public_key) = reader.get_string_with_offset()?;
    let encrypted_len = usize::try_from(reader.get_u32()?).ok()?;
    let encrypted_offset = base + reader.consumed();
    decoded.get(encrypted_offset..encrypted_offset + encrypted_len)?;

    let mut parsed = OpenSshPrivate2Parse {
        ciphername_offset: base + ciphername_offset,
        ciphername_len: ciphername.len(),
        kdfname_offset: base + kdfname_offset,
        kdfname_len: kdfname.len(),
        kdf_offset: base + kdf_offset,
        kdf_len: kdf.len(),
        public_key_offset: base + public_key_offset,
        public_key_len: public_key.len(),
        encrypted_offset,
        encrypted_len,
        bcrypt_salt_offset: 0,
        bcrypt_salt_len: 0,
        bcrypt_rounds: 0,
        kdf_kind: OSSH_RUST_PRIVATE2_KDF_NONE,
    };

    match kdfname {
        KDF_NONE => {
            if !kdf.is_empty() {
                return None;
            }
        }
        KDF_BCRYPT => {
            let mut kdf_reader = SshWireReader::new(kdf);
            let (salt_offset, salt) = kdf_reader.get_string_with_offset()?;
            let rounds = kdf_reader.get_u32()?;
            if kdf_reader.consumed() != kdf.len() {
                return None;
            }
            parsed.bcrypt_salt_offset = base + kdf_offset + salt_offset;
            parsed.bcrypt_salt_len = salt.len();
            parsed.bcrypt_rounds = rounds;
            parsed.kdf_kind = OSSH_RUST_PRIVATE2_KDF_BCRYPT;
        }
        _ => return None,
    }

    Some(parsed)
}

fn parse_private2_plaintext(decrypted: &[u8]) -> Option<OpenSshPrivate2PlaintextParse> {
    let mut reader = SshWireReader::new(decrypted);
    let key_type = reader.get_cstring()?;
    let is_cert = is_cert_key_type(key_type);
    let mut cert_offset = 0usize;
    let mut cert_len = 0usize;
    let key_kind;
    let mut curve_nid = 0;
    let mut part1_offset = 0usize;
    let mut part1_len = 0usize;
    let mut part2_offset = 0usize;
    let mut part2_len = 0usize;
    let mut part3_offset = 0usize;
    let mut part3_len = 0usize;
    let mut part4_offset = 0usize;
    let mut part4_len = 0usize;
    let mut part5_offset = 0usize;
    let mut part5_len = 0usize;
    let mut part6_offset = 0usize;
    let mut part6_len = 0usize;

    if is_cert {
        let (offset, cert) = reader.get_string_with_offset()?;
        cert_offset = offset;
        cert_len = cert.len();
    }

    match key_type {
        b"ssh-ed25519" | b"ssh-ed25519-cert-v01@openssh.com" => {
            let (public_offset, public) = reader.get_string_with_offset()?;
            let (secret_offset, secret) = reader.get_string_with_offset()?;
            if secret.len() != 64 {
                return None;
            }
            key_kind = OSSH_RUST_PRIVATE2_KEY_ED25519;
            part1_offset = public_offset;
            part1_len = public.len();
            part2_offset = secret_offset;
            part2_len = secret.len();
        }
        b"ssh-rsa" | b"ssh-rsa-cert-v01@openssh.com" => {
            if !is_cert {
                let (n_offset, n) = reader.get_mpint_with_offset()?;
                let (e_offset, e) = reader.get_mpint_with_offset()?;
                part1_len = n.len();
                part1_offset = n_offset;
                part2_len = e.len();
                part2_offset = e_offset;
            }
            let (d_offset, d) = reader.get_mpint_with_offset()?;
            let (iqmp_offset, iqmp) = reader.get_mpint_with_offset()?;
            let (p_offset, p) = reader.get_mpint_with_offset()?;
            let (q_offset, q) = reader.get_mpint_with_offset()?;
            key_kind = OSSH_RUST_PRIVATE2_KEY_RSA;
            part3_offset = d_offset;
            part3_len = d.len();
            part4_offset = iqmp_offset;
            part4_len = iqmp.len();
            part5_offset = p_offset;
            part5_len = p.len();
            part6_offset = q_offset;
            part6_len = q.len();
        }
        b"ecdsa-sha2-nistp256"
        | b"ecdsa-sha2-nistp384"
        | b"ecdsa-sha2-nistp521"
        | b"ecdsa-sha2-nistp256-cert-v01@openssh.com"
        | b"ecdsa-sha2-nistp384-cert-v01@openssh.com"
        | b"ecdsa-sha2-nistp521-cert-v01@openssh.com" => {
            if !is_cert {
                let curve = reader.get_cstring()?;
                if curve_name_for_key_type(key_type)? != curve {
                    return None;
                }
                let (public_offset, public) = reader.get_string_with_offset()?;
                part1_offset = public_offset;
                part1_len = public.len();
            }
            let (private_offset, private_scalar) = reader.get_mpint_with_offset()?;
            key_kind = OSSH_RUST_PRIVATE2_KEY_ECDSA;
            curve_nid = curve_nid_for_key_type(key_type)?;
            part2_offset = private_offset;
            part2_len = private_scalar.len();
        }
        _ => {
            return Some(OpenSshPrivate2PlaintextParse {
                key_kind: OSSH_RUST_PRIVATE2_KEY_UNSUPPORTED,
                curve_nid: 0,
                is_cert: u32::from(is_cert),
                cert_offset,
                cert_len,
                comment_offset: 0,
                comment_len: 0,
                part1_offset: 0,
                part1_len: 0,
                part2_offset: 0,
                part2_len: 0,
                part3_offset: 0,
                part3_len: 0,
                part4_offset: 0,
                part4_len: 0,
                part5_offset: 0,
                part5_len: 0,
                part6_offset: 0,
                part6_len: 0,
            });
        }
    }

    let (comment_data_offset, comment) = reader.get_cstring_with_offset()?;
    let mut pad = 1u8;
    while reader.consumed() < reader.input_len() {
        if reader.get_u8()? != pad {
            return None;
        }
        pad = pad.wrapping_add(1);
    }

    Some(OpenSshPrivate2PlaintextParse {
        key_kind,
        curve_nid,
        is_cert: u32::from(is_cert),
        cert_offset,
        cert_len,
        comment_offset: comment_data_offset - 4,
        comment_len: comment.len(),
        part1_offset,
        part1_len,
        part2_offset,
        part2_len,
        part3_offset,
        part3_len,
        part4_offset,
        part4_len,
        part5_offset,
        part5_len,
        part6_offset,
        part6_len,
    })
}

fn parse_public_key_line(input: &[u8]) -> Option<OpenSshPublicLineParse> {
    let key_type_len = input
        .iter()
        .position(|byte| *byte == b' ' || *byte == b'\t')?;
    let key_type_offset = 0usize;
    if key_type_len == 0 {
        return None;
    }

    let mut offset = key_type_len;
    while matches!(input.get(offset), Some(b' ' | b'\t')) {
        offset += 1;
    }
    let key_blob_offset = offset;
    if key_blob_offset >= input.len() {
        return None;
    }
    let key_blob_len = input[key_blob_offset..]
        .iter()
        .position(|byte| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(input.len() - key_blob_offset);
    if key_blob_len == 0 {
        return None;
    }
    offset = key_blob_offset + key_blob_len;
    while matches!(input.get(offset), Some(b' ' | b'\t')) {
        offset += 1;
    }
    Some(OpenSshPublicLineParse {
        key_type_offset,
        key_type_len,
        key_blob_offset,
        key_blob_len,
        comment_offset: offset,
    })
}

fn decode_public_blob(input: &[u8]) -> Option<Vec<u8>> {
    let token = core::str::from_utf8(input).ok()?;
    Base64Unpadded::decode_vec(token)
        .ok()
        .or_else(|| Base64::decode_vec(token).ok())
}

fn is_cert_key_type(key_type: &[u8]) -> bool {
    key_type.ends_with(b"-cert-v01@openssh.com")
}

fn curve_name_for_key_type(key_type: &[u8]) -> Option<&'static [u8]> {
    match key_type {
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp256-cert-v01@openssh.com" => Some(b"nistp256"),
        b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp384-cert-v01@openssh.com" => Some(b"nistp384"),
        b"ecdsa-sha2-nistp521" | b"ecdsa-sha2-nistp521-cert-v01@openssh.com" => Some(b"nistp521"),
        _ => None,
    }
}

fn curve_nid_for_key_type(key_type: &[u8]) -> Option<i32> {
    match key_type {
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp256-cert-v01@openssh.com" => Some(415),
        b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp384-cert-v01@openssh.com" => Some(715),
        b"ecdsa-sha2-nistp521" | b"ecdsa-sha2-nistp521-cert-v01@openssh.com" => Some(716),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        openssh_private2_parse, openssh_private2_parse_plaintext, openssh_public_blob_decode_len,
        openssh_public_blob_decode_write, openssh_public_line_parse, OSSH_RUST_PRIVATE2_KDF_BCRYPT,
        OSSH_RUST_PRIVATE2_KDF_NONE,
    };

    const ED25519_1: &[u8] = include_bytes!("../../../regress/unittests/sshkey/testdata/ed25519_1");
    const ED25519_1_PW: &[u8] =
        include_bytes!("../../../regress/unittests/sshkey/testdata/ed25519_1_pw");

    #[test]
    fn parses_unencrypted_openssh_private_key_header() {
        let decoded_len = super::openssh_private2_decode_len(ED25519_1.as_ptr(), ED25519_1.len());
        assert!(decoded_len > 0);
        let mut decoded = vec![0u8; decoded_len];
        assert_eq!(
            0,
            super::openssh_private2_decode_write(
                ED25519_1.as_ptr(),
                ED25519_1.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
            )
        );
        let parsed = openssh_private2_parse(decoded.as_ptr(), decoded.len()).unwrap();
        assert_eq!(parsed.kdf_kind, OSSH_RUST_PRIVATE2_KDF_NONE);
        assert!(parsed.public_key_len > 0);
        assert!(parsed.encrypted_len > 0);
    }

    #[test]
    fn parses_bcrypt_openssh_private_key_header() {
        let decoded_len =
            super::openssh_private2_decode_len(ED25519_1_PW.as_ptr(), ED25519_1_PW.len());
        assert!(decoded_len > 0);
        let mut decoded = vec![0u8; decoded_len];
        assert_eq!(
            0,
            super::openssh_private2_decode_write(
                ED25519_1_PW.as_ptr(),
                ED25519_1_PW.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
            )
        );
        let parsed = openssh_private2_parse(decoded.as_ptr(), decoded.len()).unwrap();
        assert_eq!(parsed.kdf_kind, OSSH_RUST_PRIVATE2_KDF_BCRYPT);
        assert!(parsed.bcrypt_salt_len > 0);
        assert!(parsed.bcrypt_rounds > 0);
    }

    #[test]
    fn rejects_missing_markers() {
        assert_eq!(
            super::openssh_private2_decode_len(b"not a key".as_ptr(), 9),
            0
        );
    }

    fn decode_unencrypted_payload(key: &[u8]) -> Vec<u8> {
        let decoded_len = super::openssh_private2_decode_len(key.as_ptr(), key.len());
        assert!(decoded_len > 0);
        let mut decoded = vec![0u8; decoded_len];
        assert_eq!(
            0,
            super::openssh_private2_decode_write(
                key.as_ptr(),
                key.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
            )
        );
        let header = openssh_private2_parse(decoded.as_ptr(), decoded.len()).unwrap();
        let decrypted =
            &decoded[header.encrypted_offset..header.encrypted_offset + header.encrypted_len];
        assert!(decrypted.len() >= 8);
        assert_eq!(&decrypted[..4], &decrypted[4..8]);
        decrypted[8..].to_vec()
    }

    #[test]
    fn parses_plaintext_ed25519_private_section() {
        let decrypted = decode_unencrypted_payload(ED25519_1);
        let parsed = openssh_private2_parse_plaintext(decrypted.as_ptr(), decrypted.len()).unwrap();
        assert!(parsed.comment_len > 0);
        assert_eq!(
            &decrypted[parsed.comment_offset + 4..parsed.comment_offset + 4 + parsed.comment_len],
            b"ED25519 test key #1"
        );
    }

    #[test]
    fn parses_plaintext_ecdsa_private_section() {
        let decrypted = ssh_string(b"ecdsa-sha2-nistp256")
            .into_iter()
            .chain(ssh_string(b"nistp256"))
            .chain(ssh_string(&[4, 1, 2, 3]))
            .chain(ssh_string(&[1]))
            .chain(ssh_string(b"ecdsa-comment"))
            .chain([1u8, 2u8])
            .collect::<Vec<_>>();
        let parsed = openssh_private2_parse_plaintext(decrypted.as_ptr(), decrypted.len()).unwrap();
        assert_eq!(parsed.comment_len, b"ecdsa-comment".len());
    }

    #[test]
    fn parses_plaintext_rsa_private_section() {
        let decrypted = ssh_string(b"ssh-rsa")
            .into_iter()
            .chain(ssh_string(&[17]))
            .chain(ssh_string(&[3]))
            .chain(ssh_string(&[7]))
            .chain(ssh_string(&[5]))
            .chain(ssh_string(&[11]))
            .chain(ssh_string(&[13]))
            .chain(ssh_string(b"rsa-comment"))
            .chain([1u8, 2u8, 3u8])
            .collect::<Vec<_>>();
        let parsed = openssh_private2_parse_plaintext(decrypted.as_ptr(), decrypted.len()).unwrap();
        assert_eq!(parsed.comment_len, b"rsa-comment".len());
    }

    #[test]
    fn plaintext_unknown_key_type_reports_unsupported() {
        let decrypted = ssh_string(b"sk-ssh-ed25519@openssh.com");
        let parsed = openssh_private2_parse_plaintext(decrypted.as_ptr(), decrypted.len()).unwrap();
        assert_eq!(parsed.key_kind, super::OSSH_RUST_PRIVATE2_KEY_UNSUPPORTED);
    }

    #[test]
    fn plaintext_supported_key_type_rejects_malformed_body() {
        let decrypted = ssh_string(b"ssh-ed25519");
        assert!(openssh_private2_parse_plaintext(decrypted.as_ptr(), decrypted.len()).is_none());
    }

    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn parses_public_key_line_with_comment() {
        let line = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFOG6kY7Rf4UtCFvPwKgo/BztXck2xC4a2WyA34XtIwZ comment here";
        let parsed = openssh_public_line_parse(line.as_ptr(), line.len()).unwrap();

        assert_eq!(
            &line[parsed.key_type_offset..parsed.key_type_offset + parsed.key_type_len],
            b"ssh-ed25519"
        );
        assert_eq!(&line[parsed.comment_offset..], b"comment here");
    }

    #[test]
    fn parses_public_key_line_without_comment() {
        let line =
            b"ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIFOG6kY7Rf4UtCFvPwKgo/BztXck2xC4a2WyA34XtIwZ";
        let parsed = openssh_public_line_parse(line.as_ptr(), line.len()).unwrap();

        assert_eq!(
            &line[parsed.key_type_offset..parsed.key_type_offset + parsed.key_type_len],
            b"ssh-ed25519"
        );
        assert_eq!(parsed.comment_offset, line.len());
    }

    #[test]
    fn parses_public_key_line_without_comment_and_trailing_newline() {
        let line =
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFOG6kY7Rf4UtCFvPwKgo/BztXck2xC4a2WyA34XtIwZ\n";
        let parsed = openssh_public_line_parse(line.as_ptr(), line.len()).unwrap();

        assert_eq!(
            &line[parsed.key_type_offset..parsed.key_type_offset + parsed.key_type_len],
            b"ssh-ed25519"
        );
        assert_eq!(parsed.comment_offset, line.len() - 1);
    }

    #[test]
    fn rejects_public_key_line_without_blob() {
        let line = b"ssh-ed25519";
        assert!(openssh_public_line_parse(line.as_ptr(), line.len()).is_none());
    }

    #[test]
    fn rejects_public_key_line_with_leading_whitespace() {
        let line =
            b" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFOG6kY7Rf4UtCFvPwKgo/BztXck2xC4a2WyA34XtIwZ";
        assert!(openssh_public_line_parse(line.as_ptr(), line.len()).is_none());
    }

    #[test]
    fn decodes_unpadded_public_blob() {
        let blob = b"AAAAC3NzaC1lZDI1NTE5AAAAIFOG6kY7Rf4UtCFvPwKgo/BztXck2xC4a2WyA34XtIwZ";
        let decoded_len = openssh_public_blob_decode_len(blob.as_ptr(), blob.len());
        assert!(decoded_len > 0);
        let mut decoded = vec![0u8; decoded_len];
        assert_eq!(
            0,
            openssh_public_blob_decode_write(
                blob.as_ptr(),
                blob.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
            )
        );
        assert!(!decoded.is_empty());
    }
}
