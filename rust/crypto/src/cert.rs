use crate::util::SshWireReader;

const SSH2_CERT_TYPE_USER: u32 = 1;
const SSH2_CERT_TYPE_HOST: u32 = 2;
const SSHKEY_CERT_MAX_PRINCIPALS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedCertBody {
    pub(crate) serial: u64,
    pub(crate) cert_type: u32,
    pub(crate) valid_after: u64,
    pub(crate) valid_before: u64,
    pub(crate) signed_consumed: usize,
    pub(crate) total_consumed: usize,
    pub(crate) key_id_offset: usize,
    pub(crate) key_id_len: usize,
    pub(crate) principals_offset: usize,
    pub(crate) principals_len: usize,
    pub(crate) critical_offset: usize,
    pub(crate) critical_len: usize,
    pub(crate) extensions_offset: usize,
    pub(crate) extensions_len: usize,
    pub(crate) ca_key_offset: usize,
    pub(crate) ca_key_len: usize,
    pub(crate) signature_offset: usize,
    pub(crate) signature_len: usize,
}

fn validate_option_section(mut section: SshWireReader<'_>) -> Option<()> {
    while section.consumed() != section.input_len() {
        section.get_string()?;
        section.get_string()?;
    }
    Some(())
}

fn validate_principals(mut section: SshWireReader<'_>) -> Option<()> {
    let mut count = 0usize;

    while section.consumed() != section.input_len() {
        if count >= SSHKEY_CERT_MAX_PRINCIPALS {
            return None;
        }
        section.get_cstring()?;
        count += 1;
    }
    Some(())
}

pub(crate) fn parse_cert_body(input: &[u8]) -> Option<ParsedCertBody> {
    let mut reader = SshWireReader::new(input);

    let serial = reader.get_u64()?;
    let cert_type = reader.get_u32()?;
    let (key_id_offset, key_id_raw) = reader.get_string_with_offset()?;
    let key_id = match key_id_raw.iter().position(|byte| *byte == 0) {
        Some(pos) if pos + 1 != key_id_raw.len() => return None,
        Some(pos) => &key_id_raw[..pos],
        None => key_id_raw,
    };
    let (principals_offset, principals) = reader.get_string_with_offset()?;
    let valid_after = reader.get_u64()?;
    let valid_before = reader.get_u64()?;
    let (critical_offset, critical) = reader.get_string_with_offset()?;
    let (extensions_offset, extensions) = reader.get_string_with_offset()?;
    reader.get_string()?;
    let (ca_key_offset, ca_key) = reader.get_string_with_offset()?;
    let signed_consumed = reader.consumed();
    let (signature_offset, signature) = reader.get_string_with_offset()?;

    if reader.consumed() != input.len() {
        return None;
    }
    if cert_type != SSH2_CERT_TYPE_USER && cert_type != SSH2_CERT_TYPE_HOST {
        return Some(ParsedCertBody {
            serial,
            cert_type,
            valid_after,
            valid_before,
            signed_consumed,
            total_consumed: reader.consumed(),
            key_id_offset,
            key_id_len: key_id.len(),
            principals_offset,
            principals_len: principals.len(),
            critical_offset,
            critical_len: critical.len(),
            extensions_offset,
            extensions_len: extensions.len(),
            ca_key_offset,
            ca_key_len: ca_key.len(),
            signature_offset,
            signature_len: signature.len(),
        });
    }

    validate_principals(SshWireReader::new(principals))?;
    validate_option_section(SshWireReader::new(critical))?;
    validate_option_section(SshWireReader::new(extensions))?;

    Some(ParsedCertBody {
        serial,
        cert_type,
        valid_after,
        valid_before,
        signed_consumed,
        total_consumed: reader.consumed(),
        key_id_offset,
        key_id_len: key_id.len(),
        principals_offset,
        principals_len: principals.len(),
        critical_offset,
        critical_len: critical.len(),
        extensions_offset,
        extensions_len: extensions.len(),
        ca_key_offset,
        ca_key_len: ca_key.len(),
        signature_offset,
        signature_len: signature.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_cert_body, SSH2_CERT_TYPE_USER};

    fn put_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn put_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn put_string(out: &mut Vec<u8>, value: &[u8]) {
        put_u32(out, value.len() as u32);
        out.extend_from_slice(value);
    }

    fn cert_body_with_sections(
        principals: &[&[u8]],
        critical_blob: &[u8],
        extensions_blob: &[u8],
    ) -> Vec<u8> {
        let mut principals_blob = Vec::new();
        let mut out = Vec::new();

        for principal in principals {
            put_string(&mut principals_blob, principal);
        }

        put_u64(&mut out, 7);
        put_u32(&mut out, SSH2_CERT_TYPE_USER);
        put_string(&mut out, b"test-key-id");
        put_string(&mut out, &principals_blob);
        put_u64(&mut out, 11);
        put_u64(&mut out, 13);
        put_string(&mut out, critical_blob);
        put_string(&mut out, extensions_blob);
        put_string(&mut out, b"");
        put_string(&mut out, b"ca-key");
        put_string(&mut out, b"signature");
        out
    }

    fn cert_body(principals: &[&[u8]], critical_pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut critical_blob = Vec::new();

        for (name, value) in critical_pairs {
            put_string(&mut critical_blob, name);
            put_string(&mut critical_blob, value);
        }
        cert_body_with_sections(principals, &critical_blob, b"")
    }

    #[test]
    fn cert_body_parse_accepts_valid_sections() {
        let body = cert_body(&[b"alice", b"bob"], &[(b"force-command", b"true")]);
        let parsed = parse_cert_body(&body).expect("valid cert body");

        assert_eq!(parsed.serial, 7);
        assert_eq!(parsed.cert_type, SSH2_CERT_TYPE_USER);
        assert_eq!(parsed.key_id_len, b"test-key-id".len());
        assert_eq!(parsed.principals_len, 16);
        assert_eq!(parsed.signature_len, b"signature".len());
        assert_eq!(parsed.total_consumed, body.len());
        assert!(parsed.signed_consumed < parsed.total_consumed);
    }

    #[test]
    fn cert_body_parse_rejects_malformed_principals() {
        let mut body = cert_body(&[b"alice"], &[]);
        let principals_len_offset = 4 + 8 + 4 + b"test-key-id".len();
        let principals_offset = principals_len_offset + 4;

        body[principals_offset + 4] = 0;
        assert!(parse_cert_body(&body).is_none());
    }

    #[test]
    fn cert_body_parse_rejects_malformed_critical_options() {
        let mut invalid_critical = Vec::new();

        put_string(&mut invalid_critical, b"force-command");
        let body = cert_body_with_sections(&[b"alice"], &invalid_critical, b"");
        assert!(parse_cert_body(&body).is_none());
    }
}
