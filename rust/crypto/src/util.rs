use core::ffi::c_int;
use core::slice;

pub(crate) const SSHBUF_MAX_BIGNUM: usize = 16_384 / 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArgvSplitParse {
    pub(crate) argc: usize,
    pub(crate) packed_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StrdelimParse {
    pub(crate) next_offset: usize,
    pub(crate) next_is_null: u32,
}

pub(crate) fn read_array<const N: usize>(ptr: *const u8, len: usize) -> Option<[u8; N]> {
    if ptr.is_null() || len != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(unsafe { slice::from_raw_parts(ptr, N) });
    Some(out)
}

pub(crate) fn read_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

pub(crate) fn read_slice_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        Some(&mut [])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
    }
}

pub(crate) fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        core::ptr::null()
    } else {
        bytes.as_ptr()
    }
}

pub(crate) struct SshWireReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> SshWireReader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn consumed(&self) -> usize {
        self.offset
    }

    pub(crate) fn input_len(&self) -> usize {
        self.input.len()
    }

    pub(crate) fn get_u32(&mut self) -> Option<u32> {
        let bytes = self.input.get(self.offset..self.offset + 4)?;
        self.offset += 4;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    pub(crate) fn get_u64(&mut self) -> Option<u64> {
        let bytes = self.input.get(self.offset..self.offset + 8)?;
        self.offset += 8;
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }

    pub(crate) fn get_u8(&mut self) -> Option<u8> {
        let byte = *self.input.get(self.offset)?;
        self.offset += 1;
        Some(byte)
    }

    pub(crate) fn get_string(&mut self) -> Option<&'a [u8]> {
        let (_, bytes) = self.get_string_with_offset()?;
        Some(bytes)
    }

    pub(crate) fn get_string_with_offset(&mut self) -> Option<(usize, &'a [u8])> {
        let len = usize::try_from(self.get_u32()?).ok()?;
        let offset = self.offset;
        let bytes = self.input.get(offset..offset + len)?;
        self.offset += len;
        Some((offset, bytes))
    }

    pub(crate) fn get_cstring(&mut self) -> Option<&'a [u8]> {
        let (_, bytes) = self.get_cstring_with_offset()?;
        Some(bytes)
    }

    pub(crate) fn get_cstring_with_offset(&mut self) -> Option<(usize, &'a [u8])> {
        let (offset, bytes) = self.get_string_with_offset()?;
        match bytes.iter().position(|byte| *byte == 0) {
            Some(pos) if pos + 1 != bytes.len() => None,
            Some(pos) => Some((offset, &bytes[..pos])),
            None => Some((offset, bytes)),
        }
    }

    pub(crate) fn get_mpint(&mut self) -> Option<&'a [u8]> {
        let (_, bytes) = self.get_mpint_with_offset()?;
        Some(bytes)
    }

    pub(crate) fn get_mpint_with_offset(&mut self) -> Option<(usize, &'a [u8])> {
        let (offset, bytes) = self.get_string_with_offset()?;
        if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            return None;
        }
        if bytes.len() > SSHBUF_MAX_BIGNUM + 1
            || (bytes.len() == SSHBUF_MAX_BIGNUM + 1 && bytes[0] != 0)
        {
            return None;
        }
        let first_nonzero = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
        Some((offset + first_nonzero, &bytes[first_nonzero..]))
    }
}

pub(crate) fn write_prefix(out: *mut u8, out_len: usize, bytes: &[u8]) -> c_int {
    if out.is_null() || out_len < bytes.len() {
        return -1;
    }
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    out[..bytes.len()].copy_from_slice(bytes);
    0
}

pub(crate) fn argv_split_parse(
    input: *const u8,
    input_len: usize,
    terminate_on_comment: c_int,
) -> Option<ArgvSplitParse> {
    let input = read_slice(input, input_len)?;
    let argv = parse_argv(input, terminate_on_comment != 0)?;
    Some(ArgvSplitParse {
        argc: argv.len(),
        packed_len: argv.iter().map(|arg| arg.len() + 1).sum(),
    })
}

pub(crate) fn argv_split_write(
    input: *const u8,
    input_len: usize,
    terminate_on_comment: c_int,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let input = match read_slice(input, input_len) {
        Some(input) => input,
        None => return -1,
    };
    let argv = match parse_argv(input, terminate_on_comment != 0) {
        Some(argv) => argv,
        None => return -1,
    };
    let packed_len: usize = argv.iter().map(|arg| arg.len() + 1).sum();
    if out.is_null() || out_len < packed_len {
        return -1;
    }
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    let mut offset = 0usize;
    for arg in argv {
        out[offset..offset + arg.len()].copy_from_slice(&arg);
        offset += arg.len();
        out[offset] = 0;
        offset += 1;
    }
    0
}

pub(crate) fn strdelim_parse_in_place(
    input: *mut u8,
    input_len: usize,
    split_equals: c_int,
) -> Option<StrdelimParse> {
    let input = read_slice_mut(input, input_len)?;
    if input.is_empty() {
        return Some(StrdelimParse {
            next_offset: 0,
            next_is_null: 1,
        });
    }
    let nul = input.iter().position(|byte| *byte == 0)?;
    let split_equals = split_equals != 0;
    let mut delim = None;
    for (idx, byte) in input[..nul].iter().enumerate() {
        if matches!(*byte, b' ' | b'\t' | b'\r' | b'\n' | b'"')
            || (split_equals && *byte == b'=')
        {
            delim = Some(idx);
            break;
        }
    }
    let Some(pos) = delim else {
        return Some(StrdelimParse {
            next_offset: 0,
            next_is_null: 1,
        });
    };

    if input[pos] == b'"' {
        input.copy_within(pos + 1..=nul, pos);
        let new_nul = nul - 1;
        let closing = input[pos..new_nul]
            .iter()
            .position(|byte| *byte == b'"')
            .map(|off| pos + off)?;
        input[closing] = 0;
        let mut next_offset = closing + 1;
        while matches!(input.get(next_offset), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            next_offset += 1;
        }
        return Some(StrdelimParse {
            next_offset,
            next_is_null: 0,
        });
    }

    let wspace = split_equals && input[pos] == b'=';
    input[pos] = 0;
    let mut next_offset = pos + 1;
    while matches!(input.get(next_offset), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        next_offset += 1;
    }
    if split_equals && matches!(input.get(next_offset), Some(b'=')) && !wspace {
        next_offset += 1;
        while matches!(input.get(next_offset), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            next_offset += 1;
        }
    }
    Some(StrdelimParse {
        next_offset,
        next_is_null: 0,
    })
}

fn parse_argv(input: &[u8], terminate_on_comment: bool) -> Option<Vec<Vec<u8>>> {
    let mut argv = Vec::new();
    let mut i = 0usize;

    while i < input.len() {
        if input[i] == b' ' || input[i] == b'\t' {
            i += 1;
            continue;
        }
        if terminate_on_comment && input[i] == b'#' {
            break;
        }

        let mut quote = 0u8;
        let mut arg = Vec::new();
        while i < input.len() {
            let byte = input[i];
            if byte == b'\\' {
                let next = input.get(i + 1).copied();
                if matches!(next, Some(b'\'') | Some(b'"') | Some(b'\\'))
                    || (quote == 0 && next == Some(b' '))
                {
                    i += 1;
                    arg.push(input[i]);
                } else {
                    arg.push(byte);
                }
            } else if quote == 0 && (byte == b' ' || byte == b'\t') {
                break;
            } else if quote == 0 && (byte == b'"' || byte == b'\'') {
                quote = byte;
            } else if quote != 0 && byte == quote {
                quote = 0;
            } else {
                arg.push(byte);
            }
            i += 1;
        }
        if i == input.len() && quote != 0 {
            return None;
        }
        argv.push(arg);
    }

    Some(argv)
}

#[cfg(test)]
mod tests {
    use super::{argv_split_parse, argv_split_write, strdelim_parse_in_place};

    fn split(input: &[u8], terminate_on_comment: bool) -> Option<Vec<Vec<u8>>> {
        let parsed = argv_split_parse(input.as_ptr(), input.len(), terminate_on_comment as i32)?;
        let mut packed = vec![0u8; parsed.packed_len];
        if argv_split_write(
            input.as_ptr(),
            input.len(),
            terminate_on_comment as i32,
            packed.as_mut_ptr(),
            packed.len(),
        ) != 0
        {
            return None;
        }
        let mut out = Vec::new();
        let mut start = 0usize;
        for _ in 0..parsed.argc {
            let end = packed[start..].iter().position(|byte| *byte == 0)? + start;
            out.push(packed[start..end].to_vec());
            start = end + 1;
        }
        Some(out)
    }

    #[test]
    fn argv_split_handles_quotes_and_comments() {
        assert_eq!(
            split(b"\"leamas # gold\"", true),
            Some(vec![b"leamas # gold".to_vec()])
        );
        assert_eq!(split(b"# gold", true), Some(Vec::new()));
        assert_eq!(split(b"   # gold", true), Some(Vec::new()));
        assert_eq!(
            split(b"\"leamas\"#gold", true),
            Some(vec![b"leamas#gold".to_vec()])
        );
        assert_eq!(
            split(b"\"leamas\" #gold", true),
            Some(vec![b"leamas".to_vec()])
        );
    }

    #[test]
    fn argv_split_handles_escapes() {
        assert_eq!(
            split(br#""smiley\ leamas""#, false),
            Some(vec![br#"smiley\ leamas"#.to_vec()])
        );
        assert_eq!(
            split(br#"smiley\ leamas"#, false),
            Some(vec![b"smiley leamas".to_vec()])
        );
        assert_eq!(
            split(br#"smiley\'s leamas\'"#, false),
            Some(vec![b"smiley's".to_vec(), b"leamas'".to_vec()])
        );
    }

    #[test]
    fn argv_split_rejects_unterminated_quote() {
        assert_eq!(split(br#""smiley"#, false), None);
        assert_eq!(split(b"'smiley", false), None);
    }

    fn strdelim_next(input: &[u8], split_equals: bool) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let mut buf = input.to_vec();
        buf.push(0);
        let parsed = strdelim_parse_in_place(buf.as_mut_ptr(), buf.len(), split_equals as i32)?;
        let token_end = buf.iter().position(|byte| *byte == 0)?;
        let token = buf[..token_end].to_vec();
        let rest = if parsed.next_is_null != 0 {
            None
        } else {
            let rest_end = buf[parsed.next_offset..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|off| parsed.next_offset + off)?;
            Some(buf[parsed.next_offset..rest_end].to_vec())
        };
        Some((token, rest))
    }

    #[test]
    fn strdelim_handles_equals_and_quotes() {
        assert_eq!(
            strdelim_next(b"blob1=blob2", true),
            Some((b"blob1".to_vec(), Some(b"blob2".to_vec())))
        );
        assert_eq!(
            strdelim_next(b"\"blob1\" blob2", true),
            Some((b"blob1".to_vec(), Some(b"blob2".to_vec())))
        );
        assert_eq!(
            strdelim_next(b"blob1=blob2", false),
            Some((b"blob1=blob2".to_vec(), None))
        );
    }

    #[test]
    fn strdelim_rejects_unterminated_quote() {
        assert_eq!(strdelim_next(b"\"blob", true), None);
    }
}
