use core::mem;
use core::ffi::{c_char, c_int, CStr};
use core::slice;
use std::ffi::CString;

use base64ct::{Base64, Encoding};
use rand_core::{OsRng, RngCore};
use sha1::{Digest, Sha1};

pub(crate) const SSHBUF_MAX_BIGNUM: usize = 16_384 / 8;
const HOST_HASH_MAGIC: &[u8] = b"|1|";
const HOST_HASH_DELIM: u8 = b'|';
const HOST_HASH_LEN: usize = 20;
const IPQOS_NONE: i32 = i32::MAX;
const IPQOS_AF11: i32 = 40;
const IPQOS_AF12: i32 = 48;
const IPQOS_AF13: i32 = 56;
const IPQOS_AF21: i32 = 72;
const IPQOS_AF22: i32 = 80;
const IPQOS_AF23: i32 = 88;
const IPQOS_AF31: i32 = 104;
const IPQOS_AF32: i32 = 112;
const IPQOS_AF33: i32 = 120;
const IPQOS_AF41: i32 = 136;
const IPQOS_AF42: i32 = 144;
const IPQOS_AF43: i32 = 152;
const IPQOS_CS0: i32 = 0;
const IPQOS_CS1: i32 = 32;
const IPQOS_CS2: i32 = 64;
const IPQOS_CS3: i32 = 96;
const IPQOS_CS4: i32 = 128;
const IPQOS_CS5: i32 = 160;
const IPQOS_CS6: i32 = 192;
const IPQOS_CS7: i32 = 224;
const IPQOS_EF: i32 = 184;
const IPQOS_LE: i32 = 4;
const IPQOS_VA: i32 = 176;
const IPQOS_LOWDELAY: i32 = i32::MIN;
const IPQOS_THROUGHPUT: i32 = 8;
const IPQOS_RELIABILITY: i32 = 4;

pub(crate) const DOMAIN_STATUS_EMPTY: c_int = 1;
pub(crate) const DOMAIN_STATUS_START_INVALID: c_int = 2;
pub(crate) const DOMAIN_STATUS_CONSECUTIVE_SEPARATORS: c_int = 3;
pub(crate) const DOMAIN_STATUS_INVALID_CHARS: c_int = 4;
pub(crate) const ATOI_STATUS_MISSING: c_int = 1;
pub(crate) const ATOI_STATUS_INVALID: c_int = 2;
pub(crate) const ATOI_STATUS_TOO_SMALL: c_int = 3;
pub(crate) const ATOI_STATUS_TOO_LARGE: c_int = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MultistateEntry {
    pub key: *const c_char,
    pub value: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KeywordEntry {
    pub key: *const c_char,
    pub value: c_int,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HpdelimParse {
    pub(crate) next_offset: usize,
    pub(crate) next_is_null: u32,
    pub(crate) delim: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserHostPortParse {
    pub(crate) user_offset: usize,
    pub(crate) user_len: usize,
    pub(crate) host_offset: usize,
    pub(crate) host_len: usize,
    pub(crate) port_offset: usize,
    pub(crate) port_len: usize,
    pub(crate) has_user: u32,
    pub(crate) has_port: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UriParse {
    pub(crate) user_offset: usize,
    pub(crate) user_len: usize,
    pub(crate) host_offset: usize,
    pub(crate) host_len: usize,
    pub(crate) port_offset: usize,
    pub(crate) port_len: usize,
    pub(crate) path_offset: usize,
    pub(crate) path_len: usize,
    pub(crate) has_user: u32,
    pub(crate) has_port: u32,
    pub(crate) has_path: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UserHostPathParse {
    pub(crate) user_offset: usize,
    pub(crate) user_len: usize,
    pub(crate) host_offset: usize,
    pub(crate) host_len: usize,
    pub(crate) path_offset: usize,
    pub(crate) path_len: usize,
    pub(crate) has_user: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForwardFieldParse {
    pub(crate) arg_offset: usize,
    pub(crate) next_offset: usize,
    pub(crate) ispath: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForwardParse {
    pub(crate) field_count: u32,
    pub(crate) listen_host_offset: usize,
    pub(crate) listen_host_len: usize,
    pub(crate) listen_port_offset: usize,
    pub(crate) listen_port_len: usize,
    pub(crate) listen_path_offset: usize,
    pub(crate) listen_path_len: usize,
    pub(crate) connect_host_offset: usize,
    pub(crate) connect_host_len: usize,
    pub(crate) connect_port_offset: usize,
    pub(crate) connect_port_len: usize,
    pub(crate) connect_path_offset: usize,
    pub(crate) connect_path_len: usize,
    pub(crate) has_listen_host: u32,
    pub(crate) has_listen_port: u32,
    pub(crate) has_listen_path: u32,
    pub(crate) has_connect_host: u32,
    pub(crate) has_connect_host_socks: u32,
    pub(crate) has_connect_port: u32,
    pub(crate) has_connect_path: u32,
    pub(crate) listen_port_value: i32,
    pub(crate) connect_port_value: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JumpParse {
    pub(crate) first_offset: usize,
    pub(crate) first_len: usize,
    pub(crate) extra_len: usize,
    pub(crate) is_none: u32,
    pub(crate) first_is_uri: u32,
    pub(crate) has_extra: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostfileLineParse {
    pub(crate) kind: u32,
    pub(crate) marker: u32,
    pub(crate) hosts_offset: usize,
    pub(crate) hosts_len: usize,
    pub(crate) rawkey_offset: usize,
    pub(crate) keytype_offset: usize,
    pub(crate) keytype_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PatternIntervalParse {
    pub(crate) type_len: usize,
    pub(crate) interval_offset: usize,
    pub(crate) interval_len: usize,
}

const HOSTFILE_LINE_KIND_COMMENT: u32 = 1;
const HOSTFILE_LINE_KIND_ENTRY: u32 = 2;
const HOSTFILE_LINE_KIND_INVALID_MARKER: u32 = 3;
const HOSTFILE_LINE_KIND_INVALID_ENTRY: u32 = 4;
const HOSTFILE_MARKER_NONE: u32 = 1;
const HOSTFILE_MARKER_REVOKE: u32 = 2;
const HOSTFILE_MARKER_CA: u32 = 3;

fn parse_permit_port_token(input: &[u8]) -> bool {
    if input == b"*" {
        return true;
    }
    match parse_port_token(input) {
        Some(port) => port > 0,
        None => false,
    }
}

pub(crate) fn validate_permit(input: *const u8, input_len: usize, allow_bare_port: c_int) -> bool {
    let input = match read_slice(input, input_len) {
        Some(input) if !input.is_empty() => input,
        _ => return false,
    };

    if allow_bare_port != 0 && !input.contains(&b':') {
        return parse_permit_port_token(input);
    }

    let (host, port) = if input.first() == Some(&b'[') {
        let Some(close) = input.iter().position(|byte| *byte == b']') else {
            return false;
        };
        if close <= 1 || input.get(close + 1) != Some(&b':') {
            return false;
        }
        (&input[1..close], &input[close + 2..])
    } else {
        let Some(colon) = input.iter().position(|byte| *byte == b':') else {
            return false;
        };
        (&input[..colon], &input[colon + 1..])
    };

    if host.is_empty() || host.len() >= libc::NI_MAXHOST as usize {
        return false;
    }
    parse_permit_port_token(port)
}

fn parse_ipqos_name(input: &[u8]) -> Option<i32> {
    if input.eq_ignore_ascii_case(b"none") {
        Some(IPQOS_NONE)
    } else if input.eq_ignore_ascii_case(b"af11") {
        Some(IPQOS_AF11)
    } else if input.eq_ignore_ascii_case(b"af12") {
        Some(IPQOS_AF12)
    } else if input.eq_ignore_ascii_case(b"af13") {
        Some(IPQOS_AF13)
    } else if input.eq_ignore_ascii_case(b"af21") {
        Some(IPQOS_AF21)
    } else if input.eq_ignore_ascii_case(b"af22") {
        Some(IPQOS_AF22)
    } else if input.eq_ignore_ascii_case(b"af23") {
        Some(IPQOS_AF23)
    } else if input.eq_ignore_ascii_case(b"af31") {
        Some(IPQOS_AF31)
    } else if input.eq_ignore_ascii_case(b"af32") {
        Some(IPQOS_AF32)
    } else if input.eq_ignore_ascii_case(b"af33") {
        Some(IPQOS_AF33)
    } else if input.eq_ignore_ascii_case(b"af41") {
        Some(IPQOS_AF41)
    } else if input.eq_ignore_ascii_case(b"af42") {
        Some(IPQOS_AF42)
    } else if input.eq_ignore_ascii_case(b"af43") {
        Some(IPQOS_AF43)
    } else if input.eq_ignore_ascii_case(b"cs0") {
        Some(IPQOS_CS0)
    } else if input.eq_ignore_ascii_case(b"cs1") {
        Some(IPQOS_CS1)
    } else if input.eq_ignore_ascii_case(b"cs2") {
        Some(IPQOS_CS2)
    } else if input.eq_ignore_ascii_case(b"cs3") {
        Some(IPQOS_CS3)
    } else if input.eq_ignore_ascii_case(b"cs4") {
        Some(IPQOS_CS4)
    } else if input.eq_ignore_ascii_case(b"cs5") {
        Some(IPQOS_CS5)
    } else if input.eq_ignore_ascii_case(b"cs6") {
        Some(IPQOS_CS6)
    } else if input.eq_ignore_ascii_case(b"cs7") {
        Some(IPQOS_CS7)
    } else if input.eq_ignore_ascii_case(b"ef") {
        Some(IPQOS_EF)
    } else if input.eq_ignore_ascii_case(b"le") {
        Some(IPQOS_LE)
    } else if input.eq_ignore_ascii_case(b"va") {
        Some(IPQOS_VA)
    } else if input.eq_ignore_ascii_case(b"lowdelay") {
        Some(IPQOS_LOWDELAY)
    } else if input.eq_ignore_ascii_case(b"throughput") {
        Some(IPQOS_THROUGHPUT)
    } else if input.eq_ignore_ascii_case(b"reliability") {
        Some(IPQOS_RELIABILITY)
    } else {
        None
    }
}

pub(crate) fn parse_ipqos(input: *const u8, input_len: usize) -> Option<i32> {
    let input = read_slice(input, input_len)?;
    if let Some(val) = parse_ipqos_name(input) {
        return Some(val);
    }
    let parsed = core::str::from_utf8(input).ok()?.parse::<i32>().ok()?;
    (0..=255).contains(&parsed).then_some(parsed)
}

pub(crate) fn valid_env_name(input: *const u8, input_len: usize) -> bool {
    let Some(input) = read_slice(input, input_len) else {
        return false;
    };
    !input.is_empty()
        && input
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

pub(crate) fn valid_domain(
    input: *mut u8,
    input_len: usize,
    makelower: c_int,
) -> Result<(), c_int> {
    if input.is_null() {
        return Err(DOMAIN_STATUS_EMPTY);
    }
    let input = unsafe { slice::from_raw_parts_mut(input, input_len) };
    if input.is_empty() {
        return Err(DOMAIN_STATUS_EMPTY);
    }
    let first = input[0];
    if !first.is_ascii_alphanumeric() && first != b'_' {
        return Err(DOMAIN_STATUS_START_INVALID);
    }
    let lower = makelower != 0;
    let mut last = 0u8;
    for byte in input.iter_mut() {
        let c = byte.to_ascii_lowercase();
        if lower {
            *byte = c;
        }
        if last == b'.' && c == b'.' {
            return Err(DOMAIN_STATUS_CONSECUTIVE_SEPARATORS);
        }
        if c != b'.' && c != b'-' && c != b'_' && !c.is_ascii_alphanumeric() {
            return Err(DOMAIN_STATUS_INVALID_CHARS);
        }
        last = c;
    }
    if input[input.len() - 1] == b'.' {
        input[input.len() - 1] = 0;
    }
    Ok(())
}

pub(crate) fn parse_pattern_interval(input: *const u8, input_len: usize) -> Option<PatternIntervalParse> {
    let input = read_slice(input, input_len)?;
    let eq = input.iter().position(|byte| *byte == b'=')?;
    if eq == 0 || eq + 1 >= input.len() {
        return None;
    }
    Some(PatternIntervalParse {
        type_len: eq,
        interval_offset: eq + 1,
        interval_len: input.len() - eq - 1,
    })
}

pub(crate) fn a2port(input: *const u8, input_len: usize) -> Option<i32> {
    let input = read_slice(input, input_len)?;
    parse_port_token(input)
}

pub(crate) fn atoi_err(input: *const u8, input_len: usize) -> Result<i32, c_int> {
    let input = read_slice(input, input_len).ok_or(ATOI_STATUS_MISSING)?;
    if input.is_empty() {
        return Err(ATOI_STATUS_MISSING);
    }
    if input[0] == b'+' {
        let digits = &input[1..];
        if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) {
            return Err(ATOI_STATUS_INVALID);
        }
        let value = parse_u64_decimal(digits).ok_or(ATOI_STATUS_TOO_LARGE)?;
        return i32::try_from(value).map_err(|_| ATOI_STATUS_TOO_LARGE);
    }
    if input[0] == b'-' {
        let digits = &input[1..];
        if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) {
            return Err(ATOI_STATUS_INVALID);
        }
        let value = parse_u64_decimal(digits).ok_or(ATOI_STATUS_TOO_LARGE)?;
        if value == 0 {
            return Ok(0);
        }
        return Err(ATOI_STATUS_TOO_SMALL);
    }
    if !input.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(ATOI_STATUS_INVALID);
    }
    let value = parse_u64_decimal(input).ok_or(ATOI_STATUS_TOO_LARGE)?;
    i32::try_from(value).map_err(|_| ATOI_STATUS_TOO_LARGE)
}

pub(crate) fn multistate_lookup(
    input: *const u8,
    input_len: usize,
    entries: *const MultistateEntry,
    nentries: usize,
) -> Option<c_int> {
    let input = read_slice(input, input_len)?;
    if nentries == 0 {
        return None;
    }
    let entries = unsafe { entries.as_ref() }
        .map(|_| unsafe { slice::from_raw_parts(entries, nentries) })?;
    entries.iter().find_map(|entry| {
        let key = unsafe { entry.key.as_ref() }
            .and_then(|_| unsafe { CStr::from_ptr(entry.key) }.to_str().ok())?;
        if input.eq_ignore_ascii_case(key.as_bytes()) {
            Some(entry.value)
        } else {
            None
        }
    })
}

pub(crate) fn multistate_name(
    value: c_int,
    entries: *const MultistateEntry,
    nentries: usize,
) -> Option<usize> {
    if nentries == 0 {
        return None;
    }
    let entries = unsafe { entries.as_ref() }
        .map(|_| unsafe { slice::from_raw_parts(entries, nentries) })?;
    entries.iter().position(|entry| entry.value == value)
}

pub(crate) fn keyword_lookup(
    input: *const u8,
    input_len: usize,
    entries: *const KeywordEntry,
    nentries: usize,
    ignore_case: bool,
) -> Option<c_int> {
    let input = read_slice(input, input_len)?;
    if nentries == 0 {
        return None;
    }
    let entries = unsafe { entries.as_ref() }
        .map(|_| unsafe { slice::from_raw_parts(entries, nentries) })?;
    entries.iter().find_map(|entry| {
        let key = unsafe { entry.key.as_ref() }
            .and_then(|_| unsafe { CStr::from_ptr(entry.key) }.to_str().ok())?;
        let matches = if ignore_case {
            input.eq_ignore_ascii_case(key.as_bytes())
        } else {
            input == key.as_bytes()
        };
        if matches {
            Some(entry.value)
        } else {
            None
        }
    })
}

pub(crate) fn parse_convtime_double(input: *const u8, input_len: usize) -> Option<f64> {
    let input = read_slice(input, input_len)?;
    if input.is_empty() {
        return None;
    }

    let mut total = 0.0f64;
    let mut i = 0usize;
    let mut seen_seconds = false;

    while i < input.len() {
        let start = i;
        let mut seen_dot = false;
        while i < input.len() && (input[i].is_ascii_digit() || input[i] == b'.') {
            if input[i] == b'.' {
                if seen_dot {
                    return None;
                }
                seen_dot = true;
            }
            i += 1;
        }
        if start == i {
            return None;
        }
        let token = &input[start..i];
        let value = parse_convtime_number(token)?;
        let multiplier = match input.get(i).copied() {
            None | Some(b's') | Some(b'S') => {
                if seen_seconds {
                    return None;
                }
                seen_seconds = true;
                1.0
            }
            Some(b'm') | Some(b'M') => 60.0,
            Some(b'h') | Some(b'H') => 60.0 * 60.0,
            Some(b'd') | Some(b'D') => 24.0 * 60.0 * 60.0,
            Some(b'w') | Some(b'W') => 7.0 * 24.0 * 60.0 * 60.0,
            Some(_) => return None,
        };
        if seen_dot && multiplier > 1.0 {
            return None;
        }
        total += value * multiplier;
        if !total.is_finite() {
            return None;
        }
        if i < input.len() {
            i += 1;
        }
    }
    Some(total)
}

fn parse_convtime_number(input: &[u8]) -> Option<f64> {
    if input.is_empty() {
        return None;
    }
    let mut parts = input.splitn(2, |byte| *byte == b'.');
    let int_part = parts.next()?;
    let frac_part = parts.next();
    if int_part.is_empty() && frac_part.is_none() {
        return None;
    }
    if !int_part.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let whole = if int_part.is_empty() {
        0u64
    } else {
        parse_u64_decimal(int_part)?
    };
    let mut out = whole as f64;
    if let Some(frac) = frac_part {
        if frac.is_empty() || !frac.iter().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let frac_value = parse_u64_decimal(frac)? as f64;
        let scale = 10f64.powi(i32::try_from(frac.len()).ok()?);
        out += frac_value / scale;
    }
    Some(out)
}

fn parse_u64_decimal(input: &[u8]) -> Option<u64> {
    if input.is_empty() {
        return None;
    }
    let mut out = 0u64;
    for byte in input {
        if !byte.is_ascii_digit() {
            return None;
        }
        out = out.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(out)
}

fn parse_decimal_component(input: &[u8]) -> Option<i32> {
    if input.is_empty() || !input.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut out = 0i32;
    for byte in input {
        out = out.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    Some(out)
}

pub(crate) fn parse_absolute_time(input: *const u8, input_len: usize) -> Option<u64> {
    let input = read_slice(input, input_len)?;
    let (digits, is_utc) = if input.len() > 1 && input[input.len() - 1..].eq_ignore_ascii_case(b"Z") {
        (&input[..input.len() - 1], true)
    } else if input.len() > 3 && input[input.len() - 3..].eq_ignore_ascii_case(b"UTC") {
        (&input[..input.len() - 3], true)
    } else {
        (input, false)
    };

    let (year, month, day, hour, minute, second) = match digits.len() {
        8 => (
            parse_decimal_component(&digits[0..4])?,
            parse_decimal_component(&digits[4..6])?,
            parse_decimal_component(&digits[6..8])?,
            0,
            0,
            0,
        ),
        12 => (
            parse_decimal_component(&digits[0..4])?,
            parse_decimal_component(&digits[4..6])?,
            parse_decimal_component(&digits[6..8])?,
            parse_decimal_component(&digits[8..10])?,
            parse_decimal_component(&digits[10..12])?,
            0,
        ),
        14 => (
            parse_decimal_component(&digits[0..4])?,
            parse_decimal_component(&digits[4..6])?,
            parse_decimal_component(&digits[6..8])?,
            parse_decimal_component(&digits[8..10])?,
            parse_decimal_component(&digits[10..12])?,
            parse_decimal_component(&digits[12..14])?,
        ),
        _ => return None,
    };

    let mut tm = unsafe { mem::zeroed::<libc::tm>() };
    tm.tm_year = year.checked_sub(1900)?;
    tm.tm_mon = month.checked_sub(1)?;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = -1;

    let tt = unsafe {
        if is_utc {
            libc::timegm(&mut tm)
        } else {
            libc::mktime(&mut tm)
        }
    };
    if tt < 0 {
        return None;
    }

    let mut verify = unsafe { mem::zeroed::<libc::tm>() };
    let verify_ptr = unsafe {
        if is_utc {
            libc::gmtime_r(&tt, &mut verify)
        } else {
            libc::localtime_r(&tt, &mut verify)
        }
    };
    if verify_ptr.is_null() {
        return None;
    }
    if verify.tm_year != year - 1900
        || verify.tm_mon != month - 1
        || verify.tm_mday != day
        || verify.tm_hour != hour
        || verify.tm_min != minute
        || verify.tm_sec != second
    {
        return None;
    }

    u64::try_from(tt).ok()
}

pub(crate) fn parse_hostfile_line(input: *const u8, input_len: usize) -> Option<HostfileLineParse> {
    let input = read_slice(input, input_len)?;
    let mut pos = 0usize;

    while matches!(input.get(pos), Some(b' ' | b'\t')) {
        pos += 1;
    }
    if pos >= input.len() || input[pos] == b'#' {
        return Some(HostfileLineParse {
            kind: HOSTFILE_LINE_KIND_COMMENT,
            marker: HOSTFILE_MARKER_NONE,
            hosts_offset: 0,
            hosts_len: 0,
            rawkey_offset: 0,
            keytype_offset: 0,
            keytype_len: 0,
        });
    }

    let mut marker = HOSTFILE_MARKER_NONE;
    while input.get(pos) == Some(&b'@') {
        if marker != HOSTFILE_MARKER_NONE {
            return Some(HostfileLineParse {
                kind: HOSTFILE_LINE_KIND_INVALID_MARKER,
                marker: 0,
                hosts_offset: 0,
                hosts_len: 0,
                rawkey_offset: 0,
                keytype_offset: 0,
                keytype_len: 0,
            });
        }
        let marker_end = input[pos..]
            .iter()
            .position(|byte| matches!(*byte, b' ' | b'\t'))
            .map(|off| pos + off)
            .unwrap_or(input.len());
        marker = match &input[pos..marker_end] {
            b"@cert-authority" => HOSTFILE_MARKER_CA,
            b"@revoked" => HOSTFILE_MARKER_REVOKE,
            _ => {
                return Some(HostfileLineParse {
                    kind: HOSTFILE_LINE_KIND_INVALID_MARKER,
                    marker: 0,
                    hosts_offset: 0,
                    hosts_len: 0,
                    rawkey_offset: 0,
                    keytype_offset: 0,
                    keytype_len: 0,
                });
            }
        };
        pos = marker_end;
        while matches!(input.get(pos), Some(b' ' | b'\t')) {
            pos += 1;
        }
        if pos >= input.len() {
            return None;
        }
    }

    let hosts_offset = pos;
    let hosts_end = input[pos..]
        .iter()
        .position(|byte| matches!(*byte, b' ' | b'\t'))
        .map(|off| pos + off)?;
    if hosts_end == hosts_offset {
        return None;
    }
    pos = hosts_end;
    while matches!(input.get(pos), Some(b' ' | b'\t')) {
        pos += 1;
    }
    if pos >= input.len() || input[pos] == b'#' {
        return Some(HostfileLineParse {
            kind: HOSTFILE_LINE_KIND_INVALID_ENTRY,
            marker,
            hosts_offset,
            hosts_len: hosts_end - hosts_offset,
            rawkey_offset: 0,
            keytype_offset: 0,
            keytype_len: 0,
        });
    }

    let rawkey_offset = pos;
    let keytype_offset = pos;
    let keytype_end = input[pos..]
        .iter()
        .position(|byte| matches!(*byte, b' ' | b'\t'))
        .map(|off| pos + off)?;
    if keytype_end == keytype_offset {
        return None;
    }
    pos = keytype_end;
    while matches!(input.get(pos), Some(b' ' | b'\t')) {
        pos += 1;
    }
    if pos >= input.len() || input[pos] == b'#' {
        return Some(HostfileLineParse {
            kind: HOSTFILE_LINE_KIND_INVALID_ENTRY,
            marker,
            hosts_offset,
            hosts_len: hosts_end - hosts_offset,
            rawkey_offset,
            keytype_offset,
            keytype_len: keytype_end - keytype_offset,
        });
    }

    Some(HostfileLineParse {
        kind: HOSTFILE_LINE_KIND_ENTRY,
        marker,
        hosts_offset,
        hosts_len: hosts_end - hosts_offset,
        rawkey_offset,
        keytype_offset,
        keytype_len: keytype_end - keytype_offset,
    })
}

fn parse_hashed_host_entry(input: &[u8]) -> Option<([u8; HOST_HASH_LEN], [u8; HOST_HASH_LEN])> {
    if !input.starts_with(HOST_HASH_MAGIC) {
        return None;
    }
    let rest = &input[HOST_HASH_MAGIC.len()..];
    let salt_end = rest.iter().position(|byte| *byte == HOST_HASH_DELIM)?;
    let salt_b64 = core::str::from_utf8(&rest[..salt_end]).ok()?;
    let hash_b64 = core::str::from_utf8(&rest[salt_end + 1..]).ok()?;
    let salt = Base64::decode_vec(salt_b64).ok()?;
    let hash = Base64::decode_vec(hash_b64).ok()?;
    if salt.len() != HOST_HASH_LEN || hash.len() != HOST_HASH_LEN {
        return None;
    }
    let mut salt_out = [0u8; HOST_HASH_LEN];
    let mut hash_out = [0u8; HOST_HASH_LEN];
    salt_out.copy_from_slice(&salt);
    hash_out.copy_from_slice(&hash);
    Some((salt_out, hash_out))
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; HOST_HASH_LEN] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        let digest = Sha1::digest(key);
        block[..HOST_HASH_LEN].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for (dst, src) in ipad.iter_mut().zip(block.iter()) {
        *dst = *src ^ 0x36;
    }
    for (dst, src) in opad.iter_mut().zip(block.iter()) {
        *dst = *src ^ 0x5c;
    }

    let mut inner = Sha1::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(opad);
    outer.update(inner_digest);
    let digest = outer.finalize();

    let mut out = [0u8; HOST_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn host_hash_write(
    host: *const u8,
    host_len: usize,
    name_from_hostfile: *const u8,
    src_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let host = match read_slice(host, host_len) {
        Some(host) if !host.is_empty() => host,
        _ => return -1,
    };

    let salt = if name_from_hostfile.is_null() {
        let mut salt = [0u8; HOST_HASH_LEN];
        OsRng.fill_bytes(&mut salt);
        salt
    } else {
        let names = match read_slice(name_from_hostfile, src_len) {
            Some(names) => names,
            None => return -1,
        };
        let Some((salt, _)) = parse_hashed_host_entry(names) else {
            return -1;
        };
        salt
    };

    let result = hmac_sha1(&salt, host);
    let encoded = format!(
        "{}{}{}{}",
        core::str::from_utf8(HOST_HASH_MAGIC).unwrap(),
        Base64::encode_string(&salt),
        HOST_HASH_DELIM as char,
        Base64::encode_string(&result)
    );
    let bytes = encoded.as_bytes();
    if out.is_null() || out_len < bytes.len() + 1 {
        return -1;
    }
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    out[..bytes.len()].copy_from_slice(bytes);
    out[bytes.len()] = 0;
    0
}

pub(crate) fn match_hashed_host(
    host: *const u8,
    host_len: usize,
    names: *const u8,
    names_len: usize,
) -> c_int {
    let host = match read_slice(host, host_len) {
        Some(host) if !host.is_empty() => host,
        _ => return -1,
    };
    let names = match read_slice(names, names_len) {
        Some(names) => names,
        None => return -1,
    };
    let Some((salt, expected)) = parse_hashed_host_entry(names) else {
        return -1;
    };
    if hmac_sha1(&salt, host) == expected {
        1
    } else {
        0
    }
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

pub(crate) fn hpdelim2_parse_in_place(input: *mut u8, input_len: usize) -> Option<HpdelimParse> {
    let input = read_slice_mut(input, input_len)?;
    if input.is_empty() {
        return None;
    }
    let nul = input.iter().position(|byte| *byte == 0)?;
    let pos = if input.first() == Some(&b'[') {
        input[..nul]
            .iter()
            .position(|byte| *byte == b']')
            .map(|idx| idx + 1)?
    } else {
        input[..nul]
            .iter()
            .position(|byte| matches!(*byte, b':' | b'/'))
            .unwrap_or(nul)
    };

    match input[pos] {
        0 => Some(HpdelimParse {
            next_offset: 0,
            next_is_null: 1,
            delim: 0,
        }),
        b':' | b'/' => {
            let delim = input[pos];
            input[pos] = 0;
            Some(HpdelimParse {
                next_offset: pos + 1,
                next_is_null: 0,
                delim,
            })
        }
        _ => None,
    }
}

pub(crate) fn parse_forward_field_in_place(
    input: *mut u8,
    input_len: usize,
) -> Option<ForwardFieldParse> {
    let input = read_slice_mut(input, input_len)?;
    if input.is_empty() || input[0] == 0 {
        return None;
    }

    if input[0] == b'[' {
        let nul = input.iter().position(|byte| *byte == 0)?;
        let close = input[..nul].iter().position(|byte| *byte == b']')?;
        let ispath = u32::from(input[1..close].contains(&b'/'));
        if input.get(close + 1).copied()? != 0 && input.get(close + 1).copied()? != b':' {
            return None;
        }
        input[close] = 0;
        let next_offset = if input.get(close + 1).copied()? == b':' {
            input[close + 1] = 0;
            close + 2
        } else {
            close + 1
        };
        return Some(ForwardFieldParse {
            arg_offset: 1,
            next_offset,
            ispath,
        });
    }

    let mut ispath = 0u32;
    let mut i = 0usize;
    while i < input.len() {
        match input[i] {
            0 => {
                return Some(ForwardFieldParse {
                    arg_offset: 0,
                    next_offset: i,
                    ispath,
                });
            }
            b'\\' => {
                let nul = input[i..].iter().position(|byte| *byte == 0).map(|off| i + off)?;
                input.copy_within(i + 1..=nul, i);
                if input[i] == 0 {
                    return None;
                }
                i += 1;
            }
            b'/' => {
                ispath = 1;
                i += 1;
            }
            b':' => {
                input[i] = 0;
                return Some(ForwardFieldParse {
                    arg_offset: 0,
                    next_offset: i + 1,
                    ispath,
                });
            }
            _ => {
                i += 1;
            }
        }
    }

    None
}

#[derive(Clone, Copy, Default)]
struct ForwardToken {
    offset: usize,
    len: usize,
    ispath: u32,
}

fn assign_forward_token(
    token: ForwardToken,
    offset: &mut usize,
    len: &mut usize,
    present: &mut u32,
) {
    *offset = token.offset;
    *len = token.len;
    *present = 1;
}

fn parse_port_token(input: &[u8]) -> Option<i32> {
    if input.is_empty() {
        return None;
    }
    if input.iter().all(|byte| byte.is_ascii_digit()) {
        let port = core::str::from_utf8(input).ok()?.parse::<u16>().ok()?;
        return Some(i32::from(port));
    }
    let service = CString::new(input).ok()?;
    let proto = CString::new("tcp").ok()?;
    let entry = unsafe { libc::getservbyname(service.as_ptr(), proto.as_ptr()) };
    if entry.is_null() {
        return None;
    }
    let port = unsafe { u16::from_be((*entry).s_port as u16) };
    Some(i32::from(port))
}

pub(crate) fn parse_forward_in_place(
    input: *mut u8,
    input_len: usize,
    dynamicfwd: c_int,
    _remotefwd: c_int,
) -> Option<ForwardParse> {
    let input = read_slice_mut(input, input_len)?;
    if input.is_empty() {
        return None;
    }

    let mut tokens = [ForwardToken::default(); 4];
    let mut count = 0usize;
    let mut offset = 0usize;

    while count < tokens.len() {
        if *input.get(offset)? == 0 {
            break;
        }
        let parsed =
            parse_forward_field_in_place(input[offset..].as_mut_ptr(), input.len() - offset)?;
        let arg_offset = offset + parsed.arg_offset;
        let next_offset = offset + parsed.next_offset;
        let arg_len = input[arg_offset..]
            .iter()
            .position(|byte| *byte == 0)?;
        tokens[count] = ForwardToken {
            offset: arg_offset,
            len: arg_len,
            ispath: parsed.ispath,
        };
        count += 1;
        offset = next_offset;
    }
    if count == 0 || *input.get(offset)? != 0 {
        return None;
    }

    let mut out = ForwardParse {
        field_count: count as u32,
        listen_host_offset: 0,
        listen_host_len: 0,
        listen_port_offset: 0,
        listen_port_len: 0,
        listen_path_offset: 0,
        listen_path_len: 0,
        connect_host_offset: 0,
        connect_host_len: 0,
        connect_port_offset: 0,
        connect_port_len: 0,
        connect_path_offset: 0,
        connect_path_len: 0,
        has_listen_host: 0,
        has_listen_port: 0,
        has_listen_path: 0,
        has_connect_host: 0,
        has_connect_host_socks: 0,
        has_connect_port: 0,
        has_connect_path: 0,
        listen_port_value: 0,
        connect_port_value: 0,
    };

    match count {
        1 => {
            if tokens[0].ispath != 0 {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_path_offset,
                    &mut out.listen_path_len,
                    &mut out.has_listen_path,
                );
            } else {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_port_offset,
                    &mut out.listen_port_len,
                    &mut out.has_listen_port,
                );
            }
            out.has_connect_host_socks = 1;
        }
        2 => {
            if tokens[0].ispath != 0 && tokens[1].ispath != 0 {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_path_offset,
                    &mut out.listen_path_len,
                    &mut out.has_listen_path,
                );
                assign_forward_token(
                    tokens[1],
                    &mut out.connect_path_offset,
                    &mut out.connect_path_len,
                    &mut out.has_connect_path,
                );
            } else if tokens[1].ispath != 0 {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_port_offset,
                    &mut out.listen_port_len,
                    &mut out.has_listen_port,
                );
                assign_forward_token(
                    tokens[1],
                    &mut out.connect_path_offset,
                    &mut out.connect_path_len,
                    &mut out.has_connect_path,
                );
            } else {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_host_offset,
                    &mut out.listen_host_len,
                    &mut out.has_listen_host,
                );
                assign_forward_token(
                    tokens[1],
                    &mut out.listen_port_offset,
                    &mut out.listen_port_len,
                    &mut out.has_listen_port,
                );
                out.has_connect_host_socks = 1;
            }
        }
        3 => {
            if tokens[0].ispath != 0 {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_path_offset,
                    &mut out.listen_path_len,
                    &mut out.has_listen_path,
                );
                assign_forward_token(
                    tokens[1],
                    &mut out.connect_host_offset,
                    &mut out.connect_host_len,
                    &mut out.has_connect_host,
                );
                assign_forward_token(
                    tokens[2],
                    &mut out.connect_port_offset,
                    &mut out.connect_port_len,
                    &mut out.has_connect_port,
                );
            } else if tokens[2].ispath != 0 {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_host_offset,
                    &mut out.listen_host_len,
                    &mut out.has_listen_host,
                );
                assign_forward_token(
                    tokens[1],
                    &mut out.listen_port_offset,
                    &mut out.listen_port_len,
                    &mut out.has_listen_port,
                );
                assign_forward_token(
                    tokens[2],
                    &mut out.connect_path_offset,
                    &mut out.connect_path_len,
                    &mut out.has_connect_path,
                );
            } else {
                assign_forward_token(
                    tokens[0],
                    &mut out.listen_port_offset,
                    &mut out.listen_port_len,
                    &mut out.has_listen_port,
                );
                assign_forward_token(
                    tokens[1],
                    &mut out.connect_host_offset,
                    &mut out.connect_host_len,
                    &mut out.has_connect_host,
                );
                assign_forward_token(
                    tokens[2],
                    &mut out.connect_port_offset,
                    &mut out.connect_port_len,
                    &mut out.has_connect_port,
                );
            }
        }
        4 => {
            assign_forward_token(
                tokens[0],
                &mut out.listen_host_offset,
                &mut out.listen_host_len,
                &mut out.has_listen_host,
            );
            assign_forward_token(
                tokens[1],
                &mut out.listen_port_offset,
                &mut out.listen_port_len,
                &mut out.has_listen_port,
            );
            assign_forward_token(
                tokens[2],
                &mut out.connect_host_offset,
                &mut out.connect_host_len,
                &mut out.has_connect_host,
            );
            assign_forward_token(
                tokens[3],
                &mut out.connect_port_offset,
                &mut out.connect_port_len,
                &mut out.has_connect_port,
            );
        }
        _ => return None,
    }

    if dynamicfwd != 0 {
        if !(count == 1 || count == 2) {
            return None;
        }
    } else if !(count == 3 || count == 4)
        && out.has_connect_path == 0
        && out.has_listen_path == 0
    {
        return None;
    }

    if out.has_listen_port != 0 {
        out.listen_port_value =
            parse_port_token(&input[out.listen_port_offset..out.listen_port_offset + out.listen_port_len])?;
        if _remotefwd == 0 && out.listen_port_value == 0 {
            return None;
        }
    }
    if out.has_connect_port != 0 {
        out.connect_port_value = parse_port_token(
            &input[out.connect_port_offset..out.connect_port_offset + out.connect_port_len],
        )?;
        if out.connect_port_value <= 0 {
            return None;
        }
    } else if out.has_connect_path == 0 && out.has_connect_host_socks == 0 {
        return None;
    }

    Some(out)
}

fn parse_jump_token(token: &[u8]) -> Option<bool> {
    if token.is_empty() {
        return None;
    }
    if let Some(rest) = token.strip_prefix(b"ssh://") {
        let parsed = parse_uri(rest.as_ptr(), rest.len())?;
        if parsed.has_path != 0 {
            return None;
        }
        return Some(true);
    }
    parse_user_host_port(token.as_ptr(), token.len())?;
    Some(false)
}

pub(crate) fn parse_jump(input: *const u8, input_len: usize) -> Option<JumpParse> {
    let input = read_slice(input, input_len)?;
    if input.is_empty() {
        return None;
    }
    if input.eq_ignore_ascii_case(b"none") {
        return Some(JumpParse {
            first_offset: 0,
            first_len: 0,
            extra_len: 0,
            is_none: 1,
            first_is_uri: 0,
            has_extra: 0,
        });
    }

    let mut end = input.len();
    let mut first_offset = 0usize;
    let mut first_len = 0usize;
    let mut first_is_uri = 0u32;
    let mut extra_len = 0usize;
    let mut saw_first = false;

    loop {
        let start = input[..end]
            .iter()
            .rposition(|byte| *byte == b',')
            .map(|pos| pos + 1)
            .unwrap_or(0);
        let token = &input[start..end];
        let is_uri = parse_jump_token(token)?;
        if !saw_first {
            first_offset = start;
            first_len = token.len();
            first_is_uri = u32::from(is_uri);
            if start != 0 {
                extra_len = start - 1;
            }
            saw_first = true;
        }
        if start == 0 {
            break;
        }
        end = start - 1;
    }

    Some(JumpParse {
        first_offset,
        first_len,
        extra_len,
        is_none: 0,
        first_is_uri,
        has_extra: u32::from(extra_len != 0),
    })
}

pub(crate) fn parse_user_host_port(input: *const u8, input_len: usize) -> Option<UserHostPortParse> {
    let input = read_slice(input, input_len)?;
    if input.is_empty() {
        return None;
    }

    let (user_offset, user_len, host_part_offset) = match input.iter().rposition(|byte| *byte == b'@') {
        Some(at) => {
            if at == 0 || at + 1 >= input.len() {
                return None;
            }
            (0, at, at + 1)
        }
        None => (0, 0, 0),
    };
    let host_part = &input[host_part_offset..];

    let (host_offset, host_len, port_offset, port_len) = if host_part.first() == Some(&b'[') {
        let close = host_part.iter().position(|byte| *byte == b']')?;
        if close == 1 {
            return None;
        }
        let host_offset = host_part_offset + 1;
        let host_len = close - 1;
        if close + 1 == host_part.len() {
            (host_offset, host_len, 0, 0)
        } else if host_part.get(close + 1) == Some(&b':') {
            let port_offset = host_part_offset + close + 2;
            let port_len = host_part.len().checked_sub(close + 2)?;
            if port_len == 0 {
                return None;
            }
            (host_offset, host_len, port_offset, port_len)
        } else {
            return None;
        }
    } else {
        let colon = host_part.iter().position(|byte| *byte == b':');
        let slash = host_part.iter().position(|byte| *byte == b'/');
        match (colon, slash) {
            (_, Some(slash_pos)) if colon.is_none() || slash_pos < colon.unwrap() => return None,
            (Some(colon_pos), _) => {
                if colon_pos == 0 || colon_pos + 1 >= host_part.len() {
                    return None;
                }
                (
                    host_part_offset,
                    colon_pos,
                    host_part_offset + colon_pos + 1,
                    host_part.len() - colon_pos - 1,
                )
            }
            (None, _) => {
                if host_part.is_empty() {
                    return None;
                }
                (host_part_offset, host_part.len(), 0, 0)
            }
        }
    };

    Some(UserHostPortParse {
        user_offset,
        user_len,
        host_offset,
        host_len,
        port_offset,
        port_len,
        has_user: u32::from(user_len != 0),
        has_port: u32::from(port_len != 0),
    })
}

pub(crate) fn parse_uri(input: *const u8, input_len: usize) -> Option<UriParse> {
    let input = read_slice(input, input_len)?;
    if input.is_empty() {
        return None;
    }

    let authority_end = input
        .iter()
        .position(|byte| *byte == b'/')
        .unwrap_or(input.len());
    let authority = &input[..authority_end];
    if authority.is_empty() {
        return None;
    }

    let (user_offset, user_len, authority_offset) = match authority.iter().position(|byte| *byte == b'@') {
        Some(at) => {
            if at == 0 || at + 1 >= authority.len() {
                return None;
            }
            let user_len = authority[..at]
                .iter()
                .position(|byte| *byte == b';')
                .unwrap_or(at);
            if user_len == 0 {
                return None;
            }
            (0, user_len, at + 1)
        }
        None => (0, 0, 0),
    };
    let host_port = &authority[authority_offset..];

    let (host_offset, host_len, port_offset, port_len) = if host_port.first() == Some(&b'[') {
        let close = host_port.iter().position(|byte| *byte == b']')?;
        if close == 1 {
            return None;
        }
        let host_offset = authority_offset + 1;
        let host_len = close - 1;
        if close + 1 == host_port.len() {
            (host_offset, host_len, 0, 0)
        } else if host_port.get(close + 1) == Some(&b':') {
            let port_offset = authority_offset + close + 2;
            let port_len = host_port.len().checked_sub(close + 2)?;
            if port_len == 0 {
                return None;
            }
            (host_offset, host_len, port_offset, port_len)
        } else {
            return None;
        }
    } else {
        match host_port.iter().position(|byte| *byte == b':') {
            Some(colon) => {
                if colon == 0 || colon + 1 >= host_port.len() {
                    return None;
                }
                (
                    authority_offset,
                    colon,
                    authority_offset + colon + 1,
                    host_port.len() - colon - 1,
                )
            }
            None => {
                if host_port.is_empty() {
                    return None;
                }
                (authority_offset, host_port.len(), 0, 0)
            }
        }
    };

    let (path_offset, path_len) = if authority_end == input.len() {
        (0, 0)
    } else {
        let path_offset = authority_end + 1;
        let path_len = input.len() - path_offset;
        (path_offset, path_len)
    };

    Some(UriParse {
        user_offset,
        user_len,
        host_offset,
        host_len,
        port_offset,
        port_len,
        path_offset,
        path_len,
        has_user: u32::from(user_len != 0),
        has_port: u32::from(port_len != 0),
        has_path: u32::from(path_len != 0),
    })
}

pub(crate) fn parse_user_host_path(input: *const u8, input_len: usize) -> Option<UserHostPathParse> {
    let input = read_slice(input, input_len)?;
    if input.is_empty() || input[0] == b':' {
        return None;
    }

    let mut bracketed = input[0] == b'[';
    let mut path_sep = None;
    for (i, byte) in input.iter().enumerate() {
        match *byte {
            b'@' if input.get(i + 1) == Some(&b'[') => bracketed = true,
            b']' if input.get(i + 1) == Some(&b':') && bracketed => {
                path_sep = Some(i + 1);
                break;
            }
            b':' if !bracketed => {
                path_sep = Some(i);
                break;
            }
            b'/' => return None,
            _ => {}
        }
    }
    let path_sep = path_sep?;

    let (user_offset, user_len, host_offset) = match input[..path_sep].iter().rposition(|byte| *byte == b'@') {
        Some(at) => (0, at, at + 1),
        None => (0, 0, 0),
    };
    let host_len = path_sep.checked_sub(host_offset)?;
    let path_offset = path_sep + 1;
    let path_len = input.len() - path_offset;

    Some(UserHostPathParse {
        user_offset,
        user_len,
        host_offset,
        host_len,
        path_offset,
        path_len,
        has_user: u32::from(user_len != 0),
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
    use super::{
        a2port, atoi_err, argv_split_parse, argv_split_write, host_hash_write,
        hpdelim2_parse_in_place, match_hashed_host, parse_convtime_double,
        keyword_lookup, multistate_lookup, multistate_name,
        parse_forward_field_in_place, parse_absolute_time, parse_forward_in_place,
        parse_hostfile_line, parse_ipqos, parse_jump,
        parse_pattern_interval, parse_uri, parse_user_host_path, parse_user_host_port,
        strdelim_parse_in_place, valid_domain, valid_env_name, validate_permit,
        ATOI_STATUS_INVALID, ATOI_STATUS_MISSING, ATOI_STATUS_TOO_LARGE,
        ATOI_STATUS_TOO_SMALL, ForwardParse, HostfileLineParse, JumpParse,
        KeywordEntry, MultistateEntry, PatternIntervalParse, UriParse,
        UserHostPathParse, UserHostPortParse, DOMAIN_STATUS_CONSECUTIVE_SEPARATORS,
        DOMAIN_STATUS_EMPTY, DOMAIN_STATUS_INVALID_CHARS, DOMAIN_STATUS_START_INVALID,
        IPQOS_AF21, IPQOS_CS6, IPQOS_NONE,
    };
    use std::ffi::CString;

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

    fn hpdelim_next(input: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>, u8)> {
        let mut buf = input.to_vec();
        buf.push(0);
        let parsed = hpdelim2_parse_in_place(buf.as_mut_ptr(), buf.len())?;
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
        Some((token, rest, parsed.delim))
    }

    #[test]
    fn hpdelim_handles_host_and_port_forms() {
        assert_eq!(hpdelim_next(b"host"), Some((b"host".to_vec(), None, 0)));
        assert_eq!(
            hpdelim_next(b"host:1234"),
            Some((b"host".to_vec(), Some(b"1234".to_vec()), b':'))
        );
        assert_eq!(
            hpdelim_next(b"[::1]:1234"),
            Some((b"[::1]".to_vec(), Some(b"1234".to_vec()), b':'))
        );
        assert_eq!(
            hpdelim_next(b"host/path"),
            Some((b"host".to_vec(), Some(b"path".to_vec()), b'/'))
        );
    }

    #[test]
    fn hpdelim_rejects_unclosed_bracket() {
        assert_eq!(hpdelim_next(b"[::1:1234"), None);
    }

    fn parse_fwd_field(input: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>, u32)> {
        let mut buf = input.to_vec();
        buf.push(0);
        let parsed = parse_forward_field_in_place(buf.as_mut_ptr(), buf.len())?;
        let token_start = parsed.arg_offset;
        let token_end = buf[token_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|off| token_start + off)?;
        let token = buf[token_start..token_end].to_vec();
        let rest = if parsed.next_offset >= buf.len() || buf[parsed.next_offset] == 0 {
            None
        } else {
            let rest_end = buf[parsed.next_offset..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|off| parsed.next_offset + off)?;
            Some(buf[parsed.next_offset..rest_end].to_vec())
        };
        Some((token, rest, parsed.ispath))
    }

    #[test]
    fn parse_forward_field_handles_basic_forms() {
        assert_eq!(
            parse_fwd_field(b"8080:host:80"),
            Some((b"8080".to_vec(), Some(b"host:80".to_vec()), 0))
        );
        assert_eq!(
            parse_fwd_field(b"/tmp/a.sock:host:80"),
            Some((b"/tmp/a.sock".to_vec(), Some(b"host:80".to_vec()), 1))
        );
        assert_eq!(
            parse_fwd_field(b"[host:name]:80"),
            Some((b"host:name".to_vec(), Some(b"80".to_vec()), 0))
        );
        assert_eq!(
            parse_fwd_field(b"host\\:name:80"),
            Some((b"host:name".to_vec(), Some(b"80".to_vec()), 0))
        );
        assert_eq!(
            parse_fwd_field(br#"host\/path:80"#),
            Some((br#"host/path"#.to_vec(), Some(b"80".to_vec()), 0))
        );
        assert_eq!(
            parse_fwd_field(b"host"),
            Some((b"host".to_vec(), None, 0))
        );
    }

    #[test]
    fn parse_forward_field_rejects_bad_forms() {
        assert_eq!(parse_fwd_field(b""), None);
        assert_eq!(parse_fwd_field(b"["), None);
        assert_eq!(parse_fwd_field(b"[host"), None);
        assert_eq!(parse_fwd_field(b"[host]x"), None);
        assert_eq!(parse_fwd_field(br#"host\"#), None);
    }

    fn parse_forward_spec(input: &[u8], dynamicfwd: bool) -> Option<ForwardParse> {
        let mut buf = input.to_vec();
        buf.push(0);
        parse_forward_in_place(buf.as_mut_ptr(), buf.len(), dynamicfwd as i32, 0)
    }

    #[test]
    fn parse_forward_spec_handles_basic_forms() {
        assert_eq!(
            parse_forward_spec(b"8080:dest:80", false),
            Some(ForwardParse {
                field_count: 3,
                listen_host_offset: 0,
                listen_host_len: 0,
                listen_port_offset: 0,
                listen_port_len: 4,
                listen_path_offset: 0,
                listen_path_len: 0,
                connect_host_offset: 5,
                connect_host_len: 4,
                connect_port_offset: 10,
                connect_port_len: 2,
                connect_path_offset: 0,
                connect_path_len: 0,
                has_listen_host: 0,
                has_listen_port: 1,
                has_listen_path: 0,
                has_connect_host: 1,
                has_connect_host_socks: 0,
                has_connect_port: 1,
                has_connect_path: 0,
                listen_port_value: 8080,
                connect_port_value: 80,
            })
        );
        assert_eq!(
            parse_forward_spec(b"[host:name]:8080", true),
            Some(ForwardParse {
                field_count: 2,
                listen_host_offset: 1,
                listen_host_len: 9,
                listen_port_offset: 12,
                listen_port_len: 4,
                listen_path_offset: 0,
                listen_path_len: 0,
                connect_host_offset: 0,
                connect_host_len: 0,
                connect_port_offset: 0,
                connect_port_len: 0,
                connect_path_offset: 0,
                connect_path_len: 0,
                has_listen_host: 1,
                has_listen_port: 1,
                has_listen_path: 0,
                has_connect_host: 0,
                has_connect_host_socks: 1,
                has_connect_port: 0,
                has_connect_path: 0,
                listen_port_value: 8080,
                connect_port_value: 0,
            })
        );
        assert_eq!(
            parse_forward_spec(b"/tmp/listen.sock:/tmp/connect.sock", false),
            Some(ForwardParse {
                field_count: 2,
                listen_host_offset: 0,
                listen_host_len: 0,
                listen_port_offset: 0,
                listen_port_len: 0,
                listen_path_offset: 0,
                listen_path_len: 16,
                connect_host_offset: 0,
                connect_host_len: 0,
                connect_port_offset: 0,
                connect_port_len: 0,
                connect_path_offset: 17,
                connect_path_len: 17,
                has_listen_host: 0,
                has_listen_port: 0,
                has_listen_path: 1,
                has_connect_host: 0,
                has_connect_host_socks: 0,
                has_connect_port: 0,
                has_connect_path: 1,
                listen_port_value: 0,
                connect_port_value: 0,
            })
        );
    }

    #[test]
    fn parse_forward_spec_rejects_bad_forms() {
        assert_eq!(parse_forward_spec(b"[host]x:8080:dest:80", false), None);
        assert_eq!(parse_forward_spec(b"localhost:8080", false), None);
        assert_eq!(parse_forward_spec(b"8080:dest:80", true), None);
        assert_eq!(parse_forward_spec(b"0:dest:80", false), None);
        assert_eq!(parse_forward_spec(b"8080:dest:0", false), None);
    }

    #[test]
    fn parse_jump_handles_basic_forms() {
        assert_eq!(
            parse_jump(b"jumpa,ssh://user@jumpb:2200".as_ptr(), 27),
            Some(JumpParse {
                first_offset: 6,
                first_len: 21,
                extra_len: 5,
                is_none: 0,
                first_is_uri: 1,
                has_extra: 1,
            })
        );
        assert_eq!(
            parse_jump(b"jumpb:2200".as_ptr(), 10),
            Some(JumpParse {
                first_offset: 0,
                first_len: 10,
                extra_len: 0,
                is_none: 0,
                first_is_uri: 0,
                has_extra: 0,
            })
        );
        assert_eq!(
            parse_jump(b"NoNe".as_ptr(), 4),
            Some(JumpParse {
                first_offset: 0,
                first_len: 0,
                extra_len: 0,
                is_none: 1,
                first_is_uri: 0,
                has_extra: 0,
            })
        );
    }

    #[test]
    fn parse_jump_rejects_bad_forms() {
        assert_eq!(parse_jump(b"".as_ptr(), 0), None);
        assert_eq!(parse_jump(b"jumpa,,jumpb".as_ptr(), 12), None);
        assert_eq!(parse_jump(b"ssh://user@jump/path".as_ptr(), 20), None);
    }

    #[test]
    fn parse_user_host_port_handles_basic_forms() {
        assert_eq!(
            parse_user_host_port(b"host".as_ptr(), 4),
            Some(UserHostPortParse {
                user_offset: 0,
                user_len: 0,
                host_offset: 0,
                host_len: 4,
                port_offset: 0,
                port_len: 0,
                has_user: 0,
                has_port: 0,
            })
        );
        assert_eq!(
            parse_user_host_port(b"user@host:2222".as_ptr(), 14),
            Some(UserHostPortParse {
                user_offset: 0,
                user_len: 4,
                host_offset: 5,
                host_len: 4,
                port_offset: 10,
                port_len: 4,
                has_user: 1,
                has_port: 1,
            })
        );
        assert_eq!(
            parse_user_host_port(b"user@[::1]:22".as_ptr(), 13),
            Some(UserHostPortParse {
                user_offset: 0,
                user_len: 4,
                host_offset: 6,
                host_len: 3,
                port_offset: 11,
                port_len: 2,
                has_user: 1,
                has_port: 1,
            })
        );
    }

    #[test]
    fn parse_user_host_port_rejects_bad_forms() {
        assert_eq!(parse_user_host_port(b"".as_ptr(), 0), None);
        assert_eq!(parse_user_host_port(b"@host".as_ptr(), 5), None);
        assert_eq!(parse_user_host_port(b"host:".as_ptr(), 5), None);
        assert_eq!(parse_user_host_port(b"host/path".as_ptr(), 9), None);
        assert_eq!(parse_user_host_port(b"[::1".as_ptr(), 4), None);
        assert_eq!(parse_user_host_port(b"[]:22".as_ptr(), 5), None);
    }

    #[test]
    fn parse_uri_handles_basic_forms() {
        assert_eq!(
            parse_uri(b"someuser@some.host:22/some/path".as_ptr(), 31),
            Some(UriParse {
                user_offset: 0,
                user_len: 8,
                host_offset: 9,
                host_len: 9,
                port_offset: 19,
                port_len: 2,
                path_offset: 22,
                path_len: 9,
                has_user: 1,
                has_port: 1,
                has_path: 1,
            })
        );
        assert_eq!(
            parse_uri(b"someuser;ignored@[::1]:2222".as_ptr(), 27),
            Some(UriParse {
                user_offset: 0,
                user_len: 8,
                host_offset: 18,
                host_len: 3,
                port_offset: 23,
                port_len: 4,
                path_offset: 0,
                path_len: 0,
                has_user: 1,
                has_port: 1,
                has_path: 0,
            })
        );
    }

    #[test]
    fn parse_uri_rejects_bad_forms() {
        assert_eq!(parse_uri(b"".as_ptr(), 0), None);
        assert_eq!(parse_uri(b"@host".as_ptr(), 5), None);
        assert_eq!(parse_uri(b"user@".as_ptr(), 5), None);
        assert_eq!(parse_uri(b"host:".as_ptr(), 5), None);
        assert_eq!(parse_uri(b"[]:22".as_ptr(), 5), None);
    }

    #[test]
    fn validate_permit_handles_basic_forms() {
        assert!(validate_permit(b"dest.example:80".as_ptr(), 15, 0));
        assert!(validate_permit(b"[host:name]:smtp".as_ptr(), 16, 0));
        assert!(validate_permit(b"*:*".as_ptr(), 3, 0));
        assert!(validate_permit(b"8080".as_ptr(), 4, 1));
        assert!(validate_permit(b"*".as_ptr(), 1, 1));
    }

    #[test]
    fn validate_permit_rejects_bad_forms() {
        assert!(!validate_permit(b"".as_ptr(), 0, 0));
        assert!(!validate_permit(b"dest.example".as_ptr(), 12, 0));
        assert!(!validate_permit(b"host:".as_ptr(), 5, 0));
        assert!(!validate_permit(b"[]:22".as_ptr(), 5, 0));
        assert!(!validate_permit(b"[host]x:22".as_ptr(), 10, 0));
        assert!(!validate_permit(b"host:0".as_ptr(), 6, 0));
        assert!(!validate_permit(b"foo/bar".as_ptr(), 7, 0));
    }

    #[test]
    fn parse_ipqos_handles_basic_forms() {
        assert_eq!(parse_ipqos(b"af21".as_ptr(), 4), Some(IPQOS_AF21));
        assert_eq!(parse_ipqos(b"CS6".as_ptr(), 3), Some(IPQOS_CS6));
        assert_eq!(parse_ipqos(b"none".as_ptr(), 4), Some(IPQOS_NONE));
        assert_eq!(parse_ipqos(b"184".as_ptr(), 3), Some(184));
    }

    #[test]
    fn parse_ipqos_rejects_bad_forms() {
        assert_eq!(parse_ipqos(core::ptr::null(), 0), None);
        assert_eq!(parse_ipqos(b"".as_ptr(), 0), None);
        assert_eq!(parse_ipqos(b"256".as_ptr(), 3), None);
        assert_eq!(parse_ipqos(b"-1".as_ptr(), 2), None);
        assert_eq!(parse_ipqos(b"bogus".as_ptr(), 5), None);
    }

    #[test]
    fn valid_env_name_handles_basic_forms() {
        assert!(valid_env_name(b"FOO".as_ptr(), 3));
        assert!(valid_env_name(b"foo_123".as_ptr(), 7));
        assert!(!valid_env_name(core::ptr::null(), 0));
        assert!(!valid_env_name(b"".as_ptr(), 0));
        assert!(!valid_env_name(b"FOO-BAR".as_ptr(), 7));
        assert!(!valid_env_name(b"FOO.BAR".as_ptr(), 7));
    }

    #[test]
    fn valid_domain_handles_basic_forms() {
        let mut lowered = b"EXAMPLE.COM.".to_vec();
        assert_eq!(valid_domain(lowered.as_mut_ptr(), lowered.len(), 1), Ok(()));
        assert_eq!(&lowered[..], b"example.com\0");

        let mut preserved = b"MiXeD.Example".to_vec();
        assert_eq!(valid_domain(preserved.as_mut_ptr(), preserved.len(), 0), Ok(()));
        assert_eq!(&preserved[..], b"MiXeD.Example");
    }

    #[test]
    fn valid_domain_rejects_bad_forms() {
        let mut empty = Vec::<u8>::new();
        assert_eq!(
            valid_domain(empty.as_mut_ptr(), empty.len(), 1),
            Err(DOMAIN_STATUS_EMPTY)
        );

        let mut bad_start = b"-bad.example".to_vec();
        assert_eq!(
            valid_domain(bad_start.as_mut_ptr(), bad_start.len(), 1),
            Err(DOMAIN_STATUS_START_INVALID)
        );

        let mut double_dot = b"bad..example".to_vec();
        assert_eq!(
            valid_domain(double_dot.as_mut_ptr(), double_dot.len(), 1),
            Err(DOMAIN_STATUS_CONSECUTIVE_SEPARATORS)
        );

        let mut bad_chars = b"bad!example".to_vec();
        assert_eq!(
            valid_domain(bad_chars.as_mut_ptr(), bad_chars.len(), 1),
            Err(DOMAIN_STATUS_INVALID_CHARS)
        );
    }

    #[test]
    fn parse_pattern_interval_handles_basic_forms() {
        assert_eq!(
            parse_pattern_interval(b"session:command=1m".as_ptr(), 18),
            Some(PatternIntervalParse {
                type_len: 15,
                interval_offset: 16,
                interval_len: 2,
            })
        );
        assert_eq!(
            parse_pattern_interval(b"global=10".as_ptr(), 9),
            Some(PatternIntervalParse {
                type_len: 6,
                interval_offset: 7,
                interval_len: 2,
            })
        );
    }

    #[test]
    fn parse_pattern_interval_rejects_bad_forms() {
        assert_eq!(parse_pattern_interval(core::ptr::null(), 0), None);
        assert_eq!(parse_pattern_interval(b"".as_ptr(), 0), None);
        assert_eq!(parse_pattern_interval(b"session".as_ptr(), 7), None);
        assert_eq!(parse_pattern_interval(b"=1m".as_ptr(), 3), None);
        assert_eq!(parse_pattern_interval(b"session=".as_ptr(), 8), None);
    }

    #[test]
    fn a2port_handles_basic_forms() {
        assert_eq!(a2port(b"0".as_ptr(), 1), Some(0));
        assert_eq!(a2port(b"22".as_ptr(), 2), Some(22));
        assert_eq!(a2port(b"65535".as_ptr(), 5), Some(65535));
        assert_eq!(a2port(b"smtp".as_ptr(), 4), Some(25));
    }

    #[test]
    fn a2port_rejects_bad_forms() {
        assert_eq!(a2port(core::ptr::null(), 0), None);
        assert_eq!(a2port(b"".as_ptr(), 0), None);
        assert_eq!(a2port(b"-1".as_ptr(), 2), None);
        assert_eq!(a2port(b"65536".as_ptr(), 5), None);
        assert_eq!(a2port(b"no-such-service".as_ptr(), 15), None);
    }

    #[test]
    fn atoi_err_handles_basic_forms() {
        assert_eq!(atoi_err(b"0".as_ptr(), 1), Ok(0));
        assert_eq!(atoi_err(b"22".as_ptr(), 2), Ok(22));
        assert_eq!(atoi_err(b"+1".as_ptr(), 2), Ok(1));
        assert_eq!(atoi_err(b"-0".as_ptr(), 2), Ok(0));
        assert_eq!(atoi_err(b"2147483647".as_ptr(), 10), Ok(i32::MAX));
    }

    #[test]
    fn atoi_err_reports_status() {
        assert_eq!(atoi_err(core::ptr::null(), 0), Err(ATOI_STATUS_MISSING));
        assert_eq!(atoi_err(b"".as_ptr(), 0), Err(ATOI_STATUS_MISSING));
        assert_eq!(atoi_err(b"bogus".as_ptr(), 5), Err(ATOI_STATUS_INVALID));
        assert_eq!(atoi_err(b"+".as_ptr(), 1), Err(ATOI_STATUS_INVALID));
        assert_eq!(atoi_err(b"-1".as_ptr(), 2), Err(ATOI_STATUS_TOO_SMALL));
        assert_eq!(atoi_err(b"2147483648".as_ptr(), 10), Err(ATOI_STATUS_TOO_LARGE));
    }

    #[test]
    fn multistate_lookup_handles_basic_forms() {
        let yes = CString::new("yes").unwrap();
        let no = CString::new("no").unwrap();
        let entries = [
            MultistateEntry {
                key: yes.as_ptr(),
                value: 1,
            },
            MultistateEntry {
                key: no.as_ptr(),
                value: 0,
            },
        ];

        assert_eq!(
            multistate_lookup(b"YES".as_ptr(), 3, entries.as_ptr(), entries.len()),
            Some(1)
        );
        assert_eq!(
            multistate_lookup(b"no".as_ptr(), 2, entries.as_ptr(), entries.len()),
            Some(0)
        );
    }

    #[test]
    fn multistate_lookup_rejects_bad_forms() {
        let yes = CString::new("yes").unwrap();
        let entries = [MultistateEntry {
            key: yes.as_ptr(),
            value: 1,
        }];

        assert_eq!(multistate_lookup(core::ptr::null(), 0, entries.as_ptr(), 1), None);
        assert_eq!(multistate_lookup(b"maybe".as_ptr(), 5, entries.as_ptr(), 1), None);
        assert_eq!(multistate_lookup(b"yes".as_ptr(), 3, core::ptr::null(), 1), None);
    }

    #[test]
    fn multistate_name_handles_basic_forms() {
        let yes = CString::new("yes").unwrap();
        let no = CString::new("no").unwrap();
        let entries = [
            MultistateEntry {
                key: yes.as_ptr(),
                value: 1,
            },
            MultistateEntry {
                key: no.as_ptr(),
                value: 0,
            },
        ];

        assert_eq!(multistate_name(1, entries.as_ptr(), entries.len()), Some(0));
        assert_eq!(multistate_name(0, entries.as_ptr(), entries.len()), Some(1));
    }

    #[test]
    fn multistate_name_rejects_bad_forms() {
        let yes = CString::new("yes").unwrap();
        let entries = [MultistateEntry {
            key: yes.as_ptr(),
            value: 1,
        }];

        assert_eq!(multistate_name(2, entries.as_ptr(), entries.len()), None);
        assert_eq!(multistate_name(1, core::ptr::null(), 1), None);
    }

    #[test]
    fn keyword_lookup_handles_basic_forms() {
        let user = CString::new("user").unwrap();
        let hostname = CString::new("hostname").unwrap();
        let entries = [
            KeywordEntry {
                key: user.as_ptr(),
                value: 1,
            },
            KeywordEntry {
                key: hostname.as_ptr(),
                value: 2,
            },
        ];

        assert_eq!(
            keyword_lookup(b"user".as_ptr(), 4, entries.as_ptr(), entries.len(), false),
            Some(1)
        );
        assert_eq!(
            keyword_lookup(b"HOSTNAME".as_ptr(), 8, entries.as_ptr(), entries.len(), true),
            Some(2)
        );
    }

    #[test]
    fn keyword_lookup_rejects_bad_forms() {
        let user = CString::new("user").unwrap();
        let entries = [KeywordEntry {
            key: user.as_ptr(),
            value: 1,
        }];

        assert_eq!(
            keyword_lookup(b"USER".as_ptr(), 4, entries.as_ptr(), entries.len(), false),
            None
        );
        assert_eq!(keyword_lookup(core::ptr::null(), 0, entries.as_ptr(), 1, false), None);
        assert_eq!(keyword_lookup(b"user".as_ptr(), 4, core::ptr::null(), 1, false), None);
    }

    #[test]
    fn parse_convtime_double_handles_basic_forms() {
        assert_eq!(parse_convtime_double(b"0".as_ptr(), 1), Some(0.0));
        assert_eq!(parse_convtime_double(b"1".as_ptr(), 1), Some(1.0));
        assert_eq!(parse_convtime_double(b"2s".as_ptr(), 2), Some(2.0));
        assert_eq!(parse_convtime_double(b"3m".as_ptr(), 2), Some(180.0));
        assert_eq!(parse_convtime_double(b"1m30s".as_ptr(), 5), Some(90.0));
        assert_eq!(parse_convtime_double(b"1.5s".as_ptr(), 4), Some(1.5));
        assert_eq!(parse_convtime_double(b".5s".as_ptr(), 3), Some(0.5));
        assert_eq!(parse_convtime_double(b"1m.5s".as_ptr(), 5), Some(60.5));
        assert_eq!(parse_convtime_double(b"1w2d3h4m5s".as_ptr(), 10), Some(788645.0));
    }

    #[test]
    fn parse_convtime_double_rejects_bad_forms() {
        assert_eq!(parse_convtime_double(core::ptr::null(), 0), None);
        assert_eq!(parse_convtime_double(b"".as_ptr(), 0), None);
        assert_eq!(parse_convtime_double(b"trout".as_ptr(), 5), None);
        assert_eq!(parse_convtime_double(b"1.s".as_ptr(), 3), None);
        assert_eq!(parse_convtime_double(b"0x1".as_ptr(), 3), None);
        assert_eq!(parse_convtime_double(b"-1".as_ptr(), 2), None);
        assert_eq!(parse_convtime_double(b"3.w0.5s".as_ptr(), 7), None);
        assert_eq!(parse_convtime_double(b"1.0d0.5s".as_ptr(), 8), None);
        assert_eq!(parse_convtime_double(b"1.5m".as_ptr(), 4), None);
        assert_eq!(parse_convtime_double(b"1s1.5".as_ptr(), 5), None);
    }

    #[test]
    fn parse_absolute_time_handles_basic_forms() {
        assert_eq!(
            parse_absolute_time(b"20000101Z".as_ptr(), b"20000101Z".len()),
            Some(946684800)
        );
        assert_eq!(
            parse_absolute_time(b"200001011223UTC".as_ptr(), b"200001011223UTC".len()),
            Some(946729380)
        );
        assert_eq!(
            parse_absolute_time(
                b"20000101122345UTC".as_ptr(),
                b"20000101122345UTC".len()
            ),
            Some(946729425)
        );
        assert!(parse_absolute_time(b"20000101".as_ptr(), b"20000101".len()).is_some());
        assert!(parse_absolute_time(b"200001011223".as_ptr(), b"200001011223".len()).is_some());
        assert!(
            parse_absolute_time(b"20000101122345".as_ptr(), b"20000101122345".len()).is_some()
        );
    }

    #[test]
    fn parse_absolute_time_rejects_bad_forms() {
        for bad in [
            b"20001301".as_slice(),
            b"20000001".as_slice(),
            b"2".as_slice(),
            b"2000".as_slice(),
            b"20000".as_slice(),
            b"200001".as_slice(),
            b"2000010".as_slice(),
            b"200001010".as_slice(),
            b"20000199".as_slice(),
            b"200001019900".as_slice(),
            b"200001010099".as_slice(),
            b"20000101000099".as_slice(),
            b"20000101ZZ".as_slice(),
            b"20000101PDT".as_slice(),
            b"20000101U".as_slice(),
            b"20000101UTCUTC".as_slice(),
        ] {
            assert_eq!(parse_absolute_time(bad.as_ptr(), bad.len()), None);
        }
    }

    #[test]
    fn parse_hostfile_line_handles_basic_forms() {
        let revoked = b"@revoked host.example ssh-ed25519 AAAAC3Nza comment";
        assert_eq!(
            parse_hostfile_line(revoked.as_ptr(), revoked.len()),
            Some(HostfileLineParse {
                kind: 2,
                marker: 2,
                hosts_offset: 9,
                hosts_len: 12,
                rawkey_offset: 22,
                keytype_offset: 22,
                keytype_len: 11,
            })
        );
        let invalid_marker = b"@bad host key";
        assert_eq!(
            parse_hostfile_line(invalid_marker.as_ptr(), invalid_marker.len()),
            Some(HostfileLineParse {
                kind: 3,
                marker: 0,
                hosts_offset: 0,
                hosts_len: 0,
                rawkey_offset: 0,
                keytype_offset: 0,
                keytype_len: 0,
            })
        );
        let comment = b"   # comment";
        assert_eq!(
            parse_hostfile_line(comment.as_ptr(), comment.len()),
            Some(HostfileLineParse {
                kind: 1,
                marker: 1,
                hosts_offset: 0,
                hosts_len: 0,
                rawkey_offset: 0,
                keytype_offset: 0,
                keytype_len: 0,
            })
        );
    }

    #[test]
    fn parse_hostfile_line_rejects_bad_forms() {
        let double_marker = b"@revoked @cert-authority host key";
        assert_eq!(
            parse_hostfile_line(double_marker.as_ptr(), double_marker.len()),
            Some(HostfileLineParse {
                kind: 3,
                marker: 0,
                hosts_offset: 0,
                hosts_len: 0,
                rawkey_offset: 0,
                keytype_offset: 0,
                keytype_len: 0,
            })
        );
        let no_key = b"host.example   ";
        assert_eq!(
            parse_hostfile_line(no_key.as_ptr(), no_key.len()),
            Some(HostfileLineParse {
                kind: 4,
                marker: 1,
                hosts_offset: 0,
                hosts_len: 12,
                rawkey_offset: 0,
                keytype_offset: 0,
                keytype_len: 0,
            })
        );
        let no_blob = b"host.example ssh-ed25519 ";
        assert_eq!(
            parse_hostfile_line(no_blob.as_ptr(), no_blob.len()),
            Some(HostfileLineParse {
                kind: 4,
                marker: 1,
                hosts_offset: 0,
                hosts_len: 12,
                rawkey_offset: 13,
                keytype_offset: 13,
                keytype_len: 11,
            })
        );
    }

    #[test]
    fn host_hash_reuses_known_salt_and_matches_fixture() {
        let host = b"sisyphus.example.com";
        let entry = b"|1|B7t/AYabn8zgwU47Cb4A/Nqt3eI=|arQPZyRphkzisr7w6wwikvhaOyE=";
        let mut out = [0u8; 128];
        assert_eq!(
            host_hash_write(
                host.as_ptr(),
                host.len(),
                entry.as_ptr(),
                entry.len(),
                out.as_mut_ptr(),
                out.len()
            ),
            0
        );
        let out_len = out.iter().position(|byte| *byte == 0).unwrap();
        assert_eq!(&out[..out_len], entry);
        assert_eq!(match_hashed_host(host.as_ptr(), host.len(), entry.as_ptr(), entry.len()), 1);
        assert_eq!(
            match_hashed_host(
                b"prometheus.example.com".as_ptr(),
                b"prometheus.example.com".len(),
                entry.as_ptr(),
                entry.len()
            ),
            0
        );
    }

    #[test]
    fn host_hash_rejects_invalid_hashed_entries() {
        let host = b"sisyphus.example.com";
        assert_eq!(
            match_hashed_host(host.as_ptr(), host.len(), b"|1|bad".as_ptr(), b"|1|bad".len()),
            -1
        );
    }

    #[test]
    fn parse_user_host_path_handles_basic_forms() {
        assert_eq!(
            parse_user_host_path(b"someuser@some.host:some/path".as_ptr(), 28),
            Some(UserHostPathParse {
                user_offset: 0,
                user_len: 8,
                host_offset: 9,
                host_len: 9,
                path_offset: 19,
                path_len: 9,
                has_user: 1,
            })
        );
        assert_eq!(
            parse_user_host_path(b"someuser@[::1]:some/path".as_ptr(), 24),
            Some(UserHostPathParse {
                user_offset: 0,
                user_len: 8,
                host_offset: 9,
                host_len: 5,
                path_offset: 15,
                path_len: 9,
                has_user: 1,
            })
        );
    }

    #[test]
    fn parse_user_host_path_rejects_bad_forms() {
        assert_eq!(parse_user_host_path(b"".as_ptr(), 0), None);
        assert_eq!(parse_user_host_path(b":path".as_ptr(), 5), None);
        assert_eq!(parse_user_host_path(b"host/path".as_ptr(), 9), None);
    }
}
