#![no_main]
use std::mem::{transmute, MaybeUninit};
use std::ptr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_a2port, ossh_rust_argv_split_parse, ossh_rust_argv_split_write,
    ossh_rust_atoi_err, ossh_rust_convtime_double, ossh_rust_dollar_expand_parse,
    ossh_rust_dollar_expand_write, ossh_rust_expand_parse, ossh_rust_expand_write,
    ossh_rust_keyword_lookup, ossh_rust_lookup_env_in_list, ossh_rust_lookup_setenv_in_list,
    ossh_rust_multistate_lookup, ossh_rust_opt_dequote_parse, ossh_rust_opt_dequote_write,
    ossh_rust_opt_flag, ossh_rust_opt_match, ossh_rust_parse_absolute_time,
    ossh_rust_parse_forward, ossh_rust_parse_forward_field, ossh_rust_parse_hostfile_line,
    ossh_rust_parse_ipqos, ossh_rust_parse_jump, ossh_rust_parse_pattern_interval,
    ossh_rust_parse_uri, ossh_rust_parse_user_host_path, ossh_rust_parse_user_host_port,
    ossh_rust_valid_domain, ossh_rust_valid_env_name, ossh_rust_validate_permit,
    RustArgvSplitParse, RustDollarExpandParse, RustExpandEntry, RustForwardFieldParse,
    RustForwardParse, RustHostfileLineParse, RustJumpParse, RustKeywordEntry,
    RustMultistateEntry, RustOptDequoteParse, RustPatternIntervalParse, RustUriParse,
    RustUserHostPathParse, RustUserHostPortParse,
};

#[repr(C)]
struct ArgvSplitParseRepr {
    argc: usize,
    packed_len: usize,
}

#[repr(C)]
struct OptDequoteParseRepr {
    output_len: usize,
    next_offset: usize,
}

#[repr(C)]
struct DollarExpandParseRepr {
    output_len: usize,
    missing_var: u32,
}

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    aux: Vec<u8>,
    flag_bits: u8,
}

fn ptr_or_null(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fn mut_ptr_or_null(bytes: &mut [u8]) -> *mut u8 {
    if bytes.is_empty() {
        ptr::null_mut()
    } else {
        bytes.as_mut_ptr()
    }
}

fn cap(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.truncate(2048);
    bytes
}

fn capped_alloc(len: usize) -> Option<Vec<u8>> {
    (len <= 8192).then(|| vec![0u8; len])
}

fn keyword_entries() -> [RustKeywordEntry; 3] {
    [
        RustKeywordEntry {
            key: c"user".as_ptr(),
            value: 1,
        },
        RustKeywordEntry {
            key: c"hostname".as_ptr(),
            value: 2,
        },
        RustKeywordEntry {
            key: c"proxyjump".as_ptr(),
            value: 3,
        },
    ]
}

fn multistate_entries() -> [RustMultistateEntry; 4] {
    [
        RustMultistateEntry {
            key: c"yes".as_ptr(),
            value: 1,
        },
        RustMultistateEntry {
            key: c"no".as_ptr(),
            value: 0,
        },
        RustMultistateEntry {
            key: c"ask".as_ptr(),
            value: 2,
        },
        RustMultistateEntry {
            key: c"confirm".as_ptr(),
            value: 3,
        },
    ]
}

fn expand_entries() -> [RustExpandEntry; 3] {
    [
        RustExpandEntry {
            key: c"h".as_ptr(),
            repl: c"host".as_ptr(),
        },
        RustExpandEntry {
            key: c"p".as_ptr(),
            repl: c"2222".as_ptr(),
        },
        RustExpandEntry {
            key: c"u".as_ptr(),
            repl: c"user".as_ptr(),
        },
    ]
}

fn env_list() -> [*const u8; 4] {
    // These helpers expect C-style "name=value\0" entries, so keep the
    // terminator in the fixture bytes instead of relying on Rust string types.
    [
        b"TERM=xterm\0".as_ptr(),
        b"FOO=bar\0".as_ptr(),
        b"EMPTY=\0".as_ptr(),
        b"HOME=/tmp\0".as_ptr(),
    ]
}

fuzz_target!(|input: Input| {
    let data = cap(input.data);
    let aux = cap(input.aux);
    let data_ptr = ptr_or_null(&data);
    let aux_ptr = ptr_or_null(&aux);

    let mut argv_out = MaybeUninit::<RustArgvSplitParse>::uninit();
    if ossh_rust_argv_split_parse(
        data_ptr,
        data.len(),
        i32::from(input.flag_bits & 1 != 0),
        argv_out.as_mut_ptr(),
    ) == 0
    {
        let parsed: ArgvSplitParseRepr = unsafe { transmute(argv_out.assume_init()) };
        if let Some(mut out) = capped_alloc(parsed.packed_len) {
            let _ = ossh_rust_argv_split_write(
                data_ptr,
                data.len(),
                i32::from(input.flag_bits & 1 != 0),
                out.as_mut_ptr(),
                out.len(),
            );
        }
    }

    let mut field_buf = data.clone();
    let mut field_out = MaybeUninit::<RustForwardFieldParse>::uninit();
    let _ = ossh_rust_parse_forward_field(
        mut_ptr_or_null(&mut field_buf),
        field_buf.len(),
        field_out.as_mut_ptr(),
    );

    for &(dynamicfwd, remotefwd) in &[(0, 0), (1, 0), (0, 1)] {
        let mut forward_buf = data.clone();
        let mut forward_out = MaybeUninit::<RustForwardParse>::uninit();
        let _ = ossh_rust_parse_forward(
            mut_ptr_or_null(&mut forward_buf),
            forward_buf.len(),
            dynamicfwd,
            remotefwd,
            forward_out.as_mut_ptr(),
        );
    }

    let mut jump_out = MaybeUninit::<RustJumpParse>::uninit();
    let _ = ossh_rust_parse_jump(data_ptr, data.len(), jump_out.as_mut_ptr());

    let mut hostfile_out = MaybeUninit::<RustHostfileLineParse>::uninit();
    let _ = ossh_rust_parse_hostfile_line(data_ptr, data.len(), hostfile_out.as_mut_ptr());

    let mut user_host_port_out = MaybeUninit::<RustUserHostPortParse>::uninit();
    let _ = ossh_rust_parse_user_host_port(
        data_ptr,
        data.len(),
        user_host_port_out.as_mut_ptr(),
    );

    let mut uri_out = MaybeUninit::<RustUriParse>::uninit();
    let _ = ossh_rust_parse_uri(data_ptr, data.len(), uri_out.as_mut_ptr());

    let mut user_host_path_out = MaybeUninit::<RustUserHostPathParse>::uninit();
    let _ = ossh_rust_parse_user_host_path(
        data_ptr,
        data.len(),
        user_host_path_out.as_mut_ptr(),
    );

    let _ = ossh_rust_validate_permit(data_ptr, data.len(), i32::from(input.flag_bits & 2 != 0));

    let mut int_out = 0i32;
    let mut atoi_status = 0i32;
    let _ = ossh_rust_parse_ipqos(data_ptr, data.len(), &mut int_out);
    let _ = ossh_rust_a2port(data_ptr, data.len(), &mut int_out);
    let _ = ossh_rust_atoi_err(data_ptr, data.len(), &mut int_out, &mut atoi_status);

    let entries = multistate_entries();
    let _ = ossh_rust_multistate_lookup(
        data_ptr,
        data.len(),
        entries.as_ptr(),
        entries.len(),
        &mut int_out,
    );

    let keywords = keyword_entries();
    let _ = ossh_rust_keyword_lookup(
        data_ptr,
        data.len(),
        keywords.as_ptr(),
        keywords.len(),
        i32::from(input.flag_bits & 4 != 0),
        &mut int_out,
    );

    let mut offset = 0usize;
    let mut result = 0i32;
    let _ = ossh_rust_opt_flag(
        c"no-touch".as_ptr().cast(),
        b"no-touch".len(),
        i32::from(input.flag_bits & 8 != 0),
        data_ptr,
        data.len(),
        &mut offset,
        &mut result,
    );
    let _ = ossh_rust_opt_match(
        c"command".as_ptr().cast(),
        b"command".len(),
        data_ptr,
        data.len(),
        &mut offset,
        &mut result,
    );

    let envs = env_list();
    let mut value_offset = 0usize;
    let _ = ossh_rust_lookup_env_in_list(
        data_ptr,
        data.len(),
        envs.as_ptr().cast(),
        envs.len(),
        &mut offset,
        &mut value_offset,
    );
    let _ = ossh_rust_lookup_setenv_in_list(
        data_ptr,
        data.len(),
        envs.as_ptr().cast(),
        envs.len(),
        &mut offset,
        &mut value_offset,
    );

    let mut dequote_out = MaybeUninit::<RustOptDequoteParse>::uninit();
    let mut status = 0i32;
    if ossh_rust_opt_dequote_parse(data_ptr, data.len(), dequote_out.as_mut_ptr(), &mut status) == 0 {
        let parsed: OptDequoteParseRepr = unsafe { transmute(dequote_out.assume_init()) };
        if let Some(mut out) = capped_alloc(parsed.output_len) {
            let _ = ossh_rust_opt_dequote_write(data_ptr, data.len(), out.as_mut_ptr(), out.len());
        }
    }

    let mut dollar_out = MaybeUninit::<RustDollarExpandParse>::uninit();
    if ossh_rust_dollar_expand_parse(data_ptr, data.len(), dollar_out.as_mut_ptr(), &mut status) == 0 {
        let parsed: DollarExpandParseRepr = unsafe { transmute(dollar_out.assume_init()) };
        if parsed.missing_var == 0 {
            if let Some(mut out) = capped_alloc(parsed.output_len) {
                let _ = ossh_rust_dollar_expand_write(
                    data_ptr,
                    data.len(),
                    out.as_mut_ptr(),
                    out.len(),
                );
            }
        }
    }

    let expand_entries = expand_entries();
    let expand_flags = if input.flag_bits & 16 != 0 { 3 } else { 2 };
    let mut expand_out = MaybeUninit::<RustDollarExpandParse>::uninit();
    if ossh_rust_expand_parse(
        aux_ptr,
        aux.len(),
        expand_flags,
        expand_entries.as_ptr(),
        expand_entries.len(),
        expand_out.as_mut_ptr(),
        &mut status,
    ) == 0
    {
        let parsed: DollarExpandParseRepr = unsafe { transmute(expand_out.assume_init()) };
        if parsed.missing_var == 0 {
            if let Some(mut out) = capped_alloc(parsed.output_len) {
                let _ = ossh_rust_expand_write(
                    aux_ptr,
                    aux.len(),
                    expand_flags,
                    expand_entries.as_ptr(),
                    expand_entries.len(),
                    out.as_mut_ptr(),
                    out.len(),
                );
            }
        }
    }

    let _ = ossh_rust_valid_env_name(data_ptr, data.len());

    let mut domain_buf = data.clone();
    let mut domain_status = 0i32;
    let _ = ossh_rust_valid_domain(
        mut_ptr_or_null(&mut domain_buf),
        domain_buf.len(),
        i32::from(input.flag_bits & 32 != 0),
        &mut domain_status,
    );

    let mut time_out = 0u64;
    let mut conv_out = 0.0f64;
    let _ = ossh_rust_parse_absolute_time(data_ptr, data.len(), &mut time_out);
    let _ = ossh_rust_convtime_double(data_ptr, data.len(), &mut conv_out);

    let mut pattern_out = MaybeUninit::<RustPatternIntervalParse>::uninit();
    let _ = ossh_rust_parse_pattern_interval(data_ptr, data.len(), pattern_out.as_mut_ptr());
});
