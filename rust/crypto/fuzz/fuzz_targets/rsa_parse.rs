#![no_main]

use std::ptr;
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_rsa_component_len, ossh_rust_rsa_export_component, ossh_rust_rsa_free,
    ossh_rust_rsa_from_private, ossh_rust_rsa_from_public, ossh_rust_rsa_generate,
    ossh_rust_rsa_sign_prehashed, ossh_rust_rsa_verify_prehashed,
};

const SSH_DIGEST_SHA256: i32 = 2;
const OSSH_RUST_RSA_COMPONENT_N: i32 = 1;
const OSSH_RUST_RSA_COMPONENT_E: i32 = 2;
const OSSH_RUST_RSA_COMPONENT_D: i32 = 3;
const OSSH_RUST_RSA_COMPONENT_IQMP: i32 = 4;
const OSSH_RUST_RSA_COMPONENT_P: i32 = 5;
const OSSH_RUST_RSA_COMPONENT_Q: i32 = 6;
const MAX_COMPONENT_LEN: usize = 512;

#[derive(Clone)]
struct Fixture {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
    private_exponent: Vec<u8>,
    iqmp: Vec<u8>,
    prime_p: Vec<u8>,
    prime_q: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    use_valid_modulus: bool,
    use_valid_exponent: bool,
    use_valid_private: bool,
    use_valid_iqmp: bool,
    use_valid_p: bool,
    use_valid_q: bool,
    mutate_modulus: bool,
    mutate_modulus_index: u16,
    mutate_exponent: bool,
    mutate_exponent_index: u16,
    mutate_private: bool,
    mutate_private_index: u16,
    mutate_iqmp: bool,
    mutate_iqmp_index: u16,
    mutate_p: bool,
    mutate_p_index: u16,
    mutate_q: bool,
    mutate_q_index: u16,
    arbitrary_modulus: Vec<u8>,
    arbitrary_exponent: Vec<u8>,
    arbitrary_private: Vec<u8>,
    arbitrary_iqmp: Vec<u8>,
    arbitrary_p: Vec<u8>,
    arbitrary_q: Vec<u8>,
    short_modulus: u16,
    short_exponent: u16,
    short_private: u16,
    short_iqmp: u16,
    short_p: u16,
    short_q: u16,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let key = ossh_rust_rsa_generate(1024);
        assert!(!key.is_null());
        let fixture = Fixture {
            modulus: export_component(key, OSSH_RUST_RSA_COMPONENT_N),
            exponent: export_component(key, OSSH_RUST_RSA_COMPONENT_E),
            private_exponent: export_component(key, OSSH_RUST_RSA_COMPONENT_D),
            iqmp: export_component(key, OSSH_RUST_RSA_COMPONENT_IQMP),
            prime_p: export_component(key, OSSH_RUST_RSA_COMPONENT_P),
            prime_q: export_component(key, OSSH_RUST_RSA_COMPONENT_Q),
        };
        ossh_rust_rsa_free(key);
        fixture
    })
}

fn export_component(key: *const core::ffi::c_void, component: i32) -> Vec<u8> {
    let len = ossh_rust_rsa_component_len(key, component);
    assert!(len > 0);
    let mut out = vec![0u8; len];
    assert_eq!(
        ossh_rust_rsa_export_component(key, component, out.as_mut_ptr(), out.len()),
        0
    );
    out
}

fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fn maybe_mutate(bytes: &mut [u8], mutate: bool, index: u16) {
    if mutate && !bytes.is_empty() {
        let idx = usize::from(index) % bytes.len();
        bytes[idx] ^= 0x01;
    }
}

fn view<'a>(bytes: &'a [u8], short: u16, exact: bool) -> &'a [u8] {
    if exact {
        bytes
    } else {
        let len = usize::from(short) % (bytes.len().saturating_add(1));
        &bytes[..len.min(bytes.len())]
    }
}

fuzz_target!(|input: Input| {
    let fixture = fixture();

    let mut modulus = if input.use_valid_modulus {
        fixture.modulus.clone()
    } else {
        input.arbitrary_modulus
    };
    let mut exponent = if input.use_valid_exponent {
        fixture.exponent.clone()
    } else {
        input.arbitrary_exponent
    };
    let mut private_exponent = if input.use_valid_private {
        fixture.private_exponent.clone()
    } else {
        input.arbitrary_private
    };
    let mut iqmp = if input.use_valid_iqmp {
        fixture.iqmp.clone()
    } else {
        input.arbitrary_iqmp
    };
    let mut prime_p = if input.use_valid_p {
        fixture.prime_p.clone()
    } else {
        input.arbitrary_p
    };
    let mut prime_q = if input.use_valid_q {
        fixture.prime_q.clone()
    } else {
        input.arbitrary_q
    };

    modulus.truncate(MAX_COMPONENT_LEN);
    exponent.truncate(MAX_COMPONENT_LEN);
    private_exponent.truncate(MAX_COMPONENT_LEN);
    iqmp.truncate(MAX_COMPONENT_LEN);
    prime_p.truncate(MAX_COMPONENT_LEN);
    prime_q.truncate(MAX_COMPONENT_LEN);

    maybe_mutate(&mut modulus, input.mutate_modulus, input.mutate_modulus_index);
    maybe_mutate(&mut exponent, input.mutate_exponent, input.mutate_exponent_index);
    maybe_mutate(
        &mut private_exponent,
        input.mutate_private,
        input.mutate_private_index,
    );
    maybe_mutate(&mut iqmp, input.mutate_iqmp, input.mutate_iqmp_index);
    maybe_mutate(&mut prime_p, input.mutate_p, input.mutate_p_index);
    maybe_mutate(&mut prime_q, input.mutate_q, input.mutate_q_index);

    let modulus_view = view(
        &modulus,
        input.short_modulus,
        input.use_valid_modulus && !input.mutate_modulus && input.short_modulus == 0,
    );
    let exponent_view = view(
        &exponent,
        input.short_exponent,
        input.use_valid_exponent && !input.mutate_exponent && input.short_exponent == 0,
    );
    let private_view = view(
        &private_exponent,
        input.short_private,
        input.use_valid_private && !input.mutate_private && input.short_private == 0,
    );
    let iqmp_view = view(
        &iqmp,
        input.short_iqmp,
        input.use_valid_iqmp && !input.mutate_iqmp && input.short_iqmp == 0,
    );
    let p_view = view(
        &prime_p,
        input.short_p,
        input.use_valid_p && !input.mutate_p && input.short_p == 0,
    );
    let q_view = view(
        &prime_q,
        input.short_q,
        input.use_valid_q && !input.mutate_q && input.short_q == 0,
    );

    let public = ossh_rust_rsa_from_public(
        slice_ptr(modulus_view),
        modulus_view.len(),
        slice_ptr(exponent_view),
        exponent_view.len(),
    );
    let private = ossh_rust_rsa_from_private(
        slice_ptr(modulus_view),
        modulus_view.len(),
        slice_ptr(exponent_view),
        exponent_view.len(),
        slice_ptr(private_view),
        private_view.len(),
        slice_ptr(iqmp_view),
        iqmp_view.len(),
        slice_ptr(p_view),
        p_view.len(),
        slice_ptr(q_view),
        q_view.len(),
    );

    if input.use_valid_modulus
        && input.use_valid_exponent
        && !input.mutate_modulus
        && !input.mutate_exponent
        && input.short_modulus == 0
        && input.short_exponent == 0
    {
        assert!(!public.is_null());
    }
    if input.use_valid_modulus
        && input.use_valid_exponent
        && input.use_valid_private
        && input.use_valid_iqmp
        && input.use_valid_p
        && input.use_valid_q
        && !input.mutate_modulus
        && !input.mutate_exponent
        && !input.mutate_private
        && !input.mutate_iqmp
        && !input.mutate_p
        && !input.mutate_q
        && input.short_modulus == 0
        && input.short_exponent == 0
        && input.short_private == 0
        && input.short_iqmp == 0
        && input.short_p == 0
        && input.short_q == 0
    {
        assert!(!private.is_null());
    }

    if !public.is_null() && !private.is_null() {
        let digest = [0x5a; 32];
        let mut signature = vec![0u8; modulus_view.len()];
        let sign_rc = ossh_rust_rsa_sign_prehashed(
            private,
            SSH_DIGEST_SHA256,
            digest.as_ptr(),
            digest.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );
        if sign_rc == 0 {
            assert_eq!(
                ossh_rust_rsa_verify_prehashed(
                    public,
                    SSH_DIGEST_SHA256,
                    digest.as_ptr(),
                    digest.len(),
                    signature.as_ptr(),
                    signature.len(),
                ),
                1
            );
        }
    }

    if !public.is_null() {
        ossh_rust_rsa_free(public);
    }
    if !private.is_null() {
        ossh_rust_rsa_free(private);
    }
});
