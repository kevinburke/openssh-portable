#![no_main]

use std::ptr;
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_ecdsa_export_private, ossh_rust_ecdsa_export_public, ossh_rust_ecdsa_free,
    ossh_rust_ecdsa_from_private, ossh_rust_ecdsa_from_public, ossh_rust_ecdsa_generate,
    ossh_rust_ecdsa_sign_prehashed, ossh_rust_ecdsa_verify_prehashed,
};

const NID_X9_62_PRIME256V1: i32 = 415;
const NID_SECP384R1: i32 = 715;
const NID_SECP521R1: i32 = 716;

#[derive(Clone)]
struct Fixture {
    curve_nid: i32,
    digest_len: usize,
    public_len: usize,
    private_len: usize,
    signature_len: usize,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    curve_selector: u8,
    use_valid_public: bool,
    use_valid_private: bool,
    mutate_public: bool,
    mutate_public_index: u16,
    mutate_private: bool,
    mutate_private_index: u16,
    arbitrary_public: Vec<u8>,
    arbitrary_private: Vec<u8>,
    short_public: u8,
    short_private: u8,
}

fn fixtures() -> &'static [Fixture; 3] {
    static FIXTURES: OnceLock<[Fixture; 3]> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        [
            build_fixture(NID_X9_62_PRIME256V1, 65, 32, 64, 32),
            build_fixture(NID_SECP384R1, 97, 48, 96, 48),
            build_fixture(NID_SECP521R1, 133, 66, 132, 64),
        ]
    })
}

fn build_fixture(
    curve_nid: i32,
    public_len: usize,
    private_len: usize,
    signature_len: usize,
    digest_len: usize,
) -> Fixture {
    let key = ossh_rust_ecdsa_generate(curve_nid);
    assert!(!key.is_null());

    let mut public_key = vec![0u8; public_len];
    let mut private_key = vec![0u8; private_len];
    assert_eq!(
        ossh_rust_ecdsa_export_public(key, public_key.as_mut_ptr(), public_key.len()),
        0
    );
    assert_eq!(
        ossh_rust_ecdsa_export_private(key, private_key.as_mut_ptr(), private_key.len()),
        0
    );
    ossh_rust_ecdsa_free(key);

    Fixture {
        curve_nid,
        digest_len,
        public_len,
        private_len,
        signature_len,
        public_key,
        private_key,
    }
}

fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fuzz_target!(|input: Input| {
    let fixture = &fixtures()[usize::from(input.curve_selector) % fixtures().len()];

    let mut public_key = if input.use_valid_public {
        fixture.public_key.clone()
    } else {
        input.arbitrary_public
    };
    public_key.truncate(fixture.public_len.saturating_mul(2));
    if input.mutate_public && !public_key.is_empty() {
        let idx = usize::from(input.mutate_public_index) % public_key.len();
        public_key[idx] ^= 0x01;
    }
    let public_len = if input.use_valid_public && !input.mutate_public && input.short_public == 0 {
        fixture.public_len
    } else {
        usize::from(input.short_public) % (public_key.len().saturating_add(1))
    };
    let public_view = &public_key[..public_len.min(public_key.len())];

    let mut private_key = if input.use_valid_private {
        fixture.private_key.clone()
    } else {
        input.arbitrary_private
    };
    private_key.truncate(fixture.private_len.saturating_mul(2));
    if input.mutate_private && !private_key.is_empty() {
        let idx = usize::from(input.mutate_private_index) % private_key.len();
        private_key[idx] ^= 0x01;
    }
    let private_len = if input.use_valid_private && !input.mutate_private && input.short_private == 0
    {
        fixture.private_len
    } else {
        usize::from(input.short_private) % (private_key.len().saturating_add(1))
    };
    let private_view = &private_key[..private_len.min(private_key.len())];

    let public = ossh_rust_ecdsa_from_public(
        fixture.curve_nid,
        slice_ptr(public_view),
        public_view.len(),
    );
    let private = ossh_rust_ecdsa_from_private(
        fixture.curve_nid,
        slice_ptr(public_view),
        public_view.len(),
        slice_ptr(private_view),
        private_view.len(),
    );

    if input.use_valid_public && !input.mutate_public && public_view.len() == fixture.public_len {
        assert!(!public.is_null());
    }
    if input.use_valid_public
        && input.use_valid_private
        && !input.mutate_public
        && !input.mutate_private
        && public_view.len() == fixture.public_len
        && private_view.len() == fixture.private_len
    {
        assert!(!private.is_null());
    }

    if !private.is_null() && !public.is_null() {
        let digest = vec![0x5a; fixture.digest_len];
        let mut signature = vec![0u8; fixture.signature_len];
        let sign_rc = ossh_rust_ecdsa_sign_prehashed(
            private,
            digest.as_ptr(),
            digest.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );
        if sign_rc == 0 {
            assert_eq!(
                ossh_rust_ecdsa_verify_prehashed(
                    public,
                    digest.as_ptr(),
                    digest.len(),
                    signature.as_ptr(),
                    signature.len(),
                ),
                0
            );
        }
    }

    if !public.is_null() {
        ossh_rust_ecdsa_free(public);
    }
    if !private.is_null() {
        ossh_rust_ecdsa_free(private);
    }
});
