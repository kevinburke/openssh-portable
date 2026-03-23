use core::ffi::c_char;

const OSSH_RUST_CRYPTO_ABI_VERSION: u32 = 1;
static BACKEND_LABEL: &[u8] = b"Rust crypto backend\0";

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_crypto_abi_version() -> u32 {
    OSSH_RUST_CRYPTO_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn ossh_rust_crypto_backend_label() -> *const c_char {
    BACKEND_LABEL.as_ptr().cast()
}
