//! `ffi.rs`: Foreign Function Interface providing C ABI

// This is the only code in Miscreant allowed to be unsafe
#![allow(unsafe_code)]
#![allow(non_upper_case_globals)]

use aead;
use core::{ptr, slice};
use generic_array::typenum::Unsigned;

//
// AES-128-SIV AEAD
//

/// AES-128-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128siv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<aead::Aes128Siv>(
        ct,
        ctlen_p,
        msg,
        msglen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-128-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128siv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<aead::Aes128Siv>(
        msg,
        msglen_p,
        ct,
        ctlen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-128-SIV key size
#[no_mangle]
pub static crypto_aead_aes128siv_KEYBYTES: u32 = 32;

/// AES-128-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes128siv_ABYTES: u32 = 16;

//
// AES-256-SIV AEAD
//

/// AES-256-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256siv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<aead::Aes256Siv>(
        ct,
        ctlen_p,
        msg,
        msglen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-256-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256siv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<aead::Aes256Siv>(
        msg,
        msglen_p,
        ct,
        ctlen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-128-SIV key size
#[no_mangle]
pub static crypto_aead_aes256siv_KEYBYTES: u32 = 64;

/// AES-128-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes256siv_ABYTES: u32 = 16;

//
// AES-128-PMAC-SIV AEAD
//

/// AES-128-PMAC-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128pmacsiv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<aead::Aes128PmacSiv>(
        ct,
        ctlen_p,
        msg,
        msglen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-128-PMAC-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes128pmacsiv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<aead::Aes128PmacSiv>(
        msg,
        msglen_p,
        ct,
        ctlen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-128-PMAC-SIV key size
#[no_mangle]
pub static crypto_aead_aes128pmacsiv_KEYBYTES: u32 = 32;

/// AES-128-PMAC-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes128pmacsiv_ABYTES: u32 = 16;

//
// AES-256-PMAC-SIV AEAD
//

/// AES-256-PMAC-SIV AEAD: authenticated encryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256pmacsiv_encrypt(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_encrypt::<aead::Aes256PmacSiv>(
        ct,
        ctlen_p,
        msg,
        msglen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-256-PMAC-SIV AEAD: authenticated decryption
#[no_mangle]
pub unsafe extern "C" fn crypto_aead_aes256pmacsiv_decrypt(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    aead_decrypt::<aead::Aes256PmacSiv>(
        msg,
        msglen_p,
        ct,
        ctlen,
        nonce,
        noncelen,
        ad,
        adlen,
        key,
    )
}

/// AES-128-SIV key size
#[no_mangle]
pub static crypto_aead_aes256pmacsiv_KEYBYTES: u32 = 64;

/// AES-128-SIV authenticator tag size
#[no_mangle]
pub static crypto_aead_aes256pmacsiv_ABYTES: u32 = 16;

//
// Generic AEAD encrypt/decrypt
//

/// Generic C-like interface to AEAD encryption
unsafe fn aead_encrypt<A: aead::Algorithm>(
    ct: *mut u8,
    ctlen_p: *mut u64,
    msg: *const u8,
    msglen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    let taglen = A::TagSize::to_usize();

    if *ctlen_p < msglen.checked_add(taglen as u64).expect("overflow") {
        return -1;
    }

    *ctlen_p = msglen.checked_add(taglen as u64).expect("overflow");
    ptr::copy(msg, ct.offset(taglen as isize), msglen as usize);

    let key_slice = slice::from_raw_parts(key, A::KeySize::to_usize());
    let ct_slice = slice::from_raw_parts_mut(ct, *ctlen_p as usize);
    let nonce_slice = slice::from_raw_parts(nonce, noncelen as usize);
    let ad_slice = slice::from_raw_parts(ad, adlen as usize);

    A::new(key_slice).seal_in_place(nonce_slice, ad_slice, ct_slice);

    return 0;
}

/// Generic C-like interface to AEAD decryption
unsafe fn aead_decrypt<A: aead::Algorithm>(
    msg: *mut u8,
    msglen_p: *mut u64,
    ct: *const u8,
    ctlen: u64,
    nonce: *const u8,
    noncelen: u64,
    ad: *const u8,
    adlen: u64,
    key: *const u8,
) -> i32 {
    let taglen = A::TagSize::to_usize();

    if ctlen < taglen as u64 {
        return -1;
    }

    // TODO: support decrypting messages into buffers smaller than the ciphertext
    if *msglen_p < ctlen {
        return -1;
    }

    *msglen_p = ctlen.checked_sub(taglen as u64).expect("underflow");
    ptr::copy(ct, msg, ctlen as usize);

    let key_slice = slice::from_raw_parts(key, A::KeySize::to_usize());
    let msg_slice = slice::from_raw_parts_mut(msg, ctlen as usize);
    let ad_slice = slice::from_raw_parts(ad, adlen as usize);
    let nonce_slice = slice::from_raw_parts(nonce, noncelen as usize);

    if A::new(key_slice)
        .open_in_place(nonce_slice, ad_slice, msg_slice)
        .is_err()
    {
        return -1;
    }

    // Move the message to the beginning of the buffer
    ptr::copy(msg.offset(taglen as isize), msg, *msglen_p as usize);

    // Zero out the end of the buffer
    for c in msg_slice[*msglen_p as usize..].iter_mut() {
        *c = 0;
    }

    return 0;
}
