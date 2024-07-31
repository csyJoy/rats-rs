use bitflags::bitflags;
use lazy_static::lazy_static;
use libc::c_int;
use openssl_sys::*;
use pkcs8::ObjectIdentifier;
use std::cell::Cell;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::Mutex;

use crate::cert::dice::extensions::OID_TCG_DICE_ENDORSEMENT_MANIFEST;
use crate::cert::dice::extensions::OID_TCG_DICE_TAGGED_EVIDENCE;

use super::{Error, ErrorKind, Result};

pub mod client;
pub mod server;

lazy_static! {
    static ref OPENSSL_EX_DATA_IDX: Arc<Mutex<Cell<i32>>> = unsafe {
        Arc::new(Mutex::new(Cell::new(CRYPTO_get_ex_new_index(
            4,
            0,
            ptr::null_mut(),
            None,
            None,
            None,
        ))))
    };
}

trait GetFd{
    fn get_fd(&self) -> i32;
}

struct GetFdDumpImpl;

impl GetFd for GetFdDumpImpl {
    fn get_fd(&self) -> i32{
        0
    }
}

struct TcpWrapper(TcpStream);

impl GetFd for TcpWrapper {
    fn get_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

#[inline]
pub fn as_raw_mut<F, T>(p: &mut F) -> *mut T {
    p as *mut F as usize as *mut T
}

#[inline]
pub fn as_raw<F, T>(p: &F) -> *const T {
    p as *const F as usize as *const T
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct TlsFlags : u64 {
        const MUTAL = 0x0000_0001;
        const SERVER = 0x0000_0002;
        const PROVIDE_ENDORSEMENTS = 0x0000_0004;
        const ATTESTER_ENFORCED = 0x0001_0000;
        const VERIFIER_ENFORCED = 0x0002_0000;
    }

    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct SslMode : i32 {
        const SSL_VERIFY_NONE                 = 0x00;
        const SSL_VERIFY_PEER                 = 0x01;
        const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
        const SSL_VERIFY_CLIENT_ONCE          = 0x04;
        const SSL_VERIFY_POST_HANDSHAKE       = 0x08;
    }

    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct TlsErr : i32 {
        const NONE = (1 << 28);
        const NO_MEM = (1 << 28) + 1;
        const NOT_FOUND = (1 << 28) + 2;
        const INVALID = (1 << 28) + 3;
        const TRANSMIT = (1 << 28) + 4;
        const RECEIVE = (1 << 28) + 5;
        const UNSUPPORTED_QUOTE = (1 << 28) + 6;
        const PRIV_KEY = (1 << 28) + 7;
        const CERT = (1 << 28) + 8;
        const UNKNOWN = (1 << 28) + 9;
    }

    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct SslInit : u64 {
        const LOAD_CRYPTO_STRINGS = 0x0000_0002;
        const ADD_ALL_CIPHERS = 0x0000_0004;
        const ADD_ALL_DIGESTS = 0x0000_0008;
        const LOAD_SSL_STRINGS = 0x0020_0000;
    }
}

pub fn ossl_init() -> Result<()> {
    unsafe {
        OPENSSL_init_crypto(
            SslInit::ADD_ALL_DIGESTS.bits() | SslInit::ADD_ALL_DIGESTS.bits(),
            ptr::null(),
        );
        OPENSSL_init_ssl(
            SslInit::LOAD_SSL_STRINGS.bits() | SslInit::LOAD_CRYPTO_STRINGS.bits(),
            ptr::null(),
        );
        OPENSSL_init_crypto(SslInit::LOAD_CRYPTO_STRINGS.bits(), ptr::null());
        OPENSSL_init_crypto(SslInit::ADD_ALL_DIGESTS.bits(), ptr::null());
        if OPENSSL_init_ssl(0, ptr::null()) < 0 {
            return Err(Error::kind(ErrorKind::OsslInitializeFail));
        }
    }
    Ok(())
}

trait VerifyCertExtension {
    fn verify_certificate_extension(
        &mut self,
        pubkey: Vec<u8>,
        evidence: Vec<u8>,
        endorsement: Vec<u8>,
    ) -> Result<()>;
}

extern "C" fn verify_certificate_default<T: VerifyCertExtension>(
    preverify_ok: libc::c_int,
    ctx: *mut X509_STORE_CTX,
) -> libc::c_int {
    let this = unsafe {
        let cert_store = X509_STORE_CTX_get0_store(ctx);
        X509_STORE_get_ex_data(cert_store, OPENSSL_EX_DATA_IDX.lock().unwrap().get())
    };
    let cert = unsafe { X509_STORE_CTX_get_current_cert(ctx) };
    if this.is_null() {
        log::error!("failed to get tls_wrapper_ctx pointer\n");
        return 0;
    }
    if preverify_ok == 0 {
        let err = unsafe { X509_STORE_CTX_get_error(ctx) };
        if err == 18 {
            return 1;
        }
        log::error!("Failed on pre-verification due to {}\n", err);
        if err == 9 {
            log::error!(
                "Please ensure check the time-keeping is consistent between client and server\n"
            );
        }
        return 0;
    }
    let pubkey = unsafe { X509_get_pubkey(cert) };
    if pubkey.is_null() {
        log::error!("Unable to decode the public key from certificate\n");
        return TlsErr::INVALID.bits();
    }
    let pubkey_buffer_size = unsafe { i2d_PUBKEY(pubkey, ptr::null_mut()) };
    let mut pubkey_buffer = vec![0u8; pubkey_buffer_size as usize];
    let mut p = pubkey_buffer.as_mut_ptr();
    unsafe {
        i2d_PUBKEY(pubkey, as_raw_mut(&mut p));
        EVP_PKEY_free(pubkey);
    }
    let evidence = find_extension_from_cert(cert, OID_TCG_DICE_TAGGED_EVIDENCE, true);
    if evidence.is_err() {
        return 0;
    }
    let endorsement = find_extension_from_cert(cert, OID_TCG_DICE_ENDORSEMENT_MANIFEST, true);
    if endorsement.is_err() {
        return 0;
    }
    unsafe {
        (*(this as *mut T)).verify_certificate_extension(
            pubkey_buffer,
            evidence.unwrap(),
            endorsement.unwrap(),
        );
    }
    1
}

fn find_extension_from_cert(
    cert: *mut X509,
    oid: ObjectIdentifier,
    optional: bool,
) -> Result<Vec<u8>> {
    let extensions = unsafe {
        let ptr = X509_get0_extensions(cert);
        if ptr.is_null() {
            return Err(Error::kind(ErrorKind::OsslGetExtensionFail));
        }
        ptr
    };
    let extensions_num = unsafe { OPENSSL_sk_num(extensions as *const OPENSSL_STACK) };
    for i in 0..extensions_num {
        let mut oid_buf = [0 as libc::c_char; 128];
        unsafe {
            let ext = OPENSSL_sk_value(extensions as *const OPENSSL_STACK, i) as _;
            let obj = X509_EXTENSION_get_object(ext);
            OBJ_obj2txt(oid_buf.as_mut_ptr(), 128, obj, 1);
            let cur_oid =
                ObjectIdentifier::try_from(&*(oid_buf.as_ref() as *const _ as *const [u8]))
                    .map_err(|_| Error::kind(ErrorKind::OsslOIDErr))?;
            if cur_oid == oid {
                let str = X509_EXTENSION_get_data(ext);
                let res = slice::from_raw_parts_mut((*str).data, (*str).length as usize);
                return Ok(res.into());
            }
        }
    }
    if optional {
        Ok(vec![])
    } else {
        Err(Error::kind(ErrorKind::OsslFindX509ExFail))
    }
}

