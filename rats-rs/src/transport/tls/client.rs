use crate::cert::dice::cbor::parse_evidence_buffer_with_tag;
use crate::cert::dice::cbor::OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE;
use crate::crypto::DefaultCrypto;
use crate::crypto::HashAlgo;
use crate::tee::sgx_dcap::evidence;
use crate::tee::AutoEvidence;
use crate::transport::GenericSecureTransPortRead;
use crate::transport::GenericSecureTransPortWrite;
use std::cell::Cell;
use std::ffi::c_int;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::Arc;
use std::sync::Mutex;

use crate::errors::*;
use crate::tee::{AutoVerifier, GenericEvidence, GenericVerifier};
use crate::{crypto::AsymmetricPrivateKey, transport::GenericSecureTransPort};
use maybe_async::maybe_async;
use openssl_sys::*;
use pkcs8::EncodePrivateKey;

use super::ossl_init;
use super::GetFd;
use super::GetFdDumpImpl;
use super::SslMode;
use super::TcpWrapper;
use super::TlsFlags;
use super::OPENSSL_EX_DATA_IDX;
use super::{as_raw, as_raw_mut, VerifyCertExtension};
use lazy_static::lazy_static;

#[allow(dead_code)]
struct Client {
    ctx: Option<*mut SSL_CTX>,
    ssl_session: Option<*mut SSL>,
    verifier: AutoVerifier,
    verify: SSL_verify_cb,
    conf_flag: TlsFlags,
    stream: Box<dyn GetFd>,
}

#[allow(dead_code)]
struct TlsClientBuilder {
    verify: SSL_verify_cb,
    stream: Box<dyn GetFd>,
}

#[allow(dead_code)]
impl TlsClientBuilder{
    fn build(self) -> Result<Client> {
        let mut c = Client {
            ctx: None,
            ssl_session: None,
            verifier: AutoVerifier::new(),
            verify: self.verify,
            conf_flag: TlsFlags::default(),
            stream: self.stream,
        };
        c.init()?;
        Ok(c)
    }
    fn with_verify(mut self, verify: SSL_verify_cb) -> Self {
        self.verify = verify;
        self
    }
    fn with_tcp_stream<A: ToSocketAddrs>(mut self, addr: A) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .map_err(|err| Error::kind(ErrorKind::OsslClientConnectFail))?;
        self.stream = Box::new(TcpWrapper(stream));
        Ok(self)
    }
    fn new() -> Self {
        Self {
            verify: None,
            stream: Box::new(GetFdDumpImpl{}),
        }
    }
}

#[allow(dead_code)]
impl VerifyCertExtension for Client {
    fn verify_certificate_extension(
        &mut self,
        pubkey: Vec<u8>,
        evidence: Vec<u8>,
        endorsement: Vec<u8>,
    ) -> Result<()> {
        let (tag, raw_evidence, claims_buffer) = parse_evidence_buffer_with_tag(evidence.as_ref())?;
        if !endorsement.is_empty() {
            //TODO: parse endorsement
        }
        let claims_buffer_hash;
        if !claims_buffer.is_empty() {
            claims_buffer_hash = DefaultCrypto::hash(HashAlgo::Sha256, claims_buffer.as_ref());
        } else {
            claims_buffer_hash = vec![];
        }
        let e = AutoEvidence::create_evidence_from_dice(
            OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE,
            evidence.as_ref(),
        )?;
        self.verifier.verify_evidence(&e, vec![].as_ref())?;
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for Client {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if self.ctx.is_none() || self.ssl_session.is_none() {
            return Err(Error::kind(ErrorKind::OsslCtxOrSessionUninitialized));
        }
        let res = unsafe {
            SSL_write(
                self.ssl_session.unwrap(),
                bytes.as_ptr() as *const libc::c_void,
                bytes.len() as i32,
            )
        };
        if res < 0 {
            return Err(Error::kind(ErrorKind::OsslSendFail));
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        if let Some(ssl_session) = self.ssl_session {
            unsafe {
                SSL_shutdown(ssl_session);
                SSL_free(ssl_session);
            }
        }
        if let Some(ctx) = self.ctx {
            unsafe {
                SSL_CTX_free(ctx);
            }
        }
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortRead for Client {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.ctx.is_none() || self.ssl_session.is_none() {
            return Err(Error::kind(ErrorKind::OsslCtxOrSessionUninitialized));
        }
        let res = unsafe {
            SSL_read(
                self.ssl_session.unwrap(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as i32,
            )
        };
        if res < 0 {
            return Err(Error::kind(ErrorKind::OsslReceiveFail));
        }
        Ok(res as usize)
    }
}

#[maybe_async]
impl GenericSecureTransPort for Client {
    async fn negotiate(&mut self) -> Result<()> {
        let ctx = as_raw_mut(
            self.ctx
                .as_mut()
                .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?,
        );
        unsafe {
            if self.verify.is_some() {
                let mut mode = SslMode::SSL_VERIFY_NONE;
                if self.conf_flag.contains(TlsFlags::MUTAL) {
                    mode |= SslMode::SSL_VERIFY_PEER | SslMode::SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                }
                SSL_CTX_set_verify(ctx, mode.bits(), self.verify);
            }
        }
        let session;
        unsafe {
            session = SSL_new(ctx);
            if session.is_null() {
                return Err(Error::kind(ErrorKind::OsslNoMem));
            }
        }
        unsafe {
            let cert_store = SSL_CTX_get_cert_store(self.ctx.unwrap());
            X509_STORE_set_ex_data(
                cert_store,
                OPENSSL_EX_DATA_IDX.lock().unwrap().get(),
                as_raw_mut(self),
            );
            let res = SSL_set_fd(session, self.stream.get_fd());
            if res != 1 {
                return Err(Error::kind(ErrorKind::OsslSetFdFail));
            }
        }
        let err;
        unsafe {
            err = SSL_connect(session);
        }
        if err != 1 {
            return Err(Error::kind(ErrorKind::OsslServerNegotiationFail));
        }
        self.ssl_session = Some(session);
        Ok(())
    }
}

impl Client {
    pub fn init(&mut self) -> Result<()> {
        ossl_init()?;
        let ctx = unsafe { openssl_sys::SSL_CTX_new(openssl_sys::TLS_server_method()) };
        if ctx.is_null() {
            return Err(Error::kind(ErrorKind::OsslCtxInitializeFail));
        }
        self.ctx = Some(ctx);
        Ok(())
    }
    pub fn use_privkey(&mut self, privkey: AsymmetricPrivateKey) -> Result<()> {
        let pkey;
        let epkey: ::libc::c_int;
        match privkey {
            AsymmetricPrivateKey::Rsa2048(key)
            | AsymmetricPrivateKey::Rsa3072(key)
            | AsymmetricPrivateKey::Rsa4096(key) => {
                pkey = key.to_pkcs8_der().map_err(|_e| Error::unknown())?;
                epkey = 19;
            }
            _ => return Err(Error::kind(ErrorKind::OsslUnsupportedPkeyAlgo)),
        }
        let ctx = as_raw_mut(
            self.ctx
                .as_mut()
                .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?,
        );
        let pkey_len = pkey.as_bytes().len() as ::libc::c_long;
        let pkey_buffer = as_raw(&pkey.as_bytes()[0]);
        unsafe {
            let res = openssl_sys::SSL_CTX_use_PrivateKey_ASN1(epkey, ctx, pkey_buffer, pkey_len);
            if res != 1 {
                return Err(Error::kind(ErrorKind::OsslUsePrivKeyfail));
            }
        }
        Ok(())
    }
    pub fn use_cert(&mut self, cert: Vec<u8>) -> Result<()> {
        let ctx = as_raw_mut(
            self.ctx
                .as_mut()
                .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?,
        );
        unsafe {
            let ptr = cert.as_ptr();
            let len = cert.len();
            let res = openssl_sys::SSL_CTX_use_certificate_ASN1(
                ctx,
                len as ::libc::c_int,
                ptr as usize as *const ::libc::c_uchar,
            );
            if res != 1 {
                return Err(Error::kind(ErrorKind::OsslUseCertfail));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
