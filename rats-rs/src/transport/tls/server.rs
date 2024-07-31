use super::{
    as_raw, as_raw_mut, ossl_init, EpvPkey, GetFd, SslMode, TcpWrapper, TlsFlags, VerifyCertExtension, OPENSSL_EX_DATA_IDX
};
use crate::cert::dice::cbor::parse_evidence_buffer_with_tag;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::{AutoAttester, GenericVerifier};
use crate::transport::{GenericSecureTransPortRead, GenericSecureTransPortWrite};
use crate::{crypto::AsymmetricPrivateKey, transport::GenericSecureTransPort};
use lazy_static::lazy_static;
use maybe_async::maybe_async;
use openssl_sys::*;
use pkcs8::EncodePrivateKey;
use std::cell::Cell;
use std::ffi::c_int;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::{Arc, Mutex};

//TODO: use typestate only impl `VerifyCertExtension` if needed
struct Server {
    ctx: Option<*mut SSL_CTX>,
    ssl_session: Option<*mut SSL>,
    conf_flag: TlsFlags,
    verify: SSL_verify_cb,
    stream: Box<dyn GetFd>,
}

impl VerifyCertExtension for Server {
    fn verify_certificate_extension(
        &mut self,
        pubkey: Vec<u8>,
        evidence: Vec<u8>,
        endorsement: Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }
}

// TODO: use typestate design pattern?
struct TlsServerBuilder {
    verify: SSL_verify_cb,
    conf_flag: Option<TlsFlags>,
    stream: Box<dyn GetFd>,
}

impl TlsServerBuilder {
    fn build(self) -> Result<Server> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify: self.verify,
            conf_flag: self.conf_flag.unwrap_or_default(),
            stream: self.stream,
        };
        s.init()?;
        Ok(s)
    }
    fn with_verify(mut self, verify: SSL_verify_cb) -> Self {
        self.verify = verify;
        self
    }
    fn with_conf_flag(mut self, conf_flag: TlsFlags) -> Self {
        self.conf_flag = Some(conf_flag);
        self
    }
    fn with_tcp_stream<A: ToSocketAddrs>(mut self, addr: A) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .map_err(|err| Error::kind(ErrorKind::OsslClientConnectFail))?;
        self.stream = Box::new(TcpWrapper(stream));
        Ok(self)
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for Server {
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
impl GenericSecureTransPortRead for Server {
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
impl GenericSecureTransPort for Server {
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
        let session = unsafe {
            let session = SSL_new(ctx);
            if session.is_null() {
                return Err(Error::kind(ErrorKind::OsslNoMem));
            }
            session
        };
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
            err = SSL_accept(session);
        }
        if err != 1 {
            return Err(Error::kind(ErrorKind::OsslServerNegotiationFail));
        }
        self.ssl_session = Some(session);
        Ok(())
    }
}

impl Server {
    pub fn init(&mut self) -> Result<()> {
        ossl_init()?;
        let ctx = unsafe { SSL_CTX_new(TLS_server_method()) };
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
                pkey = key.to_pkcs8_der()?;
                epkey = EpvPkey::RSA.bits();
            }
            AsymmetricPrivateKey::P256(key) => {
                pkey = key.to_pkcs8_der()?;
                epkey = EpvPkey::EC.bits();
            }
            _ => return Err(Error::kind(ErrorKind::OsslUnsupportedPkeyAlgo)),
        }
        let ctx = self
            .ctx
            .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?;
        let pkey_len = pkey.as_bytes().len() as ::libc::c_long;
        let pkey_buffer = as_raw(&pkey.as_bytes()[0]);
        unsafe {
            let res = SSL_CTX_use_PrivateKey_ASN1(epkey, ctx, pkey_buffer, pkey_len);
            if res != 1 {
                return Err(Error::kind(ErrorKind::OsslUsePrivKeyfail));
            }
        }
        Ok(())
    }

    pub fn use_cert(&mut self, cert: &Vec<u8>) -> Result<()> {
        let ctx = self
            .ctx
            .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?;
        let ptr = cert.as_ptr();
        let len = cert.len();
        let res = unsafe {
            SSL_CTX_use_certificate_ASN1(
                ctx,
                len as ::libc::c_int,
                ptr as usize as *const ::libc::c_uchar,
            )
        };
        if res != 1 {
            return Err(Error::kind(ErrorKind::OsslUseCertfail));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Server;
    use crate::{
        cert::create::{CertBuilder, CertBundle},
        crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
        errors::*,
        tee::AutoAttester,
        transport::{
            tls::{as_raw_mut, GetFdDumpImpl, TlsFlags},
            GenericSecureTransPortWrite,
        },
    };
    use core::slice;
    use openssl_sys::*;
    use std::ptr;

    #[test]
    fn test_server_init() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify: None,
            conf_flag: TlsFlags::default(),
            stream: Box::new(GetFdDumpImpl),
        };
        s.init()?;
        Ok(())
    }
    #[test]
    fn test_server_shutdown() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify: None,
            conf_flag: TlsFlags::default(),
            stream: Box::new(GetFdDumpImpl),
        };
        s.init()?;
        s.shutdown()?;
        Ok(())
    }

    fn ossl_get_privkey(s: &mut Server) -> Vec<u8> {
        let ssl_session = unsafe { SSL_new(s.ctx.unwrap()) };
        let pkey = unsafe { SSL_get_privatekey(ssl_session) };
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        let res = unsafe {
            PEM_write_bio_PrivateKey(
                bio,
                pkey,
                ptr::null(),
                ptr::null_mut(),
                0,
                None,
                ptr::null_mut(),
            )
        };
        assert_ne!(res, 0);
        let mut pem_data = ptr::null_mut::<i8>();
        let pem_size = unsafe { BIO_get_mem_data(bio, as_raw_mut(&mut pem_data)) };
        let now =
            unsafe { slice::from_raw_parts(pem_data as *const u8, pem_size as usize).to_vec() };
        unsafe {
            SSL_shutdown(ssl_session);
            SSL_free(ssl_session);
        }
        now
    }

    #[test]
    fn test_server_use_key() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify: None,
            conf_flag: TlsFlags::default(),
            stream: Box::new(GetFdDumpImpl),
        };
        s.init()?;
        let privkey = DefaultCrypto::gen_private_key(AsymmetricAlgo::Rsa2048)?;
        let binding = privkey.to_pkcs8_pem()?;
        let privpem = binding.as_bytes();
        s.use_privkey(privkey)?;
        let now = ossl_get_privkey(&mut s);
        assert_eq!(privpem, now.as_slice());
        s.shutdown()?;
        Ok(())
    }

    #[test]
    fn test_server_use_cert() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify: None,
            conf_flag: TlsFlags::default(),
            stream: Box::new(GetFdDumpImpl),
        };
        s.init()?;
        let privkey = DefaultCrypto::gen_private_key(AsymmetricAlgo::Rsa2048)?;
        let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
            .build_with_private_key(&privkey)?
            .cert_to_der()?;
        s.use_cert(&cert)?;
        let raw_cert = unsafe { SSL_CTX_get0_certificate(s.ctx.unwrap()) };
        let mut raw_ptr = ptr::null_mut::<u8>();
        let len = unsafe { i2d_X509(raw_cert, &mut raw_ptr as *mut *mut u8) };
        let now = unsafe { slice::from_raw_parts(raw_ptr as *const u8, len as usize).to_vec() };
        assert_eq!(cert, now);
        s.shutdown()?;
        Ok(())
    }
}
