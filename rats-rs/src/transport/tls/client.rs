use crate::transport::GenericSecureTransPort;
use openssl_sys::{SSL_CTX, SSL};
use maybe_async::maybe_async;
use crate::errors::*;

struct Client {
    ctx: Option<SSL_CTX>,
}

struct TlsClientBuilder {
}

impl TlsClientBuilder {
    fn build() -> Client {
        let mut c = Client{ ctx: None };
        c.init();
        c
    }
}

#[maybe_async]
impl GenericSecureTransPort for Client {
    async fn negotiate(&mut self) -> Result<()> {
        todo!()
    }
}

impl Client {
    pub fn init(&mut self) {
        todo!()
    }
}

#[cfg(test)]
mod tests{
    use crate::errors::*;
    use super::*;
    
    #[test]
    pub fn test_build_client() -> Result<()> {
        let c = TlsClientBuilder::build();
        println!("build client complete");
        Ok(())
    }
}
