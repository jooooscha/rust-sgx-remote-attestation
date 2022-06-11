use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{config::Config, Context, context::HandshakeContext};
use mbedtls::Result;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;

use super::random::Rng;

pub type Callback = Box<dyn FnMut(&mut HandshakeContext, &str) -> Result<()>>;

#[cfg(target_env = "sgx")]
pub mod server {
    use super::*;
    use std::sync::Arc;
    pub fn callback(psk: &[u8]) -> Callback {
        let _psk = psk.to_owned();
        /* Box::new(move |ctx: &mut HandshakeContext, _: &str| ctx.set_psk(psk.as_ref())) */
        Box::new(move |_ctx: &mut HandshakeContext, _ : &str| Ok(()))
    }

    pub fn config(rng: Rng, _callback: &mut Callback) -> Config {
        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
        let arc = Arc::new(rng.inner);
        /* config.set_rng(Some(&mut rng.inner)); */
        config.set_rng(arc);
        /* config.set_psk_callback(callback); */
        config
    }

    pub fn context(config: Config) -> Result<Context> {
        let arc = Arc::new(config);
        Ok(Context::new(arc))
    }

    pub struct ServerTlsPskContext {
        inner: Context,
        _config: Pin<Box<Config>>,
        _callback: Pin<Box<Callback>>,
        _rng: Pin<Box<Rng>>,
        _psk: Pin<Box<[u8; 16]>>,
    }

    impl ServerTlsPskContext {
        pub fn new(psk: [u8; 16]) -> Self {
            let rng = Rng::new();
            let mut callback = callback(&psk);
            let conf = config(rng, &mut callback);
            let context = context(conf).unwrap();

            // because config is not clone
            let rng = Rng::new();
            let conf = config(rng, &mut callback);
            let rng = Rng::new();

            Self {
                inner: context,
                _config: Box::pin(conf),
                _callback: Box::pin(callback),
                _rng: Box::pin(rng),
                _psk: Box::pin(psk),
            }
        }
    }

    impl<'a> Deref for ServerTlsPskContext {
        type Target = Context;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<'a> DerefMut for ServerTlsPskContext {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }
}

#[cfg(not(target_env = "sgx"))]
pub mod client {
    use super::*;
    use std::sync::Arc;

    pub fn config<'a: 'c, 'b: 'c, 'c>(rng: Rng, _psk: &'b [u8]) -> Result<Config> {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        let inner_arc = Arc::new(rng.inner);
        config.set_rng(inner_arc);
        /* config.set_psk(psk, "Client_identity")?; */
        Ok(config)
    }

    pub fn context<'a>(config: Config) -> Result<Context> {
        let arc = Arc::new(config);
        Ok(Context::new(arc))
    }

    pub struct ClientTlsPskContext {
        inner: Context,
        _config: Pin<Box<Config>>,
        _rng: Pin<Box<Rng>>,
        _psk: Pin<Box<[u8; 16]>>,
    }

    impl<'a> ClientTlsPskContext {
        pub fn new<'b: 'a>(psk: [u8; 16]) -> Self {
            /* let mut rng = Box::pin(Rng::new().unwrap()); */
            /* let psk = Box::pin(psk); */
            /* let psk_ptr: *const _ = &*psk; */
            /* let rng_ptr: *mut _ = &mut *rng; */
            /* let config = Box::pin(config(rng, &*psk_ptr).unwrap()); */
            /* let config_ptr: *const _ = &*config; */
            let rng = Rng::new().unwrap();
            let conf = config(rng, &psk).unwrap();
            let context = context(conf).unwrap();
            // because Config is not clone
            let rng = Rng::new().unwrap();
            let conf = config(rng, &psk).unwrap();
            let rng = Rng::new().unwrap();
            Self {
                inner: context,
                _config: Box::pin(conf),
                _rng: Box::pin(rng),
                _psk: Box::pin(psk),
            }
        }
    }

    impl Deref for ClientTlsPskContext {
        type Target = Context;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl DerefMut for ClientTlsPskContext {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }
}
