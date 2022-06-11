#[cfg(target_env = "sgx")]
mod inner {
    use mbedtls::rng::Rdrand;
    pub struct Rng {
        pub inner: Rdrand,
    }

    impl Rng {
        pub fn new() -> Self {
            Self { inner: Rdrand }
        }
    }
}

#[cfg(not(target_env = "sgx"))]
mod inner {
    use mbedtls::rng::OsEntropy;
    use std::sync::Arc;
    use std::pin::Pin;
    pub struct Rng {
        pub inner: mbedtls::rng::CtrDrbg,
        _entropy: Pin<Box<OsEntropy>>,
    }

    impl Rng {
        pub fn new() -> super::super::Result<Self> {
            let entropy = Box::pin(OsEntropy::new());
            /* let entropy_ptr: *mut _ = &mut *entropy; */
            /* let entropy_ptr: Arc<OsEntropy> = Arc::new(*entropy); */
            let entropy_ptr: Arc<OsEntropy> = Arc::new(OsEntropy::new());
            Ok(Self {
                _entropy: entropy,
                inner: mbedtls::rng::CtrDrbg::new(entropy_ptr, None)?,
            })
        }
    }
}

pub use inner::*;
