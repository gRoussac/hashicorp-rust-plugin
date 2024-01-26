use derp::Der;
use ed25519_dalek::{
    SignatureError, SigningKey as Ed25519SecretKey, SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH,
};
use pem::Pem;
use std::{
    ffi::{CStr, CString},
    fmt::{self, Debug, Display, Formatter},
};

mod ffi {
    #[allow(dead_code)]
    extern "C" {
        pub fn plugin_init(request: *const u8, response: *mut u8) -> i32;
    }
}

#[no_mangle]
pub extern "C" fn plugin_init(request: *const u8, response: *mut u8) -> i32 {
    let request_cstr = unsafe { CStr::from_ptr(request as *const i8) };
    let _request_str = request_cstr.to_str().unwrap_or_default();

    let key = SecretKey::generate_ed25519().unwrap();
    let key = key.to_pem().unwrap();

    let cleaned_key = key
        .replace("-----BEGIN PRIVATE KEY-----\r\n", "")
        .replace("\r\n-----END PRIVATE KEY-----\r\n", "");

    let response_str = cleaned_key.to_string();

    let response_cstr = CString::new(response_str).expect("CString::new failed");

    unsafe {
        libc::strcpy(response as *mut i8, response_cstr.as_ptr());
    }

    0
}

pub const SECRET_KEY_LENGTH: usize = 32;
const ED25519_PEM_SECRET_KEY_TAG: &str = "PRIVATE KEY";
const ED25519_OBJECT_IDENTIFIER: [u8; 3] = [43, 101, 112];

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    AsymmetricKey(String),
    FromHex(base16::DecodeError),
    FromBase64(base64::DecodeError),
    SignatureError,
    System(String),
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}

impl From<base16::DecodeError> for Error {
    fn from(error: base16::DecodeError) -> Self {
        Error::FromHex(error)
    }
}

impl From<SignatureError> for Error {
    fn from(_error: SignatureError) -> Self {
        Error::SignatureError
    }
}

#[derive(Debug)]
pub enum SecretKey {
    Ed25519(Ed25519SecretKey),
}

impl SecretKey {
    /// The length in bytes of a system secret key.
    pub const SYSTEM_LENGTH: usize = 0;

    /// The length in bytes of an Ed25519 secret key.
    pub const ED25519_LENGTH: usize = ED25519_SECRET_KEY_LENGTH;

    /// Constructs a new ed25519 variant from a byte slice.
    pub fn ed25519_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Error> {
        Ok(SecretKey::Ed25519(Ed25519SecretKey::try_from(
            bytes.as_ref(),
        )?))
    }

    pub fn generate_ed25519() -> Result<Self, Error> {
        let mut bytes = [0u8; Self::ED25519_LENGTH];
        let _ = getrandom::getrandom(&mut bytes[..]);
        SecretKey::ed25519_from_bytes(bytes)
    }

    /// PEM encodes a key.
    pub fn to_pem(&self) -> Result<String, Error> {
        let tag = match self {
            SecretKey::Ed25519(_) => ED25519_PEM_SECRET_KEY_TAG.to_string(),
        };
        let contents = self.to_der()?;
        let pem = Pem { tag, contents };
        Ok(pem::encode(&pem))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        match self {
            SecretKey::Ed25519(secret_key) => {
                // See https://tools.ietf.org/html/rfc8410#section-10.3
                let mut key_bytes = vec![];
                let mut der = Der::new(&mut key_bytes);
                der.octet_string(&secret_key.to_bytes()).unwrap();

                let mut encoded = vec![];
                der = Der::new(&mut encoded);
                der.sequence(|der| {
                    der.integer(&[0])?;
                    der.sequence(|der| der.oid(&ED25519_OBJECT_IDENTIFIER))?;
                    der.octet_string(&key_bytes)
                })
                .unwrap();
                Ok(encoded)
            }
        }
    }
}
