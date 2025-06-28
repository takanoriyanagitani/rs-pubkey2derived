use std::io;

use io::Read;

use hkdf::Hkdf;

use sha2::Digest;
use sha2::Sha256;

use base64::Engine;

pub use x25519_dalek;

use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;
use x25519_dalek::SharedSecret;

use const_oid::db::rfc8410::ID_X_25519;

use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};

use spki::der;

use der::EncodePem;
use der::asn1::BitString;
use der::pem::LineEnding;

use aes_gcm::Aes256Gcm;
use aes_gcm::Key;

pub fn raw2pubkey(raw: [u8; 32]) -> PublicKey {
    raw.into()
}

pub fn reader2pubkey<R>(mut rdr: R) -> Result<PublicKey, io::Error>
where
    R: Read,
{
    let mut buf: [u8; 32] = [0; 32];
    rdr.read_exact(&mut buf)?;
    Ok(raw2pubkey(buf))
}

pub struct Salt {
    pub salt: [u8; 32],
}

impl Default for Salt {
    fn default() -> Self {
        Self {
            salt: rand::random(),
        }
    }
}

impl Salt {
    pub fn raw(&self) -> &[u8] {
        &self.salt
    }

    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.salt)
    }
}

pub struct SharedInfo {
    pub info: Vec<u8>,
}

impl SharedInfo {
    pub fn new(fqdn: &[u8], app_code_name: &[u8], use_case: &[u8]) -> Self {
        let sz: usize = fqdn.len() + app_code_name.len() + use_case.len();
        let mut v: Vec<u8> = Vec::with_capacity(sz);
        v.extend_from_slice(fqdn);
        v.extend_from_slice(app_code_name);
        v.extend_from_slice(use_case);
        Self { info: v }
    }
}

impl SharedInfo {
    pub fn raw(&self) -> &[u8] {
        &self.info
    }
}

pub struct PublicInfo {
    pub salt: Salt,
    pub shared_info: SharedInfo,
}

impl PublicInfo {
    pub fn derive_key(&self, secret: &SharedSecret) -> Result<[u8; 32], io::Error> {
        let mut key: [u8; 32] = [0; 32];
        let hkdf: Hkdf<_> = Hkdf::<Sha256>::new(Some(self.salt.raw()), secret.as_bytes());
        hkdf.expand(self.shared_info.raw(), &mut key)
            .map_err(|_| "unable to derive a key")
            .map_err(io::Error::other)?;
        Ok(key)
    }
}

impl PublicInfo {
    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    pub fn shared_info(&self) -> &SharedInfo {
        &self.shared_info
    }
}

pub struct Combined {
    info: PublicInfo,
    my_pub_key: PublicKey,
    shared_secret: SharedSecret,
}

impl Combined {
    pub fn salt(&self) -> &Salt {
        self.info.salt()
    }

    pub fn salt_base64(&self) -> String {
        self.salt().to_base64()
    }

    pub fn my_public_key(&self) -> &PublicKey {
        &self.my_pub_key
    }

    pub fn my_public_key_raw(&self) -> &[u8; 32] {
        self.my_pub_key.as_bytes()
    }

    pub fn my_public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.my_public_key_raw())
    }

    pub fn derive_key(&self) -> Result<SymmetricKey, io::Error> {
        Ok(SymmetricKey {
            secret: self.info.derive_key(&self.shared_secret)?,
        })
    }
}

impl Combined {
    pub fn my_pub_key_to_spki(&self) -> Result<SubjectPublicKeyInfo<(), BitString>, io::Error> {
        let oid: &str = &format!("{ID_X_25519}");
        let pubkey_bytes: &[u8] = self.my_public_key_raw();
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: ObjectIdentifier::new_unwrap(oid),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(pubkey_bytes)
                .map_err(|e| format!("invalid pubkey bytes: {e}"))
                .map_err(io::Error::other)?,
        })
    }

    pub fn my_pub_key_to_pem(&self) -> Result<String, io::Error> {
        let spki_value: SubjectPublicKeyInfo<_, _> = self.my_pub_key_to_spki()?;
        spki_value
            .to_pem(LineEnding::LF)
            .map_err(|e| format!("unable to convert to pem: {e}"))
            .map_err(io::Error::other)
    }
}

impl Combined {
    pub fn from_public_key(pubkey: &PublicKey, salt: Salt, shared_info: SharedInfo) -> Self {
        let pubinfo: PublicInfo = PublicInfo { salt, shared_info };
        let ephemeral: EphemeralSecret = EphemeralSecret::random();
        let my_pub_key: PublicKey = (&ephemeral).into();
        let secret: SharedSecret = ephemeral.diffie_hellman(pubkey);
        Self {
            info: pubinfo,
            my_pub_key,
            shared_secret: secret,
        }
    }
}

pub struct SymmetricKey {
    secret: [u8; 32],
}

impl SymmetricKey {
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.secret);
        let sum = hasher.finalize();
        hex::encode(sum)
    }

    pub fn to_aes_gcm_key(self) -> Key<Aes256Gcm> {
        self.secret.into()
    }
}
