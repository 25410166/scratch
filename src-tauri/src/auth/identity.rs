use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
use rand::rngs::OsRng;
use std::fmt;

pub struct DeviceIdentity {
    pub device_key: String,
    pub signing_key: SigningKey,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_key", &self.device_key)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl DeviceIdentity {
    /// Generate a brand new device identity
    pub fn generate() -> Self {
        let device_key = format!("catnotes-{}", uuid::Uuid::new_v4());
        let signing_key = SigningKey::generate(&mut OsRng);

        Self {
            device_key,
            signing_key,
        }
    }

    /// Load identity from saved bytes or generate if missing
    pub fn from_raw_bytes(device_key: String, private_key_bytes: &[u8]) -> Result<Self, String> {
        let key_bytes: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| "Invalid private key byte length for Ed25519".to_string())?;

        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(Self {
            device_key,
            signing_key,
        })
    }

    /// Get Ed25519 public key in Base64 DER SPKI format for API POST /auth/start
    pub fn public_key_spki_base64(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        match verifying_key.to_public_key_der() {
            Ok(der) => STANDARD.encode(der.as_bytes()),
            Err(_) => {
                // Fallback raw 32-byte public key base64 if SPKI conversion fails
                STANDARD.encode(verifying_key.as_bytes())
            }
        }
    }

    /// Export raw private key bytes (32 bytes) for secure storage
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}
