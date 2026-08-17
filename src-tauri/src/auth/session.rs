use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signer;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::auth::identity::DeviceIdentity;
use crate::auth::pkce::generate_state;

pub struct SignedSessionHeaders {
    pub timestamp: u64,
    pub nonce: String,
    pub signature_base64url: String,
    pub device_key: String,
}

/// Sign a desktop session check request:
/// Message format must be exactly:
/// GET
/// /api/desktop/session?appSlug=catnotes
/// {timestamp}
/// {nonce}
pub fn sign_session_request(identity: &DeviceIdentity) -> SignedSessionHeaders {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let nonce = generate_state();

    let message = format!(
        "GET\n/api/desktop/session?appSlug=catnotes\n{}\n{}",
        timestamp, nonce
    );

    let signature = identity.signing_key.sign(message.as_bytes());
    let signature_base64url = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    SignedSessionHeaders {
        timestamp,
        nonce,
        signature_base64url,
        device_key: identity.device_key.clone(),
    }
}
