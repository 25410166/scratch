use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::auth::types::{LeasePayload, APP_SLUG, DESKTOP_LEASE_PUBLIC_KEY_BASE64};

#[derive(Debug, PartialEq, Eq)]
pub enum LeaseStatus {
    Valid(LeasePayload),
    InGracePeriod(LeasePayload),
    Expired,
    InvalidSignature,
    EntitlementDenied,
}

/// Verify an offline Ed25519 signed lease token
pub fn verify_offline_lease(lease_token: &str, device_id: &str) -> LeaseStatus {
    // Expected format: header.payload.signature (3 parts)
    let parts: Vec<&str> = lease_token.split('.').collect();
    if parts.len() != 3 {
        return LeaseStatus::InvalidSignature;
    }

    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    // Decode signature
    let sig_bytes = match STANDARD.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return LeaseStatus::InvalidSignature,
    };

    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return LeaseStatus::InvalidSignature,
    };

    // Decode public key
    let pubkey_bytes = match STANDARD.decode(DESKTOP_LEASE_PUBLIC_KEY_BASE64) {
        Ok(b) => b,
        Err(_) => return LeaseStatus::InvalidSignature,
    };

    // Public key may be raw 32 bytes or DER SPKI
    let key_bytes: [u8; 32] = if pubkey_bytes.len() == 32 {
        pubkey_bytes.try_into().unwrap()
    } else if pubkey_bytes.len() > 32 {
        let len = pubkey_bytes.len();
        pubkey_bytes[len - 32..].try_into().unwrap()
    } else {
        return LeaseStatus::InvalidSignature;
    };

    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(k) => k,
        Err(_) => return LeaseStatus::InvalidSignature,
    };

    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
    let signed_content = format!("{}.{}", parts[0], parts[1]);

    if verifying_key.verify(signed_content.as_bytes(), &signature).is_err() {
        return LeaseStatus::InvalidSignature;
    }

    // Decode payload
    let payload_json = match STANDARD.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => return LeaseStatus::InvalidSignature,
    };

    let payload: LeasePayload = match serde_json::from_slice(&payload_json) {
        Ok(p) => p,
        Err(_) => return LeaseStatus::InvalidSignature,
    };

    // Verify entitlement fields
    if !payload.entitlement_allowed {
        return LeaseStatus::EntitlementDenied;
    }

    if !payload.app_entitlements.contains(&APP_SLUG.to_string()) {
        return LeaseStatus::EntitlementDenied;
    }

    if payload.device_id != device_id {
        return LeaseStatus::EntitlementDenied;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now < payload.expires_at {
        LeaseStatus::Valid(payload)
    } else if now < payload.grace_until {
        LeaseStatus::InGracePeriod(payload)
    } else {
        LeaseStatus::Expired
    }
}
