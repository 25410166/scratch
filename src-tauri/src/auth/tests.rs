#[cfg(test)]
mod tests {
    use crate::auth::api::map_api_error_text;
    use crate::auth::identity::DeviceIdentity;
    use crate::auth::lease::{verify_offline_lease, LeaseStatus};
    use crate::auth::pkce::{constant_time_compare, generate_pkce, generate_state};
    use crate::auth::session::sign_session_request;
    use ed25519_dalek::Verifier;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    #[test]
    fn test_pkce_challenge_generation() {
        let pkce = generate_pkce();
        assert_eq!(pkce.verifier.len(), 43);
        assert!(!pkce.challenge.is_empty());
        assert_ne!(pkce.verifier, pkce.challenge);
    }

    #[test]
    fn test_callback_state_validation() {
        let state1 = generate_state();
        let state2 = generate_state();

        assert!(state1.len() >= 16);
        assert!(state2.len() >= 16);
        assert_ne!(state1, state2);

        // Constant time comparison
        assert!(constant_time_compare(&state1, &state1));
        assert!(!constant_time_compare(&state1, &state2));
        assert!(!constant_time_compare(&state1, "short"));
    }

    #[test]
    fn test_deep_link_parsing() {
        let url_str = "cookapps-catnotes://auth?code=CODE123&state=STATE456";
        let parsed = url::Url::parse(url_str).unwrap();

        assert_eq!(parsed.scheme(), "cookapps-catnotes");
        assert_eq!(parsed.host_str(), Some("auth"));

        let mut code = None;
        let mut state = None;
        for (k, v) in parsed.query_pairs() {
            if k == "code" {
                code = Some(v.into_owned());
            } else if k == "state" {
                state = Some(v.into_owned());
            }
        }

        assert_eq!(code, Some("CODE123".to_string()));
        assert_eq!(state, Some("STATE456".to_string()));
    }

    #[test]
    fn test_ed25519_request_signature() {
        let identity = DeviceIdentity::generate();
        let headers = sign_session_request(&identity);

        assert_eq!(headers.device_key, identity.device_key);
        assert!(headers.timestamp > 0);
        assert!(!headers.nonce.is_empty());
        assert!(!headers.signature_base64url.is_empty());

        // Verify signature format and validity
        let expected_message = format!(
            "GET\n/api/desktop/session?appSlug=catnotes\n{}\n{}",
            headers.timestamp, headers.nonce
        );

        let sig_bytes = URL_SAFE_NO_PAD.decode(&headers.signature_base64url).unwrap();
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        assert!(identity.signing_key.verifying_key().verify(expected_message.as_bytes(), &signature).is_ok());
    }

    #[test]
    fn test_expired_token_error_mapping() {
        let err_json = r#"{"error": "INVALID_DESKTOP_TOKEN", "message": "Desktop session expired. Sign in again."}"#;
        assert_eq!(
            map_api_error_text(err_json),
            "Desktop session expired. Sign in again."
        );
    }

    #[test]
    fn test_ip_reauth_required_error_mapping() {
        let ip_err = r#"{"error": "IP_REAUTH_REQUIRED"}"#;
        assert_eq!(
            map_api_error_text(ip_err),
            "Network changed. Sign in again through CookApps website."
        );
    }

    #[test]
    fn test_device_limit_reached_error_mapping() {
        let device_limit_err = r#"{"error": "DEVICE_LIMIT_REACHED"}"#;
        assert_eq!(
            map_api_error_text(device_limit_err),
            "Device limit reached. Replace an existing device on CookApps website."
        );
    }

    #[test]
    fn test_upgrade_required_error_mapping() {
        let upgrade_err = r#"{"error": "UPGRADE_REQUIRED"}"#;
        assert_eq!(
            map_api_error_text(upgrade_err),
            "Personal plan is required to use CatNotes."
        );
    }

    #[test]
    fn test_invalid_lease_token() {
        let status = verify_offline_lease("invalid.lease.token", "catnotes-device-1");
        assert_eq!(status, LeaseStatus::InvalidSignature);
    }
}
