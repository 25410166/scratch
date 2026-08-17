use reqwest::Client;
use std::time::Duration;
use crate::auth::identity::DeviceIdentity;
use crate::auth::session::sign_session_request;
use crate::auth::types::{
    ApiErrorResponse, ExchangeRequest, ExchangeResponse, SessionResponse, StartAuthRequest,
    StartAuthResponse, APP_SLUG, DEFAULT_API_BASE_URL,
};

pub struct CookAppsApiClient {
    client: Client,
    base_url: String,
}

impl CookAppsApiClient {
    pub fn new(base_url: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());

        let base_url = base_url
            .or_else(|| std::env::var("COOKAPPS_BASE_URL").ok())
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string());

        Self { client, base_url }
    }

    /// Step 1: Start Desktop Login
    pub async fn start_login(
        &self,
        identity: &DeviceIdentity,
        state: &str,
        code_challenge: &str,
    ) -> Result<StartAuthResponse, String> {
        let platform = if cfg!(target_os = "macos") {
            "macOS"
        } else {
            "Windows"
        };

        let request_body = StartAuthRequest {
            app_slug: APP_SLUG.to_string(),
            device_key: identity.device_key.clone(),
            device_name: format!("User {}", platform),
            platform: platform.to_string(),
            state: state.to_string(),
            code_challenge: code_challenge.to_string(),
            public_key_ed25519: identity.public_key_spki_base64(),
        };

        let url = format!("{}/api/desktop/auth/start", self.base_url);
        let res = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-store")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| map_network_error(&e.to_string()))?;

        if !res.status().is_success() {
            let error_text = res.text().await.unwrap_or_default();
            return Err(map_api_error_text(&error_text));
        }

        res.json::<StartAuthResponse>()
            .await
            .map_err(|e| format!("Failed to parse login start response: {}", e))
    }

    /// Step 4: Exchange Login Code
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        device_key: &str,
    ) -> Result<ExchangeResponse, String> {
        let request_body = ExchangeRequest {
            code: code.to_string(),
            code_verifier: code_verifier.to_string(),
            device_key: device_key.to_string(),
        };

        let url = format!("{}/api/desktop/auth/exchange", self.base_url);
        let res = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-store")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| map_network_error(&e.to_string()))?;

        if !res.status().is_success() {
            let error_text = res.text().await.unwrap_or_default();
            return Err(map_api_error_text(&error_text));
        }

        res.json::<ExchangeResponse>()
            .await
            .map_err(|e| format!("Failed to parse exchange response: {}", e))
    }

    /// Step 5: Check Desktop Session
    pub async fn check_session(
        &self,
        identity: &DeviceIdentity,
        access_token: &str,
    ) -> Result<SessionResponse, String> {
        let headers = sign_session_request(identity);
        let url = format!("{}/api/desktop/session?appSlug={}", self.base_url, APP_SLUG);

        let res = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("X-CookApps-Device-Key", &headers.device_key)
            .header("X-CookApps-Timestamp", headers.timestamp.to_string())
            .header("X-CookApps-Nonce", &headers.nonce)
            .header("X-CookApps-Signature", &headers.signature_base64url)
            .header("Cache-Control", "no-store")
            .send()
            .await
            .map_err(|e| map_network_error(&e.to_string()))?;

        if !res.status().is_success() {
            let error_text = res.text().await.unwrap_or_default();
            return Err(map_api_error_text(&error_text));
        }

        res.json::<SessionResponse>()
            .await
            .map_err(|e| format!("Failed to parse session response: {}", e))
    }
}

/// Map server error codes to human-readable user messages
pub fn map_api_error_text(error_json: &str) -> String {
    let parsed: Option<ApiErrorResponse> = serde_json::from_str(error_json).ok();
    let code = parsed
        .as_ref()
        .and_then(|p| p.error.as_deref().or(p.message.as_deref()))
        .unwrap_or(error_json);

    match code {
        "APP_NOT_AVAILABLE" => "App is unavailable. Contact support.".to_string(),
        "UPGRADE_REQUIRED" => "Personal plan is required to use CatNotes.".to_string(),
        "DEVICE_LIMIT_REACHED" => {
            "Device limit reached. Replace an existing device on CookApps website.".to_string()
        }
        "REPLACEMENT_DEVICE_UNAVAILABLE" => {
            "Selected device is no longer available. Refresh device list.".to_string()
        }
        "IP_REAUTH_REQUIRED" => "Network changed. Sign in again through CookApps website.".to_string(),
        "DEVICE_REVOKED" => "This device was revoked. Sign in again.".to_string(),
        "INVALID_EXCHANGE_CODE" => "Login code expired or was already used.".to_string(),
        "EXCHANGE_ALREADY_CONSUMED" => "Login request was already completed.".to_string(),
        "PKCE_VERIFICATION_FAILED" => "Secure login verification failed.".to_string(),
        "DEVICE_BINDING_MISMATCH" => "Login belongs to another device.".to_string(),
        "DEVICE_PROOF_REQUIRED" => "Secure device verification is required.".to_string(),
        "DEVICE_PROOF_INVALID" => "Device verification failed.".to_string(),
        "DESKTOP_TOKEN_REQUIRED" => "Desktop session is missing. Sign in again.".to_string(),
        "INVALID_DESKTOP_TOKEN" => "Desktop session expired. Sign in again.".to_string(),
        "USER_DISABLED" => "Account is inactive. Contact support.".to_string(),
        other => {
            if let Some(msg) = parsed.as_ref().and_then(|p| p.message.clone()) {
                msg
            } else {
                format!("CookApps Auth error: {}", other)
            }
        }
    }
}

fn map_network_error(err: &str) -> String {
    format!("Cannot connect to CookApps. Retry later. ({})", err)
}
