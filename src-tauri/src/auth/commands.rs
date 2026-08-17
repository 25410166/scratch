use std::sync::{Arc, Mutex};
use tauri::{AppHandle, State};
use tauri_plugin_opener::OpenerExt;
use crate::auth::api::CookAppsApiClient;
use crate::auth::identity::DeviceIdentity;
use crate::auth::lease::{verify_offline_lease, LeaseStatus};
use crate::auth::pkce::{constant_time_compare, generate_pkce, generate_state};
use crate::auth::storage::SecureStorage;
use crate::auth::types::{AuthState, AuthStatusCode, StartAuthResponse};

#[derive(Default)]
pub struct PendingAuthSession {
    pub state: Option<String>,
    pub verifier: Option<String>,
}

pub struct AuthManager {
    pub storage: SecureStorage,
    pub api_client: CookAppsApiClient,
    pub pending_session: Mutex<PendingAuthSession>,
}

impl AuthManager {
    pub fn new(app_data_dir: std::path::PathBuf) -> Self {
        Self {
            storage: SecureStorage::new(app_data_dir),
            api_client: CookAppsApiClient::new(None),
            pending_session: Mutex::new(PendingAuthSession::default()),
        }
    }

    /// Load or create installation identity
    pub fn get_or_create_identity(&self) -> DeviceIdentity {
        let data = self.storage.load_auth_data();

        if let (Some(device_key), Some(hex_key)) = (data.device_key.clone(), data.private_key_hex.clone()) {
            if let Ok(raw_bytes) = hex::decode(&hex_key) {
                if let Ok(identity) = DeviceIdentity::from_raw_bytes(device_key, &raw_bytes) {
                    return identity;
                }
            }
        }

        // Identity missing or corrupted -> generate new stable identity
        let new_identity = DeviceIdentity::generate();
        let mut save_data = data;
        save_data.device_key = Some(new_identity.device_key.clone());
        save_data.private_key_hex = Some(hex::encode(new_identity.private_key_bytes()));
        let _ = self.storage.save_auth_data(&save_data);

        new_identity
    }

    /// Determine current application AuthState
    pub async fn evaluate_auth_state(&self) -> AuthState {
        let data = self.storage.load_auth_data();

        // 1. If we have active access token, attempt online session check
        if let Some(ref access_token) = data.access_token {
            let identity = self.get_or_create_identity();

            match self.api_client.check_session(&identity, access_token).await {
                Ok(session) => {
                    // Save refreshed tokens & entitlement
                    let mut updated = data.clone();
                    updated.access_token = Some(session.access_token);
                    updated.lease_token = Some(session.lease_token);
                    updated.lease_expires_at = Some(session.lease_expires_at);
                    updated.lease_grace_until = Some(session.lease_grace_until);
                    updated.user_profile = Some(session.user.clone());
                    updated.entitlement = Some(session.entitlement.clone());
                    let _ = self.storage.save_auth_data(&updated);

                    if !session.entitlement.allowed {
                        let status = if session.entitlement.plan_required.as_deref() == Some("PERSONAL")
                            && session.user.plan_code == "FREE"
                        {
                            AuthStatusCode::UpgradeRequired
                        } else {
                            AuthStatusCode::Error
                        };

                        let reason_msg = session
                            .entitlement
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Personal plan is required to use CatNotes.".to_string());
                        let checkout_url = session.entitlement.checkout_url.clone();

                        return AuthState {
                            status,
                            message: reason_msg,
                            user: Some(session.user),
                            entitlement: Some(session.entitlement),
                            is_offline: false,
                            is_grace_period: false,
                            checkout_url,
                        };
                    }

                    return AuthState {
                        status: AuthStatusCode::Authenticated,
                        message: "Authenticated".to_string(),
                        user: Some(session.user),
                        entitlement: Some(session.entitlement),
                        is_offline: false,
                        is_grace_period: false,
                        checkout_url: None,
                    };
                }
                Err(err_msg) => {
                    // Online check failed (e.g. offline network or IP reauth)
                    if err_msg.contains("IP_REAUTH_REQUIRED") || err_msg.contains("Network changed") {
                        return AuthState {
                            status: AuthStatusCode::IpReauthRequired,
                            message: "Network changed. Sign in again through CookApps website.".to_string(),
                            user: data.user_profile,
                            entitlement: data.entitlement,
                            is_offline: false,
                            is_grace_period: false,
                            checkout_url: None,
                        };
                    }

                    if err_msg.contains("DEVICE_LIMIT_REACHED") {
                        return AuthState {
                            status: AuthStatusCode::DeviceLimitReached,
                            message: "Device limit reached. Replace an existing device on CookApps website.".to_string(),
                            user: data.user_profile,
                            entitlement: data.entitlement,
                            is_offline: false,
                            is_grace_period: false,
                            checkout_url: None,
                        };
                    }
                }
            }
        }

        // 2. Offline lease fallback verification
        if let (Some(ref lease_token), Some(ref user_profile), Some(ref entitlement)) = (
            &data.lease_token,
            &data.user_profile,
            &data.entitlement,
        ) {
            let identity = self.get_or_create_identity();

            match verify_offline_lease(lease_token, &identity.device_key) {
                LeaseStatus::Valid(_) => {
                    return AuthState {
                        status: AuthStatusCode::OfflineActive,
                        message: "Offline access active".to_string(),
                        user: Some(user_profile.clone()),
                        entitlement: Some(entitlement.clone()),
                        is_offline: true,
                        is_grace_period: false,
                        checkout_url: None,
                    };
                }
                LeaseStatus::InGracePeriod(_) => {
                    return AuthState {
                        status: AuthStatusCode::OfflineGrace,
                        message: "Offline grace period active".to_string(),
                        user: Some(user_profile.clone()),
                        entitlement: Some(entitlement.clone()),
                        is_offline: true,
                        is_grace_period: true,
                        checkout_url: None,
                    };
                }
                LeaseStatus::Expired | LeaseStatus::InvalidSignature | LeaseStatus::EntitlementDenied => {}
            }
        }

        // 3. Unauthenticated default
        AuthState {
            status: AuthStatusCode::Unauthenticated,
            message: "Sign in with your CookApps account to use CatNotes.".to_string(),
            user: None,
            entitlement: None,
            is_offline: false,
            is_grace_period: false,
            checkout_url: None,
        }
    }
    /// Execute code exchange with PKCE and state validation
    pub async fn process_deep_link_exchange(
        &self,
        code: &str,
        state: &str,
    ) -> Result<AuthState, String> {
        eprintln!("[exchange] process_deep_link_exchange called, code_len={}, state_prefix={}", code.len(), &state[..state.len().min(8)]);
        let stored_data = self.storage.load_auth_data();
        eprintln!("[exchange] stored pending_state present={}, pending_verifier present={}", stored_data.pending_state.is_some(), stored_data.pending_verifier.is_some());

        let (saved_state, saved_verifier) = {
            let mut session = self.pending_session.lock().map_err(|e| e.to_string())?;
            let mem_state = session.state.take();
            let mem_verifier = session.verifier.take();
            eprintln!("[exchange] mem_state present={}, mem_verifier present={}", mem_state.is_some(), mem_verifier.is_some());
            (
                mem_state.or(stored_data.pending_state),
                mem_verifier.or(stored_data.pending_verifier),
            )
        };

        let saved_state = saved_state.ok_or_else(|| "LOGIN_STATE_MISMATCH: No pending login session".to_string())?;
        let saved_verifier = saved_verifier.ok_or_else(|| "PKCE_VERIFICATION_FAILED: Missing verifier".to_string())?;

        // Clear stored pending state
        let mut save_clean = self.storage.load_auth_data();
        save_clean.pending_state = None;
        save_clean.pending_verifier = None;
        let _ = self.storage.save_auth_data(&save_clean);

        let states_match = constant_time_compare(&saved_state, state);
        eprintln!("[exchange] state comparison: saved_prefix={}, incoming_prefix={}, match={}", &saved_state[..saved_state.len().min(8)], &state[..state.len().min(8)], states_match);
        if !states_match {
            return Err("LOGIN_STATE_MISMATCH: Callback state mismatch".to_string());
        }

        if code.trim().is_empty() {
            return Err("LOGIN_CODE_MISSING: Code parameter is missing".to_string());
        }

        let identity = self.get_or_create_identity();
        eprintln!("[exchange] calling API exchange_code, device_key_prefix={}", &identity.device_key[..identity.device_key.len().min(8)]);
        let exchange = self
            .api_client
            .exchange_code(code, &saved_verifier, &identity.device_key)
            .await?;

        eprintln!("[exchange] exchange_code API success, user={:?}", exchange.user.email);
        let mut data = self.storage.load_auth_data();
        data.device_key = Some(identity.device_key.clone());
        data.private_key_hex = Some(hex::encode(identity.private_key_bytes()));
        data.access_token = Some(exchange.access_token);
        data.lease_token = Some(exchange.lease_token);
        data.lease_expires_at = Some(exchange.lease_expires_at);
        data.lease_grace_until = Some(exchange.lease_grace_until);
        data.user_profile = Some(exchange.user.clone());
        data.entitlement = Some(exchange.entitlement.clone());
        data.pending_state = None;
        data.pending_verifier = None;
        self.storage.save_auth_data(&data)?;

        Ok(self.evaluate_auth_state().await)
    }
}


pub type SharedAuthManager = Arc<AuthManager>;

#[tauri::command]
pub async fn start_cookapps_login(
    app: AppHandle,
    auth_mgr: State<'_, SharedAuthManager>,
) -> Result<StartAuthResponse, String> {
    let identity = auth_mgr.get_or_create_identity();
    let pkce = generate_pkce();
    let state = generate_state();

    // Store pending state & verifier in memory and persistent storage
    {
        let mut session = auth_mgr.pending_session.lock().map_err(|e| e.to_string())?;
        session.state = Some(state.clone());
        session.verifier = Some(pkce.verifier.clone());
    }
    let mut data = auth_mgr.storage.load_auth_data();
    data.pending_state = Some(state.clone());
    data.pending_verifier = Some(pkce.verifier.clone());
    let _ = auth_mgr.storage.save_auth_data(&data);

    let response = auth_mgr
        .api_client
        .start_login(&identity, &state, &pkce.challenge)
        .await?;

    // Open system browser with loginUrl
    let _ = app.opener().open_url(&response.login_url, None::<&str>);

    Ok(response)
}

#[tauri::command]
pub async fn handle_deep_link_code(
    code: String,
    state: String,
    auth_mgr: State<'_, SharedAuthManager>,
) -> Result<AuthState, String> {
    auth_mgr.process_deep_link_exchange(&code, &state).await
}

#[tauri::command]
pub async fn get_auth_state(
    auth_mgr: State<'_, SharedAuthManager>,
) -> Result<AuthState, String> {
    Ok(auth_mgr.evaluate_auth_state().await)
}

#[tauri::command]
pub async fn check_session(
    auth_mgr: State<'_, SharedAuthManager>,
) -> Result<AuthState, String> {
    Ok(auth_mgr.evaluate_auth_state().await)
}

#[tauri::command]
pub async fn logout(
    auth_mgr: State<'_, SharedAuthManager>,
) -> Result<AuthState, String> {
    auth_mgr.storage.clear_session()?;
    Ok(auth_mgr.evaluate_auth_state().await)
}

#[tauri::command]
pub async fn cancel_cookapps_login(
    auth_mgr: State<'_, SharedAuthManager>,
) -> Result<AuthState, String> {
    {
        let mut session = auth_mgr.pending_session.lock().map_err(|e| e.to_string())?;
        session.state = None;
        session.verifier = None;
    }
    Ok(auth_mgr.evaluate_auth_state().await)
}

#[tauri::command]
pub async fn open_cookapps_url(
    app: AppHandle,
    url: String,
) -> Result<(), String> {
    if !url.starts_with("https://cookapps.net") && !url.starts_with("http://localhost:3000") {
        return Err("Invalid URL destination".to_string());
    }
    app.opener()
        .open_url(&url, None::<&str>)
        .map_err(|e| e.to_string())
}
