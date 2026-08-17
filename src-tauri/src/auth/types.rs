use serde::{Deserialize, Serialize};

pub const APP_SLUG: &str = "catnotes";
pub const CALLBACK_SCHEME: &str = "cookapps-catnotes";
pub const DEFAULT_API_BASE_URL: &str = "https://cookapps.net";

// Embedded public key for verifying signed offline leases
pub const DESKTOP_LEASE_PUBLIC_KEY_BASE64: &str =
    "MCowBQYDK2VwAyEAvSTxJ6EC0pASM2tyZYWRB7MZ7KTw/g3g03FwGPIh+EM=";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAuthRequest {
    pub app_slug: String,
    pub device_key: String,
    pub device_name: String,
    pub platform: String,
    pub state: String,
    pub code_challenge: String,
    pub public_key_ed25519: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAuthResponse {
    pub success: bool,
    pub login_url: String,
    pub callback_scheme: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRequest {
    pub code: String,
    pub code_verifier: String,
    pub device_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub plan_code: String,
    pub subscription_status: String,
    pub active_devices_count: u32,
    pub max_devices_allowed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: String,
    pub device_key: String,
    pub name: String,
    pub platform: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementInfo {
    pub allowed: bool,
    pub is_free: Option<bool>,
    pub app_name: String,
    pub app_slug: Option<String>,
    pub plan_required: Option<String>,
    pub reason: Option<String>,
    pub checkout_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeResponse {
    pub success: bool,
    pub authenticated: bool,
    pub access_token: String,
    pub lease_token: String,
    pub lease_expires_at: u64,
    pub lease_grace_until: u64,
    pub ip_changed: Option<bool>,
    pub user: UserProfile,
    pub device: DeviceInfo,
    pub entitlement: EntitlementInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub authenticated: bool,
    pub access_token: String,
    pub lease_token: String,
    pub lease_expires_at: u64,
    pub lease_grace_until: u64,
    pub user: UserProfile,
    pub device: DeviceInfo,
    pub entitlement: EntitlementInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeasePayload {
    pub version: u32,
    pub user_id: String,
    pub device_id: String,
    pub plan_code: String,
    pub app_entitlements: Vec<String>,
    pub entitlement_allowed: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub grace_until: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthStatusCode {
    Unauthenticated,
    Authenticating,
    Authenticated,
    UpgradeRequired,
    DeviceLimitReached,
    IpReauthRequired,
    DeviceRevoked,
    OfflineActive,
    OfflineGrace,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthState {
    pub status: AuthStatusCode,
    pub message: String,
    pub user: Option<UserProfile>,
    pub entitlement: Option<EntitlementInfo>,
    pub is_offline: bool,
    pub is_grace_period: bool,
    pub checkout_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
    pub checkout_url: Option<String>,
}
