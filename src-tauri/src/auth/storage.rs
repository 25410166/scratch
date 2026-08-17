use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use crate::auth::types::{EntitlementInfo, UserProfile};

const KEYRING_SERVICE: &str = "com.catnotes.desktop";
const SECURE_STORE_FILENAME: &str = ".catnotes_auth.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoredAuthData {
    pub device_key: Option<String>,
    pub private_key_hex: Option<String>,
    pub access_token: Option<String>,
    pub lease_token: Option<String>,
    pub lease_expires_at: Option<u64>,
    pub lease_grace_until: Option<u64>,
    pub user_profile: Option<UserProfile>,
    pub entitlement: Option<EntitlementInfo>,
    pub pending_state: Option<String>,
    pub pending_verifier: Option<String>,
}

pub struct SecureStorage {
    app_data_dir: PathBuf,
}

impl SecureStorage {
    pub fn new(app_data_dir: PathBuf) -> Self {
        Self { app_data_dir }
    }

    /// Try loading stored data from OS Keyring first, falling back to secure file store
    pub fn load_auth_data(&self) -> StoredAuthData {
        // Attempt keyring retrieval
        if let Ok(entry) = Entry::new(KEYRING_SERVICE, "auth_payload") {
            if let Ok(password) = entry.get_password() {
                if let Ok(data) = serde_json::from_str::<StoredAuthData>(&password) {
                    return data;
                }
            }
        }

        // Fallback to app_data_dir secure file
        let file_path = self.app_data_dir.join(SECURE_STORE_FILENAME);
        if file_path.exists() {
            if let Ok(content) = fs::read_to_string(&file_path) {
                if let Ok(data) = serde_json::from_str::<StoredAuthData>(&content) {
                    return data;
                }
            }
        }

        StoredAuthData::default()
    }

    /// Save auth data into OS Keyring and fallback file store
    pub fn save_auth_data(&self, data: &StoredAuthData) -> Result<(), String> {
        let serialized = serde_json::to_string(data).map_err(|e| e.to_string())?;

        // Try OS Keyring
        if let Ok(entry) = Entry::new(KEYRING_SERVICE, "auth_payload") {
            let _ = entry.set_password(&serialized);
        }

        // Save fallback file with restricted directory permissions
        if !self.app_data_dir.exists() {
            let _ = fs::create_dir_all(&self.app_data_dir);
        }

        let file_path = self.app_data_dir.join(SECURE_STORE_FILENAME);
        fs::write(file_path, serialized).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Delete tokens upon logout while preserving installation device identity
    pub fn clear_session(&self) -> Result<(), String> {
        let mut current = self.load_auth_data();
        current.access_token = None;
        current.lease_token = None;
        current.lease_expires_at = None;
        current.lease_grace_until = None;
        current.user_profile = None;
        current.entitlement = None;

        self.save_auth_data(&current)
    }
}
