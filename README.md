# CatNotes 🐱

<img src="docs/app-icon.png" alt="CatNotes" width="128" height="128" style="border-radius: 22px; margin-bottom: 8px;">

CatNotes is a fast, friendly markdown notes app for macOS and Windows, powered by CookApps Desktop Authentication.

![macOS](https://img.shields.io/badge/platform-macOS-lightgrey) ![Windows](https://img.shields.io/badge/platform-Windows-blue)

---

## 1. App Information

- **App Name**: CatNotes
- **App Slug**: `catnotes`
- **Category**: Macarons - Mini-Tools & Shortcuts
- **Access Type**: PERSONAL - paid plan
- **Badge Tag**: None
- **Short Description**: CatNotes is a fast, friendly markdown notes app
- **Supported Platforms**: macOS, Windows
- **Production Website**: https://cookapps.net
- **Desktop Callback Scheme**: `cookapps-catnotes://auth`

---

## 2. Supported Platforms

- **macOS** (macOS 10.15 Catalina or newer)
- **Windows** (Windows 10 / Windows 11 with WebView2 Runtime)

---

## 3. Development Setup

### Prerequisites
- **Node.js**: v18.0 or higher
- **Rust**: 1.70.0 or higher (`rustup`)
- **System Toolchain**: MSVC C++ Build Tools (Windows) or Xcode Command Line Tools (macOS)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/erictli/scratch.git
cd scratch

# 2. Install NPM dependencies
npm install

# 3. Start development app with Tauri
npm run tauri dev
```

---

## 4. Production Build Commands

```bash
# Build frontend and compile native desktop binary
npm run tauri build
```

The resulting native installers will be generated under:
- **Windows**: `src-tauri/target/release/bundle/nsis/CatNotes-1.0.0-setup.exe`
- **macOS**: `src-tauri/target/release/bundle/dmg/CatNotes_1.0.0_x64.dmg`

---

## 5. CookApps Login Flow

1. User opens CatNotes.
2. CatNotes creates a stable installation `deviceKey` (UUID).
3. CatNotes creates an Ed25519 key pair for device proof.
4. CatNotes creates PKCE S256 verifier and challenge.
5. CatNotes generates a random OAuth-style `state` (>=16 chars).
6. CatNotes sends `POST https://cookapps.net/api/desktop/auth/start`.
7. Server returns a `loginUrl`. CatNotes opens `loginUrl` in system browser.
8. User logs in on CookApps website via Google or Email Magic Link.
9. Website verifies user subscription entitlement for `catnotes`.
10. Website triggers deep link: `cookapps-catnotes://auth?code={one-time-code}&state={state}`.
11. CatNotes compares `state` in constant time, exchanges `code` via `POST /api/desktop/auth/exchange`.
12. CatNotes stores tokens securely in OS Keychain / Credential Manager.
13. CatNotes executes `GET /api/desktop/session?appSlug=catnotes` signed with Ed25519 private key.
14. CatNotes allows or blocks access based on entitlement.

---

## 6. API Endpoint Contract

Production API base URL: `https://cookapps.net`

### 1. START DESKTOP LOGIN
`POST /api/desktop/auth/start`
- **Request Body**:
  ```json
  {
    "appSlug": "catnotes",
    "deviceKey": "catnotes-installation-uuid",
    "deviceName": "User MacBook",
    "platform": "macOS",
    "state": "random-url-safe-state-min-16-characters",
    "codeChallenge": "base64url-sha256-of-code-verifier",
    "publicKeyEd25519": "base64-der-spki-public-key"
  }
  ```

### 2. EXCHANGE LOGIN CODE
`POST /api/desktop/auth/exchange`
- **Request Body**:
  ```json
  {
    "code": "one-time-code",
    "codeVerifier": "original-pkce-verifier",
    "deviceKey": "catnotes-installation-uuid"
  }
  ```

### 3. DESKTOP SESSION CHECK
`GET /api/desktop/session?appSlug=catnotes`
- **Required Headers**:
  - `Authorization: Bearer DESKTOP_JWT`
  - `X-CookApps-Device-Key: DEVICE_KEY`
  - `X-CookApps-Timestamp: UNIX_TIMESTAMP`
  - `X-CookApps-Nonce: RANDOM_NONCE`
  - `X-CookApps-Signature: BASE64URL_SIGNATURE`
- Signed message format:
  ```text
  GET
  /api/desktop/session?appSlug=catnotes
  {timestamp}
  {nonce}
  ```

---

## 7. Deep-Link Setup

Protocol Scheme: `cookapps-catnotes://auth`

### OS Registration
- **macOS**: `CFBundleURLTypes` registered in `tauri.conf.json` -> `"macOS"."deepLinking"`.
- **Windows**: Windows registry protocol handler managed by `tauri-plugin-deep-link`.

Expected Deep Link Format:
```text
cookapps-catnotes://auth?code=ONE_TIME_CODE&state=ORIGINAL_STATE
```

---

## 8. Secure Storage Behavior

Credentials are saved via `keyring` crate in OS-level secure storage:
- **macOS**: Apple Keychain Service
- **Windows**: Windows Credential Manager / DPAPI

Protected values:
- `accessToken`
- `leaseToken`
- `devicePrivateKey`
- `deviceKey`
- `userProfile`
- `entitlement`

Tokens are never saved in `localStorage`, plain text files, or URLs.

---

## 9. PKCE Behavior

- Uses S256 standard (`SHA-256` hashing).
- PKCE Verifier: 64-character URL-safe random string.
- PKCE Challenge: Base64url-encoded SHA-256 of verifier.
- Verifier is deleted immediately after code exchange.

---

## 10. Ed25519 Device Proof

- Key pair generated per installation.
- Public key DER SPKI base64 is registered with CookApps server during `/auth/start`.
- Private key never leaves OS secure storage.
- Every `/api/desktop/session` request is signed using the private key with a fresh timestamp and nonce.

---

## 11. Offline Lease Verification

CookApps server returns a signed Ed25519 lease for offline support.

- `current time < expires_at`: Normal offline operation allowed.
- `expires_at <= current time < grace_until`: Limited operation with background online refresh attempt.
- `current time > grace_until`: Requires online login.

Lease validation checks:
1. Ed25519 signature verified against embedded `DESKTOP_LEASE_PUBLIC_KEY_BASE64`.
2. `lease.app_entitlements` includes `"catnotes"`.
3. `lease.entitlement_allowed === true`.
4. `lease.device_id` matches current installation device key.

---

## 12. Free, Personal, and Family Rules

- **Free Plan**: Free users are blocked with `UPGRADE_REQUIRED`.
- **Personal Plan**: Allowed 1 active desktop device slot.
- **Family Plan**: Allowed up to 5 active desktop device slots.
- **Device Limit Exceeded**: Blocked with `DEVICE_LIMIT_REACHED`.
- **Network IP Change**: Blocked with `IP_REAUTH_REQUIRED`.

---

## 13. Error Handling

- `APP_NOT_AVAILABLE`: App is unavailable. Contact support.
- `UPGRADE_REQUIRED`: Personal plan is required to use CatNotes.
- `DEVICE_LIMIT_REACHED`: Device limit reached. Replace an existing device on CookApps website.
- `IP_REAUTH_REQUIRED`: Network changed. Sign in again through CookApps website.
- `DEVICE_REVOKED`: This device was revoked. Sign in again.
- `INVALID_EXCHANGE_CODE`: Login code expired or was already used.
- `PKCE_VERIFICATION_FAILED`: Secure login verification failed.

---

## 14. Environment Variables

Example `.env` configuration:

```env
COOKAPPS_API_BASE_URL=https://cookapps.net
COOKAPPS_APP_SLUG=catnotes
COOKAPPS_CALLBACK_SCHEME=cookapps-catnotes
DESKTOP_LEASE_PUBLIC_KEY_BASE64=MCowBQYDK2VwAyEA9xX5l+v4R3eN3j0A0rN8x6n8dK5q9v2w1z3y4x5w6v8=
```

---

## 15. Test Instructions

Execute Rust unit tests:

```bash
cd src-tauri
cargo test auth::tests
```

Unit test coverage:
1. PKCE verifier & challenge generation.
2. Constant-time state comparison.
3. Ed25519 SPKI public key encoding.
4. Session request signing header format.
5. Error text mapping.
6. Offline lease token verification.

---

## 16. Security Warnings

- Do not expose Ed25519 private key through IPC.
- Never hard-code user entitlement or bypass server checks locally.
- Do not log `accessToken`, `leaseToken`, `code`, `codeVerifier`, or private keys.
- Always validate `state` in constant time before exchanging `code`.

---

## 17. Troubleshooting

- **Deep link callback not triggering**: Ensure `cookapps-catnotes` protocol scheme is registered on your system. Run `npm run tauri dev` to re-register protocol handlers.
- **Keyring access denied**: On Windows, check Windows Credential Manager service. On macOS, ensure Keychain Access is unlocked.
