export type AuthStatusCode =
  | "UNAUTHENTICATED"
  | "AUTHENTICATING"
  | "AUTHENTICATED"
  | "UPGRADE_REQUIRED"
  | "DEVICE_LIMIT_REACHED"
  | "IP_REAUTH_REQUIRED"
  | "DEVICE_REVOKED"
  | "OFFLINE_ACTIVE"
  | "OFFLINE_GRACE"
  | "ERROR";

export interface UserProfile {
  userId: string;
  email: string;
  name: string;
  planCode: string;
  subscriptionStatus: string;
  activeDevicesCount: number;
  maxDevicesAllowed: number;
}

export interface EntitlementInfo {
  allowed: boolean;
  appName: string;
  appSlug: string;
  planRequired: string;
  reason?: string | null;
  checkoutUrl?: string | null;
}

export interface AuthState {
  status: AuthStatusCode;
  message: string;
  user?: UserProfile | null;
  entitlement?: EntitlementInfo | null;
  isOffline: boolean;
  isGracePeriod: boolean;
  checkoutUrl?: string | null;
}

export interface StartAuthResponse {
  success: boolean;
  loginUrl: string;
  callbackScheme: string;
  expiresAt: string;
}
