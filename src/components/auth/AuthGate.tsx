import React from "react";
import { useAuth } from "../../context/AuthContext";
import { Button } from "../ui";
import { SpinnerIcon } from "../icons";

export const AuthGate: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const {
    authState,
    isLoading,
    isAuthenticating,
    isAuthorizing,
    startLogin,
    cancelLogin,
    checkSession,
    logout,
    openUrl,
  } = useAuth();

  const isAccessAllowed =
    authState.status === "AUTHENTICATED" ||
    authState.status === "OFFLINE_ACTIVE" ||
    authState.status === "OFFLINE_GRACE";

  // Show main app content if access is allowed
  if (isAccessAllowed) {
    return (
      <div className="relative w-full h-full flex flex-col">
        {/* Offline indicator banner if in offline grace period */}
        {authState.isGracePeriod && (
          <div className="bg-amber-500/10 border-b border-amber-500/20 px-4 py-1.5 flex items-center justify-between text-xs text-amber-600 dark:text-amber-400">
            <span>Offline grace period active. Connect to internet to refresh session.</span>
            <button
              onClick={checkSession}
              className="underline font-medium hover:text-amber-700 dark:hover:text-amber-300"
            >
              Retry Connection
            </button>
          </div>
        )}
        {children}
      </div>
    );
  }

  // Blocking Auth Modal / Screen when unauthenticated or entitlement denied
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-bg/95 backdrop-blur-md p-6">
      <div className="max-w-md w-full bg-bg-secondary rounded-2xl border border-border p-8 shadow-2xl flex flex-col items-center text-center space-y-6">
        {/* CatNotes Cool Mèo Illustration */}
        <div className="relative w-24 h-24 rounded-full bg-bg-muted p-3 border-2 border-border shadow-inner">
          <img
            src="/folders-dark.png"
            alt="CatNotes"
            className="w-full h-full object-contain"
          />
        </div>

        <div>
          <h1 className="text-2xl font-bold tracking-tight text-text">CatNotes</h1>
          <p className="text-xs text-text-muted mt-1 uppercase tracking-widest font-mono">
            Macarons • Mini-Tools & Shortcuts
          </p>
        </div>

        {/* State Banner & Message */}
        <div className="w-full space-y-2">
          {isLoading ? (
            <div className="flex items-center justify-center space-x-2 text-text-muted text-sm py-4">
              <SpinnerIcon className="w-5 h-5 animate-spin" />
              <span>Checking subscription...</span>
            </div>
          ) : isAuthorizing ? (
            <div className="bg-bg-muted p-4 rounded-xl border border-border space-y-2">
              <div className="flex items-center justify-center space-x-2 text-amber-500 font-medium text-sm">
                <SpinnerIcon className="w-4 h-4 animate-spin" />
                <span>Authorizing device...</span>
              </div>
              <p className="text-xs text-text-muted">
                Exchanging secure code and verifying plan entitlement...
              </p>
            </div>
          ) : isAuthenticating ? (
            <div className="bg-bg-muted p-4 rounded-xl border border-border space-y-2">
              <div className="flex items-center justify-center space-x-2 text-text font-medium text-sm">
                <SpinnerIcon className="w-4 h-4 animate-spin" />
                <span>Opening CookApps login...</span>
              </div>
              <p className="text-xs text-text-muted">
                Waiting for website approval. Please complete login in your browser.
              </p>
            </div>
          ) : (
            <div className="bg-bg-muted p-4 rounded-xl border border-border space-y-1">
              <p className="text-sm font-semibold text-text">
                {authState.status === "UPGRADE_REQUIRED" && "Personal or Family Plan Required"}
                {authState.status === "DEVICE_LIMIT_REACHED" && "Device Limit Reached"}
                {authState.status === "IP_REAUTH_REQUIRED" && "Network IP Changed"}
                {authState.status === "UNAUTHENTICATED" && "Sign In Required"}
                {authState.status === "ERROR" && "Authentication Error"}
              </p>
              <p className="text-xs text-text-muted leading-relaxed">
                {authState.message}
              </p>
            </div>
          )}
        </div>

        {/* User Info if available */}
        {authState.user && (
          <div className="w-full text-left text-xs bg-bg p-3 rounded-lg border border-border space-y-1">
            <div className="flex justify-between">
              <span className="text-text-muted">Signed in as:</span>
              <span className="font-mono text-text truncate max-w-[180px]">
                {authState.user.email}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Plan:</span>
              <span className="font-semibold text-amber-500">
                {authState.user.planCode}
              </span>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="w-full space-y-3 pt-2">
          {isAuthenticating || isAuthorizing ? (
            <>
              <Button
                onClick={startLogin}
                variant="outline"
                size="md"
                className="w-full justify-center text-xs"
              >
                Open CookApps login again
              </Button>
              <Button
                onClick={cancelLogin}
                variant="ghost"
                size="md"
                className="w-full justify-center text-xs text-text-muted"
              >
                Cancel
              </Button>
            </>
          ) : authState.status === "UPGRADE_REQUIRED" ? (
            <>
              <Button
                onClick={() =>
                  authState.checkoutUrl
                    ? openUrl(authState.checkoutUrl)
                    : openUrl("https://cookapps.net")
                }
                variant="primary"
                size="lg"
                className="w-full justify-center text-sm font-medium"
              >
                Upgrade to Personal
              </Button>
              <Button
                onClick={logout}
                variant="outline"
                size="md"
                className="w-full justify-center text-xs"
              >
                Sign Out
              </Button>
            </>
          ) : authState.status === "DEVICE_LIMIT_REACHED" ? (
            <>
              <Button
                onClick={() => openUrl("https://cookapps.net/devices")}
                variant="primary"
                size="lg"
                className="w-full justify-center text-sm font-medium"
              >
                Manage devices
              </Button>
              <Button
                onClick={checkSession}
                variant="outline"
                size="md"
                className="w-full justify-center text-xs"
              >
                Refresh Session
              </Button>
            </>
          ) : authState.status === "IP_REAUTH_REQUIRED" ? (
            <Button
              onClick={startLogin}
              variant="primary"
              size="lg"
              className="w-full justify-center text-sm font-medium"
            >
              Sign in again
            </Button>
          ) : (
            <Button
              onClick={startLogin}
              disabled={isAuthenticating || isLoading}
              variant="primary"
              size="lg"
              className="w-full justify-center text-sm font-medium"
            >
              Login with CookApps Account
            </Button>
          )}
        </div>

        <p className="text-[11px] text-text-muted">
          CatNotes requires an active CookApps Personal or Family subscription.
        </p>
      </div>
    </div>
  );
};
