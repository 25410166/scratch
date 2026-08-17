import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { AuthState, StartAuthResponse } from "../types/auth";

interface AuthContextType {
  authState: AuthState;
  isLoading: boolean;
  isAuthenticating: boolean;
  isAuthorizing: boolean;
  startLogin: () => Promise<void>;
  cancelLogin: () => Promise<void>;
  checkSession: () => Promise<void>;
  logout: () => Promise<void>;
  openUrl: (url: string) => Promise<void>;
  handleDeepLinkUrl: (urlStr: string) => Promise<boolean>;
}

const defaultAuthState: AuthState = {
  status: "UNAUTHENTICATED",
  message: "Sign in with your CookApps account to use CatNotes.",
  user: null,
  entitlement: null,
  isOffline: false,
  isGracePeriod: false,
  checkoutUrl: null,
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [authState, setAuthState] = useState<AuthState>(defaultAuthState);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isAuthenticating, setIsAuthenticating] = useState<boolean>(false);
  const [isAuthorizing, setIsAuthorizing] = useState<boolean>(false);

  const fetchAuthState = useCallback(async () => {
    try {
      const state = await invoke<AuthState>("get_auth_state");
      setAuthState(state);
    } catch (error) {
      console.error("Failed to fetch auth state:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Kept for API compatibility - Rust handles exchange via single-instance callback
  const handleDeepLinkUrl = useCallback(async (_urlStr: string): Promise<boolean> => {
    return false;
  }, []);

  const startLogin = useCallback(async () => {
    setIsAuthenticating(true);
    setIsAuthorizing(false);
    try {
      await invoke<StartAuthResponse>("start_cookapps_login");
    } catch (error) {
      console.error("Failed to start login:", error);
      setAuthState((prev) => ({
        ...prev,
        status: "ERROR",
        message: error instanceof Error ? error.message : String(error),
      }));
      setIsAuthenticating(false);
    }
  }, []);

  const cancelLogin = useCallback(async () => {
    try {
      const state = await invoke<AuthState>("cancel_cookapps_login");
      setAuthState(state);
    } catch (error) {
      console.error("Failed to cancel login:", error);
    } finally {
      setIsAuthenticating(false);
      setIsAuthorizing(false);
    }
  }, []);

  const checkSession = useCallback(async () => {
    setIsLoading(true);
    try {
      const state = await invoke<AuthState>("check_session");
      setAuthState(state);
    } catch (error) {
      console.error("Failed to check session:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setIsLoading(true);
    try {
      const state = await invoke<AuthState>("logout");
      setAuthState(state);
    } catch (error) {
      console.error("Failed to logout:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const openUrl = useCallback(async (url: string) => {
    try {
      await invoke("open_cookapps_url", { url });
    } catch (error) {
      console.error("Failed to open CookApps URL:", error);
    }
  }, []);

  useEffect(() => {
    fetchAuthState();

    // Rust (single-instance callback) is the sole place that performs
    // the PKCE exchange and emits auth-state-changed.  
    // Frontend only reacts to this event – never calls handle_deep_link_code itself,
    // preventing a double-exchange race condition.
    const unlistenEventPromise = listen<AuthState>("auth-state-changed", (event) => {
      console.log("[auth] auth-state-changed received, status=", event.payload.status);
      setAuthState(event.payload);
      setIsAuthenticating(false);
      setIsAuthorizing(false);
      setIsLoading(false);
    });

    // Periodic session check every 15 minutes when online
    const interval = setInterval(() => {
      if (navigator.onLine && authState.status === "AUTHENTICATED") {
        fetchAuthState();
      }
    }, 15 * 60 * 1000);

    return () => {
      unlistenEventPromise.then((unlisten: () => void) => unlisten());
      clearInterval(interval);
    };
  }, [fetchAuthState, authState.status]);

  return (
    <AuthContext.Provider
      value={{
        authState,
        isLoading,
        isAuthenticating,
        isAuthorizing,
        startLogin,
        cancelLogin,
        checkSession,
        logout,
        openUrl,
        handleDeepLinkUrl,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
