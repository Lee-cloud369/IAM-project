/**
 * =============================================================================
 * AETHER ARAN IAM - IN-MEMORY AUTHENTICATION CONTEXT (SECURE REACT STATE)
 * =============================================================================
 * 
 * Simple Explanation (Zero-Coding Background):
 * - Security Rule: Never store JWT tokens in localStorage or sessionStorage,
 *   because any malicious script injected into the page could steal them.
 * - Solution: We keep the user session and token purely in React's in-memory state.
 * - This context wraps our entire app, giving every component access to the
 *   currently logged-in user and authentication functions (login, signup, logout).
 * =============================================================================
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import {
  cognitoSignIn,
  cognitoSignUp,
  cognitoConfirmSignUp,
  cognitoResendCode,
  cognitoSignOut,
} from '../services/cognito';
import { setAuthToken, getCurrentUser } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // In-memory authentication state
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [syncWarning, setSyncWarning] = useState(null);

  /**
   * Log in user with AWS Cognito.
   * On success, saves token in React memory and sets API Authorization header.
   */
  const login = async (emailOrUsername, password) => {
    setLoading(true);
    setAuthError(null);
    setSyncWarning(null);
    try {
      const authResult = await cognitoSignIn(emailOrUsername, password);
      
      // Use Access Token for API authorization (or ID token with claims)
      const activeToken = authResult.accessToken || authResult.idToken;
      setToken(activeToken);
      setAuthToken(activeToken);

      const userProfile = {
        email: authResult.email,
        username: authResult.username,
        sub: authResult.sub,
      };
      setUser(userProfile);

      // Verify connection with backend /api/me
      try {
        const meResp = await getCurrentUser();
        if (meResp && meResp.email) {
          setUser((prev) => ({
            ...prev,
            email: meResp.email,
            username: meResp.username || prev.username,
          }));
        }
        setSyncWarning(null);
      } catch (meErr) {
        console.warn('Backend /api/me sync note:', meErr);
        const warningMsg = "Some profile data couldn't be loaded from backend server (using session profile).";
        setSyncWarning(warningMsg);
        setTimeout(() => {
          setSyncWarning(null);
        }, 6000);
      }

      setLoading(false);
      return userProfile;
    } catch (err) {
      setLoading(false);
      const message = err.message || 'Login failed. Please check your credentials.';
      setAuthError(message);
      throw err;
    }
  };

  /**
   * Register a new account in AWS Cognito User Pool.
   */
  const signUp = async (email, password) => {
    setLoading(true);
    setAuthError(null);
    try {
      const result = await cognitoSignUp(email, password);
      setLoading(false);
      return result;
    } catch (err) {
      setLoading(false);
      const message = err.message || 'Registration failed. Please try again.';
      setAuthError(message);
      throw err;
    }
  };

  /**
   * Confirm registration with the 6-digit email code for an existing user.
   */
  const confirmSignUp = async (usernameOrEmail, code) => {
    setLoading(true);
    setAuthError(null);
    try {
      const result = await cognitoConfirmSignUp(usernameOrEmail, code);
      setLoading(false);
      return result;
    } catch (err) {
      setLoading(false);
      const message = err.message || 'Verification failed. Please check your code.';
      setAuthError(message);
      throw err;
    }
  };

  /**
   * Resend verification code to the existing registered user.
   * Calls cognitoResendCode (resendConfirmationCode) — NEVER triggers a new signUp.
   */
  const resendCode = async (usernameOrEmail) => {
    setLoading(true);
    setAuthError(null);
    try {
      const result = await cognitoResendCode(usernameOrEmail);
      setLoading(false);
      return result;
    } catch (err) {
      setLoading(false);
      const message = err.message || 'Failed to resend verification code.';
      setAuthError(message);
      throw err;
    }
  };

  /**
   * Log out user: Clears in-memory token and resets application state.
   */
  const logout = () => {
    if (user?.email) {
      cognitoSignOut(user.email);
    }
    setUser(null);
    setToken(null);
    setAuthToken(null);
    setAuthError(null);
    setSyncWarning(null);
  };

  const value = {
    user,
    token,
    isAuthenticated: Boolean(token && user),
    loading,
    authError,
    setAuthError,
    syncWarning,
    setSyncWarning,
    login,
    signUp,
    confirmSignUp,
    resendCode,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
      {syncWarning && (
        <div className="fixed bottom-5 right-5 z-[9999] max-w-md bg-surface-container-high border border-amber-400/50 text-amber-200 px-4 py-3 rounded-lg shadow-2xl flex items-center justify-between gap-3 animate-fadeIn">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-amber-400 text-lg">warning</span>
            <span className="text-xs font-body-md text-on-surface">{syncWarning}</span>
          </div>
          <button
            onClick={() => setSyncWarning(null)}
            className="text-on-surface-variant hover:text-on-surface p-1 text-xs"
            title="Dismiss notification"
          >
            <span className="material-symbols-outlined text-sm">close</span>
          </button>
        </div>
      )}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
