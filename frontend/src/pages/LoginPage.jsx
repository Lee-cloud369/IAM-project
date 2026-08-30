/**
 * =============================================================================
 * AETHER ARAN IAM - LOGIN SCREEN (CYBERPUNK TACTICAL SOC AESTHETIC)
 * =============================================================================
 * Allows authorized security analysts to authenticate via AWS Cognito.
 * Tokens are kept strictly in React memory upon successful login.
 */

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function LoginPage({ onNavigateToSignup }) {
  const { login, loading, authError, setAuthError } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setAuthError('Please enter both email and password.');
      return;
    }

    try {
      await login(email.trim(), password);
    } catch (err) {
      // Error handled by AuthContext state
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#0A0A0F] flex items-center justify-center p-4 relative overflow-hidden selection:bg-primary-container selection:text-on-primary-container">
      {/* Ambient CRT Scanline Overlay */}
      <div className="fixed inset-0 cyber-scan-lines pointer-events-none opacity-20 z-10"></div>

      {/* Atmospheric Neon Glow Spheres */}
      <div className="absolute top-1/4 -left-20 w-96 h-96 rounded-full bg-[#bef500]/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 -right-20 w-96 h-96 rounded-full bg-[#FF2E9F]/5 blur-[120px] pointer-events-none"></div>

      {/* Main Glassmorphic Login Card */}
      <div className="w-full max-w-md glass-panel rounded-2xl border border-outline-variant/40 shadow-2xl p-8 sm:p-10 relative z-20 animate-fadeIn">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-surface-container-highest border border-primary-fixed mb-4 shadow-[0_0_20px_rgba(190,245,0,0.3)]">
            <span className="material-symbols-outlined text-primary-fixed text-3xl">
              shield_lock
            </span>
          </div>
          <h1 className="font-display-hero text-2xl sm:text-3xl text-primary font-bold tracking-tight uppercase">
            AETHER ARAN
          </h1>
          <p className="font-label-caps text-xs text-primary-fixed tracking-widest uppercase mt-1">
            Pluma Security • CIEM Cloud Operations
          </p>
          <div className="mt-3 text-xs text-on-surface-variant/70 font-body-md">
            AWS Cognito Identity & Access Management Gateway
          </div>
        </div>

        {/* Error Alert Box */}
        {authError && (
          <div className="mb-6 p-3.5 rounded-xl bg-error-container/20 border border-error/40 text-error text-xs font-body-md flex items-start gap-2.5 animate-fadeIn">
            <span className="material-symbols-outlined text-base shrink-0 mt-0.5">
              error
            </span>
            <div className="flex-1 leading-relaxed">{authError}</div>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Email Field */}
          <div>
            <label className="block font-label-caps text-xs text-on-surface-variant uppercase tracking-wider mb-2 font-bold">
              Analyst Email Address
            </label>
            <div className="relative flex items-center bg-surface-container-low border border-outline-variant/60 rounded-xl focus-within:border-primary-fixed focus-within:shadow-[0_0_15px_rgba(190,245,0,0.25)] transition-all">
              <span className="material-symbols-outlined text-on-surface-variant/60 pl-3.5 text-lg pointer-events-none">
                alternate_email
              </span>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (authError) setAuthError(null);
                }}
                placeholder="analyst@cloudsec.io"
                className="w-full bg-transparent text-on-surface font-mono text-sm py-3 px-3 focus:outline-none placeholder:text-on-surface-variant/30"
              />
            </div>
          </div>

          {/* Password Field */}
          <div>
            <label className="block font-label-caps text-xs text-on-surface-variant uppercase tracking-wider mb-2 font-bold">
              Cognito Password
            </label>
            <div className="relative flex items-center bg-surface-container-low border border-outline-variant/60 rounded-xl focus-within:border-primary-fixed focus-within:shadow-[0_0_15px_rgba(190,245,0,0.25)] transition-all">
              <span className="material-symbols-outlined text-on-surface-variant/60 pl-3.5 text-lg pointer-events-none">
                key
              </span>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (authError) setAuthError(null);
                }}
                placeholder="••••••••••••"
                className="w-full bg-transparent text-on-surface font-mono text-sm py-3 px-3 focus:outline-none placeholder:text-on-surface-variant/30"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="pr-3.5 text-on-surface-variant/50 hover:text-primary-fixed transition-colors"
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                <span className="material-symbols-outlined text-lg">
                  {showPassword ? 'visibility_off' : 'visibility'}
                </span>
              </button>
            </div>
          </div>

          {/* Submit Action Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 px-4 mt-2 bg-primary-fixed text-on-primary-fixed font-label-caps text-sm font-bold uppercase tracking-widest rounded-xl hover:bg-primary-fixed-dim shadow-[0_0_20px_rgba(190,245,0,0.35)] transition-all duration-200 flex items-center justify-center gap-2 active:scale-98 disabled:opacity-50 disabled:pointer-events-none"
          >
            {loading ? (
              <>
                <span className="material-symbols-outlined text-lg animate-spin">
                  sync
                </span>
                <span>AUTHENTICATING COGNITO...</span>
              </>
            ) : (
              <>
                <span>ACCESS SOC TELEMETRY</span>
                <span className="material-symbols-outlined text-lg font-bold">
                  login
                </span>
              </>
            )}
          </button>
        </form>

        {/* Footer Navigation to Sign Up */}
        <div className="mt-8 pt-6 border-t border-outline-variant/30 text-center">
          <p className="text-xs text-on-surface-variant font-body-md">
            Need a new Cloud Security Analyst account?{' '}
            <button
              onClick={onNavigateToSignup}
              className="text-primary-fixed hover:underline font-label-caps uppercase tracking-wider font-bold ml-1 transition-all inline-flex items-center gap-0.5"
            >
              Sign Up Now
              <span className="material-symbols-outlined text-xs">arrow_forward</span>
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
