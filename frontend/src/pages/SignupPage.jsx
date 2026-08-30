/**
 * =============================================================================
 * AETHER ARAN IAM - SIGN UP SCREEN (WITH COGNITO VERIFICATION CODE FLOW)
 * =============================================================================
 * Supports two-step user onboarding:
 * 1. Register with Email + Password (generates a unique Cognito username)
 * 2. Submit 6-digit verification code emailed by AWS Cognito User Pool
 *    - Confirmation & Resend operations use the EXACT registered username from Step 1,
 *      ensuring no duplicate users are created.
 */

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function SignupPage({ onNavigateToLogin }) {
  const { signUp, confirmSignUp, resendCode, loading, authError, setAuthError } = useAuth();

  // Step 1: 'register' | Step 2: 'confirm'
  const [step, setStep] = useState('register');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');
  const [registeredUsername, setRegisteredUsername] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [resendStatus, setResendStatus] = useState('');

  // Step 1: Initial Registration
  const handleRegister = async (e) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setAuthError('Please fill in all required fields.');
      return;
    }
    if (password !== confirmPassword) {
      setAuthError('Passwords do not match. Please verify.');
      return;
    }
    if (password.length < 8) {
      setAuthError('Cognito password policy requires at least 8 characters.');
      return;
    }

    try {
      const result = await signUp(email.trim(), password);
      // Store the exact Cognito username generated during sign-up for step 2 verification
      const uname = result?.cognitoUsername || result?.user?.getUsername() || '';
      setRegisteredUsername(uname);
      setSuccessMessage(`Verification code dispatched to ${email.trim()}.`);
      setStep('confirm');
    } catch (err) {
      // Error handled by context
    }
  };

  // Step 2: Confirmation Code Submission (Uses the existing registered username)
  const handleConfirm = async (e) => {
    e.preventDefault();
    if (!verificationCode.trim()) {
      setAuthError('Please enter the 6-digit confirmation code.');
      return;
    }

    // Must use the registered Cognito username created in Step 1
    const targetUsername = registeredUsername || email.trim();

    try {
      await confirmSignUp(targetUsername, verificationCode.trim());
      setSuccessMessage('Account verified successfully! Redirecting to login...');
      setTimeout(() => {
        onNavigateToLogin();
      }, 1500);
    } catch (err) {
      // Error handled by context
    }
  };

  // Resend code handler (Calls resendConfirmationCode for the existing user)
  const handleResend = async () => {
    const targetUsername = registeredUsername || email.trim();
    if (!targetUsername) return;

    try {
      setResendStatus('Resending verification code...');
      await resendCode(targetUsername);
      setResendStatus('New verification code sent to your email!');
      setTimeout(() => setResendStatus(''), 4000);
    } catch (err) {
      setResendStatus(err.message || 'Failed to resend code');
      setTimeout(() => setResendStatus(''), 4000);
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#0A0A0F] flex items-center justify-center p-4 relative overflow-hidden selection:bg-primary-container selection:text-on-primary-container">
      {/* Ambient CRT Scanline Overlay */}
      <div className="fixed inset-0 cyber-scan-lines pointer-events-none opacity-20 z-10"></div>

      {/* Atmospheric Glow */}
      <div className="absolute top-1/3 -right-20 w-96 h-96 rounded-full bg-[#bef500]/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-1/3 -left-20 w-96 h-96 rounded-full bg-[#FF2E9F]/5 blur-[120px] pointer-events-none"></div>

      {/* Main Glassmorphic Card */}
      <div className="w-full max-w-md glass-panel rounded-2xl border border-outline-variant/40 shadow-2xl p-8 sm:p-10 relative z-20 animate-fadeIn">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-surface-container-highest border border-primary-fixed mb-4 shadow-[0_0_20px_rgba(190,245,0,0.3)]">
            <span className="material-symbols-outlined text-primary-fixed text-3xl">
              {step === 'register' ? 'person_add' : 'mark_email_read'}
            </span>
          </div>
          <h1 className="font-display-hero text-2xl sm:text-3xl text-primary font-bold tracking-tight uppercase">
            {step === 'register' ? 'CREATE ANALYST ID' : 'VERIFY IDENTITY'}
          </h1>
          <p className="font-label-caps text-xs text-primary-fixed tracking-widest uppercase mt-1">
            AWS Cognito User Pool Registration
          </p>
        </div>

        {/* Success Alert */}
        {successMessage && (
          <div className="mb-6 p-3.5 rounded-xl bg-primary-fixed/10 border border-primary-fixed/40 text-primary-fixed text-xs font-body-md flex items-start gap-2.5 animate-fadeIn">
            <span className="material-symbols-outlined text-base shrink-0 mt-0.5">
              check_circle
            </span>
            <div className="flex-1 leading-relaxed">{successMessage}</div>
          </div>
        )}

        {/* Error Alert */}
        {authError && (
          <div className="mb-6 p-3.5 rounded-xl bg-error-container/20 border border-error/40 text-error text-xs font-body-md flex items-start gap-2.5 animate-fadeIn">
            <span className="material-symbols-outlined text-base shrink-0 mt-0.5">
              error
            </span>
            <div className="flex-1 leading-relaxed">{authError}</div>
          </div>
        )}

        {/* STEP 1: Registration Form */}
        {step === 'register' && (
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block font-label-caps text-xs text-on-surface-variant uppercase tracking-wider mb-2 font-bold">
                Work Email Address
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

            <div>
              <label className="block font-label-caps text-xs text-on-surface-variant uppercase tracking-wider mb-2 font-bold">
                Password (min 8 chars, uppercase, digits)
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
                >
                  <span className="material-symbols-outlined text-lg">
                    {showPassword ? 'visibility_off' : 'visibility'}
                  </span>
                </button>
              </div>
            </div>

            <div>
              <label className="block font-label-caps text-xs text-on-surface-variant uppercase tracking-wider mb-2 font-bold">
                Confirm Password
              </label>
              <div className="relative flex items-center bg-surface-container-low border border-outline-variant/60 rounded-xl focus-within:border-primary-fixed focus-within:shadow-[0_0_15px_rgba(190,245,0,0.25)] transition-all">
                <span className="material-symbols-outlined text-on-surface-variant/60 pl-3.5 text-lg pointer-events-none">
                  lock_reset
                </span>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (authError) setAuthError(null);
                  }}
                  placeholder="••••••••••••"
                  className="w-full bg-transparent text-on-surface font-mono text-sm py-3 px-3 focus:outline-none placeholder:text-on-surface-variant/30"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 px-4 mt-4 bg-primary-fixed text-on-primary-fixed font-label-caps text-sm font-bold uppercase tracking-widest rounded-xl hover:bg-primary-fixed-dim shadow-[0_0_20px_rgba(190,245,0,0.35)] transition-all duration-200 flex items-center justify-center gap-2 active:scale-98 disabled:opacity-50 disabled:pointer-events-none"
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined text-lg animate-spin">
                    sync
                  </span>
                  <span>REGISTERING IN COGNITO...</span>
                </>
              ) : (
                <>
                  <span>CREATE ACCOUNT</span>
                  <span className="material-symbols-outlined text-lg font-bold">
                    arrow_forward
                  </span>
                </>
              )}
            </button>
          </form>
        )}

        {/* STEP 2: Cognito Confirmation Code Form */}
        {step === 'confirm' && (
          <form onSubmit={handleConfirm} className="space-y-4 animate-fadeIn">
            <div className="p-3 bg-surface-container-low/60 rounded-xl border border-outline-variant/30 text-xs text-on-surface-variant/80 font-mono">
              Account: <span className="text-primary-fixed font-bold">{email}</span>
            </div>

            <div>
              <label className="block font-label-caps text-xs text-on-surface-variant uppercase tracking-wider mb-2 font-bold">
                6-Digit Email Verification Code
              </label>
              <div className="relative flex items-center bg-surface-container-low border border-outline-variant/60 rounded-xl focus-within:border-primary-fixed focus-within:shadow-[0_0_15px_rgba(190,245,0,0.25)] transition-all">
                <span className="material-symbols-outlined text-on-surface-variant/60 pl-3.5 text-lg pointer-events-none">
                  pin
                </span>
                <input
                  type="text"
                  required
                  maxLength={6}
                  value={verificationCode}
                  onChange={(e) => {
                    setVerificationCode(e.target.value);
                    if (authError) setAuthError(null);
                  }}
                  placeholder="123456"
                  className="w-full bg-transparent text-on-surface font-mono text-center text-lg tracking-widest py-3 px-3 focus:outline-none placeholder:text-on-surface-variant/30"
                />
              </div>
            </div>

            <div className="flex items-center justify-between text-xs font-label-caps pt-1">
              <button
                type="button"
                onClick={handleResend}
                disabled={loading}
                className="text-on-surface-variant hover:text-primary-fixed transition-colors underline disabled:opacity-50"
              >
                {resendStatus || 'Resend verification code'}
              </button>
              <button
                type="button"
                onClick={() => setStep('register')}
                className="text-on-surface-variant hover:text-primary transition-colors"
              >
                Change email
              </button>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 px-4 mt-4 bg-primary-fixed text-on-primary-fixed font-label-caps text-sm font-bold uppercase tracking-widest rounded-xl hover:bg-primary-fixed-dim shadow-[0_0_20px_rgba(190,245,0,0.35)] transition-all duration-200 flex items-center justify-center gap-2 active:scale-98 disabled:opacity-50 disabled:pointer-events-none"
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined text-lg animate-spin">
                    sync
                  </span>
                  <span>VERIFYING CODE...</span>
                </>
              ) : (
                <>
                  <span>CONFIRM & COMPLETE SIGN UP</span>
                  <span className="material-symbols-outlined text-lg font-bold">
                    verified_user
                  </span>
                </>
              )}
            </button>
          </form>
        )}

        {/* Footer Link to Login */}
        <div className="mt-8 pt-6 border-t border-outline-variant/30 text-center">
          <p className="text-xs text-on-surface-variant font-body-md">
            Already have a Cognito security identity?{' '}
            <button
              onClick={onNavigateToLogin}
              className="text-primary-fixed hover:underline font-label-caps uppercase tracking-wider font-bold ml-1 transition-all inline-flex items-center gap-0.5"
            >
              Log In
              <span className="material-symbols-outlined text-xs">login</span>
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
