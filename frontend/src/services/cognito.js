/**
 * =============================================================================
 * AETHER ARAN IAM - AWS COGNITO IDENTITY SERVICE WRAPPER
 * =============================================================================
 * 
 * Simple Explanation (Zero-Coding Background):
 * This file handles all direct communication with AWS Cognito:
 * 1. User Registration (signUp): Creates a new account in AWS Cognito User Pool.
 *    - Cognito Username Policy: When a User Pool is configured for email aliases,
 *      Cognito forbids '@' and '.' characters in the primary username.
 *    - Deterministic Mapping: We convert the user's email into a sanitized username
 *      (e.g., "analyst@sec.io" -> "analyst_sec_io") deterministically (without random numbers).
 * 2. Email Confirmation (confirmSignUp): Submits the 6-digit verification code.
 * 3. User Login (signIn): Converts the entered email into the exact same deterministic
 *    username format used at signup, so Cognito always finds the matching account.
 * 4. User Logout (signOut): Ends the Cognito session.
 * =============================================================================
 */

import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserAttribute,
} from 'amazon-cognito-identity-js';

// AWS Cognito User Pool Configuration
const poolData = {
  UserPoolId: import.meta.env.VITE_COGNITO_USER_POOL_ID || 'ap-south-1_91Wy5nlpc',
  ClientId: import.meta.env.VITE_COGNITO_CLIENT_ID || 'fnjlnnuk6gaqmp07egrddt3uo',
};

export const userPool = new CognitoUserPool(poolData);

/**
 * Deterministically formats an email into a valid Cognito username.
 * Replaces '@' and '.' and other non-alphanumeric characters with '_'.
 * Because this is 100% deterministic (no random suffixes), the exact same
 * username is produced during BOTH signup and login!
 */
export function formatCognitoUsername(emailOrUsername) {
  if (!emailOrUsername) return '';
  const trimmed = emailOrUsername.trim().toLowerCase();
  // If it's an email address, sanitize '@' and '.' into '_'
  if (trimmed.includes('@')) {
    return trimmed.replace(/[^a-z0-9_+-]/g, '_');
  }
  return trimmed;
}

/**
 * Register a new user in AWS Cognito User Pool.
 * Sends the deterministic username and attaches the real email attribute.
 */
export function cognitoSignUp(email, password) {
  return new Promise((resolve, reject) => {
    const cleanEmail = email.trim();
    const username = formatCognitoUsername(cleanEmail);

    const attributeList = [
      new CognitoUserAttribute({
        Name: 'email',
        Value: cleanEmail,
      }),
    ];

    userPool.signUp(username, password, attributeList, null, (err, result) => {
      if (err) {
        return reject(err);
      }
      resolve({
        ...result,
        cognitoUsername: result?.user?.getUsername() || username,
      });
    });
  });
}

/**
 * Confirm a newly registered user account with the 6-digit email confirmation code.
 */
export function cognitoConfirmSignUp(emailOrUsername, code) {
  return new Promise((resolve, reject) => {
    const username = formatCognitoUsername(emailOrUsername);

    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: userPool,
    });

    cognitoUser.confirmRegistration(code.trim(), true, (err, result) => {
      if (err) {
        return reject(err);
      }
      resolve(result);
    });
  });
}

/**
 * Resend the 6-digit confirmation code to user's email.
 */
export function cognitoResendCode(emailOrUsername) {
  return new Promise((resolve, reject) => {
    const username = formatCognitoUsername(emailOrUsername);

    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: userPool,
    });

    cognitoUser.resendConfirmationCode((err, result) => {
      if (err) {
        return reject(err);
      }
      resolve(result);
    });
  });
}

/**
 * Authenticate (Sign In) user with email and password.
 * Converts the email to the exact same deterministic Cognito username used during signup.
 */
export function cognitoSignIn(emailOrUsername, password) {
  return new Promise((resolve, reject) => {
    const cleanInput = emailOrUsername.trim();
    const username = formatCognitoUsername(cleanInput);

    const authDetails = new AuthenticationDetails({
      Username: username,
      Password: password,
    });

    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: userPool,
    });

    cognitoUser.authenticateUser(authDetails, {
      onSuccess: (session) => {
        const accessToken = session.getAccessToken().getJwtToken();
        const idToken = session.getIdToken().getJwtToken();
        const idPayload = session.getIdToken().decodePayload();

        resolve({
          accessToken,
          idToken,
          email: idPayload.email || (cleanInput.includes('@') ? cleanInput : username),
          username: cognitoUser.getUsername(),
          sub: idPayload.sub,
        });
      },
      onFailure: (err) => {
        reject(err);
      },
      newPasswordRequired: (userAttributes, requiredAttributes) => {
        reject(new Error('New password required. Please reset your password.'));
      },
    });
  });
}

/**
 * Log out user from AWS Cognito.
 */
export function cognitoSignOut(emailOrUsername) {
  if (emailOrUsername) {
    const username = formatCognitoUsername(emailOrUsername);
    const cognitoUser = new CognitoUser({
      Username: username,
      Pool: userPool,
    });
    cognitoUser.signOut();
  }
}
