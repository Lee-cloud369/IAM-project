/**
 * =============================================================================
 * AETHER ARAN IAM - CENTRALIZED API SERVICE LAYER (WITH AUTH TOKEN INJECTION)
 * =============================================================================
 * Connects React frontend to FastAPI backend endpoints.
 * Automatically injects the in-memory Cognito JWT Bearer token on every request.
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

// IN-MEMORY TOKEN HOLDER (Never persisted in localStorage for security against XSS)
let inMemoryAuthToken = null;

/**
 * Updates the in-memory authentication token used for all API requests.
 */
export function setAuthToken(token) {
  inMemoryAuthToken = token;
}

/**
 * Retrieves the current active in-memory token.
 */
export function getAuthToken() {
  return inMemoryAuthToken;
}

/**
 * Helper to handle fetch requests with Bearer token injection and error reporting.
 */
async function request(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  // Inject Cognito Bearer token if present
  if (inMemoryAuthToken) {
    headers['Authorization'] = `Bearer ${inMemoryAuthToken}`;
  }

  const config = {
    ...options,
    headers,
  };

  try {
    const response = await fetch(url, config);
    if (!response.ok) {
      const errorBody = await response.text();
      let errorJson = null;
      try {
        errorJson = JSON.parse(errorBody);
      } catch (e) {
        // Not JSON
      }
      const errorMessage = errorJson?.error || errorJson?.detail || errorBody || response.statusText;
      const error = new Error(`API Error [${response.status}]: ${errorMessage}`);
      error.status = response.status;
      error.errorDetails = errorJson;
      throw error;
    }
    return await response.json();
  } catch (error) {
    console.warn(`Fetch error for ${endpoint}:`, error);
    throw error;
  }
}

/**
 * 0. GET /api/me
 * Retrieves current authenticated user profile from Cognito token
 */
export async function getCurrentUser() {
  return request('/api/me');
}

/**
 * 1. GET /api/privilege-escalation
 * CloudTrail IAM Risk telemetry and privilege escalation events
 */
export async function getPrivilegeEscalation() {
  return request('/api/privilege-escalation');
}

/**
 * 2. GET /api/drift-report
 * Least-privilege drift and unused permissions analysis
 */
export async function getDriftReport() {
  return request('/api/drift-report');
}

/**
 * 3. GET /api/credential-hygiene
 * MFA enrollment, access key rotation age, and root usage posture
 */
export async function getCredentialHygiene() {
  return request('/api/credential-hygiene');
}

/**
 * 4. POST /api/ai-chat
 * SentryAI / NIMORA assistant query with full security context
 */
export async function askAiAssistant(question) {
  return request('/api/ai-chat', {
    method: 'POST',
    body: JSON.stringify({ question }),
  });
}

/**
 * 5. GET /api/scan-history
 * DynamoDB historical scan findings audit trail
 */
export async function getScanHistory(limit = 50, scanType = null) {
  let query = `?limit=${limit}`;
  if (scanType) {
    query += `&scan_type=${encodeURIComponent(scanType)}`;
  }
  return request(`/api/scan-history${query}`);
}

/**
 * 6. POST /api/scan/initialize
 * Triggers full security audit and records findings in DynamoDB
 */
export async function initializeScan() {
  return request('/api/scan/initialize', {
    method: 'POST',
  });
}

/**
 * 7. GET /api/health
 * Backend health, module status, and database check
 */
export async function checkBackendHealth() {
  return request('/api/health');
}

/**
 * 8. POST /api/remediate/access-key
 * Safely deactivates an active AWS access key (Status='Inactive')
 */
export async function remediateAccessKey(username = null, accessKeyId = null, reason = null) {
  return request('/api/remediate/access-key', {
    method: 'POST',
    body: JSON.stringify({
      username: username || undefined,
      access_key_id: accessKeyId || undefined,
      reason: reason || undefined,
    }),
  });
}

/**
 * 9. POST /api/remediate/mfa-flag
 * Flags and logs compliance notification for users without MFA
 */
export async function remediateMfaFlag(username = null, flagAll = false) {
  return request('/api/remediate/mfa-flag', {
    method: 'POST',
    body: JSON.stringify({
      username: username || undefined,
      flag_all: flagAll,
    }),
  });
}

/**
 * 10. POST /api/remediate/drift
 * Remediates least-privilege drift for a specific permission
 */
export async function remediateDrift(username, policy = null, service = null) {
  return request('/api/remediate/drift', {
    method: 'POST',
    body: JSON.stringify({
      username,
      policy: policy || undefined,
      service: service || undefined,
    }),
  });
}

/**
 * 11. POST /api/remediate/drift-all
 * Batch remediates all detected least-privilege drift records
 */
export async function remediateAllDrift(items = []) {
  return request('/api/remediate/drift-all', {
    method: 'POST',
    body: JSON.stringify({
      items,
    }),
  });
}

export default {
  setAuthToken,
  getAuthToken,
  getCurrentUser,
  getPrivilegeEscalation,
  getDriftReport,
  getCredentialHygiene,
  getScanHistory,
  initializeScan,
  askAiAssistant,
  checkBackendHealth,
  remediateAccessKey,
  remediateMfaFlag,
  remediateDrift,
  remediateAllDrift,
};
