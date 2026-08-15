'use strict';

/**
 * Environment-driven configuration for the Employee Access Portal.
 *
 * Every value comes from the environment. Nothing is read from disk, and no
 * credential is ever defaulted to a literal in this repository.
 */

const REQUIRED_VARS = [
  'ENTRA_PORTAL_TENANT_ID',
  'ENTRA_PORTAL_CLIENT_ID',
  'ENTRA_PORTAL_CLIENT_SECRET',
  'PORTAL_BASE_URL',
  'PORTAL_SESSION_SECRET',
];

// Multi-tenant / consumer authorities are refused: this portal authenticates a
// single corporate directory only.
const REJECTED_TENANTS = new Set(['common', 'organizations', 'consumers']);

// Authentication-only scopes. The portal never requests an administrative
// Microsoft Graph permission; it does not read or write directory objects.
const AUTH_SCOPES = Object.freeze(['openid', 'profile', 'email']);

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes, bounded.
const AUTH_TXN_TTL_MS = 10 * 60 * 1000; // Authorization request must complete quickly.

const MIN_SESSION_SECRET_LENGTH = 32;

function required(env, name) {
  return String(env[name] || '').trim();
}

/**
 * Build the validated runtime configuration.
 *
 * @param {NodeJS.ProcessEnv} env
 * @returns {Readonly<object>}
 * @throws {Error} when configuration is missing or unsafe. The message never
 *   contains a secret value, only the variable name.
 */
function loadConfig(env = process.env) {
  const missing = REQUIRED_VARS.filter((name) => !required(env, name));
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variable(s): ${missing.join(', ')}. ` +
        'See .env.example for the expected configuration.',
    );
  }

  const tenantId = required(env, 'ENTRA_PORTAL_TENANT_ID');
  if (REJECTED_TENANTS.has(tenantId.toLowerCase())) {
    throw new Error(
      `ENTRA_PORTAL_TENANT_ID must be a single tenant id; "${tenantId}" is a ` +
        'multi-tenant authority and is not allowed by this portal.',
    );
  }

  const baseUrlRaw = required(env, 'PORTAL_BASE_URL').replace(/\/+$/, '');
  let baseUrl;
  try {
    baseUrl = new URL(baseUrlRaw);
  } catch {
    throw new Error(
      'PORTAL_BASE_URL must be an absolute https URL with no trailing slash. ' +
        'http://localhost:8080 is accepted for local development.',
    );
  }
  if (baseUrl.protocol !== 'https:' && baseUrl.hostname !== 'localhost' && baseUrl.hostname !== '127.0.0.1') {
    throw new Error('PORTAL_BASE_URL must use https except for localhost development.');
  }

  const sessionSecret = String(env.PORTAL_SESSION_SECRET || '');
  if (sessionSecret.length < MIN_SESSION_SECRET_LENGTH) {
    throw new Error(
      `PORTAL_SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LENGTH} characters. ` +
        'Generate one with: openssl rand -base64 48',
    );
  }

  const origin = baseUrlRaw;
  // https origin implies a real deployment: cookies are marked Secure there.
  const secureCookies = baseUrl.protocol === 'https:';

  return Object.freeze({
    tenantId,
    clientId: required(env, 'ENTRA_PORTAL_CLIENT_ID'),
    clientSecret: String(env.ENTRA_PORTAL_CLIENT_SECRET),
    authority: `https://login.microsoftonline.com/${tenantId}`,
    baseUrl: origin,
    redirectUri: `${origin}/auth/redirect`,
    postLogoutRedirectUri: origin,
    scopes: AUTH_SCOPES,
    sessionSecret,
    secureCookies,
    port: Number(env.PORT || 8080),
    sessionTtlMs: SESSION_TTL_MS,
    authTxnTtlMs: AUTH_TXN_TTL_MS,
  });
}

module.exports = {
  loadConfig,
  AUTH_SCOPES,
  REQUIRED_VARS,
  SESSION_TTL_MS,
  AUTH_TXN_TTL_MS,
};
