'use strict';

/**
 * Stateless, tamper-proof cookie sessions.
 *
 * The portal runs on Cloud Run, where any instance may serve any request and
 * instances are recycled freely. There is therefore no server-side session
 * store: session state travels in an AES-256-GCM sealed cookie whose key is
 * derived from PORTAL_SESSION_SECRET. A restart or scale-out never invalidates
 * a legitimate session, and a forged or edited cookie never decrypts.
 *
 * Two independent keys are derived from the same secret so that a session
 * cookie can never be replayed as an in-flight authorization transaction.
 */

const crypto = require('node:crypto');

const SESSION_COOKIE = 'eap_session';
const AUTH_TXN_COOKIE = 'eap_auth_txn';

const KEY_LENGTH = 32; // AES-256
const IV_LENGTH = 12; // GCM standard nonce length
const TAG_LENGTH = 16;
const HKDF_SALT = 'employee-access-portal/v1';

function deriveKey(secret, purpose) {
  return Buffer.from(
    crypto.hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from(HKDF_SALT, 'utf8'), Buffer.from(purpose, 'utf8'), KEY_LENGTH),
  );
}

/**
 * Encrypt a JSON-serialisable payload into a URL-safe opaque string.
 */
function seal(payload, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
}

/**
 * Decrypt a sealed string. Returns null for anything that is missing, corrupt,
 * forged, or past its embedded expiry. Never throws on attacker-controlled input.
 */
function unseal(token, key, now = Date.now()) {
  if (typeof token !== 'string' || token.length === 0) return null;
  let raw;
  try {
    raw = Buffer.from(token, 'base64url');
  } catch {
    return null;
  }
  if (raw.length <= IV_LENGTH + TAG_LENGTH) return null;

  try {
    const iv = raw.subarray(0, IV_LENGTH);
    const tag = raw.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const ciphertext = raw.subarray(IV_LENGTH + TAG_LENGTH);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const payload = JSON.parse(plaintext.toString('utf8'));
    if (!payload || typeof payload !== 'object') return null;
    // Expiry is enforced from inside the sealed payload, not from the cookie
    // Max-Age, which a client controls.
    if (typeof payload.exp !== 'number' || payload.exp <= now) return null;
    return payload;
  } catch {
    return null;
  }
}

/**
 * Constant-time comparison of two untrusted strings.
 */
function safeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Build the session helpers bound to one configuration.
 */
function createSessionManager(config) {
  const sessionKey = deriveKey(config.sessionSecret, 'session');
  const txnKey = deriveKey(config.sessionSecret, 'auth-transaction');

  function cookieOptions(maxAgeMs) {
    return {
      httpOnly: true, // never readable by page script
      secure: config.secureCookies, // always true on the https Cloud Run origin
      // Lax is the strictest value compatible with returning from the Microsoft
      // login page via a top-level GET navigation.
      sameSite: 'lax',
      path: '/',
      maxAge: maxAgeMs,
    };
  }

  return {
    SESSION_COOKIE,
    AUTH_TXN_COOKIE,

    /**
     * Persist the authenticated identity. Only safe display claims are stored;
     * no access token, ID token, or refresh token is ever placed in a cookie.
     */
    setSession(res, identity) {
      const now = Date.now();
      const payload = {
        displayName: identity.displayName,
        username: identity.username,
        tenantId: identity.tenantId,
        objectId: identity.objectId,
        authenticatedAt: identity.authenticatedAt,
        csrf: randomToken(24),
        iat: now,
        exp: now + config.sessionTtlMs,
      };
      res.cookie(SESSION_COOKIE, seal(payload, sessionKey), cookieOptions(config.sessionTtlMs));
      return payload;
    },

    getSession(req, now = Date.now()) {
      return unseal(req.cookies?.[SESSION_COOKIE], sessionKey, now);
    },

    clearSession(res) {
      res.clearCookie(SESSION_COOKIE, { ...cookieOptions(0), maxAge: undefined });
    },

    /**
     * Store the in-flight authorization request (state, nonce, PKCE verifier)
     * for validation when Microsoft redirects the browser back.
     */
    setAuthTransaction(res, txn) {
      const now = Date.now();
      const payload = { ...txn, iat: now, exp: now + config.authTxnTtlMs };
      res.cookie(AUTH_TXN_COOKIE, seal(payload, txnKey), cookieOptions(config.authTxnTtlMs));
      return payload;
    },

    getAuthTransaction(req, now = Date.now()) {
      return unseal(req.cookies?.[AUTH_TXN_COOKIE], txnKey, now);
    },

    clearAuthTransaction(res) {
      res.clearCookie(AUTH_TXN_COOKIE, { ...cookieOptions(0), maxAge: undefined });
    },
  };
}

module.exports = {
  createSessionManager,
  safeEquals,
  randomToken,
  seal,
  unseal,
  deriveKey,
  SESSION_COOKIE,
  AUTH_TXN_COOKIE,
};
