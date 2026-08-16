'use strict';

/**
 * Short-lived signed identity assertions for the voice channel.
 *
 * The portal is the only component that knows who the employee is: it has just
 * completed an Entra authorization-code flow and holds a sealed session. The
 * voice gateway has no way to repeat that check, so the portal vouches for the
 * employee with an HMAC-signed assertion that the gateway can verify offline.
 *
 * Constraints this file exists to enforce:
 *   - signing happens SERVER-SIDE only; the secret never reaches page script
 *   - the assertion is bound to ONE call id, so it cannot be replayed into
 *     another call inside its lifetime
 *   - the lifetime is minutes, not hours
 *   - the signing key is dedicated: it is not the Entra client secret, the
 *     Graph secret, the TURN secret, the Dograh API key, or PORTAL_SESSION_SECRET
 *
 * Wire format matches dograh_voice/voice_gateway/identity.py exactly:
 *     base64url(header) "." base64url(payload) "." base64url(HMAC-SHA256)
 */

const crypto = require('node:crypto');

const AUDIENCE = 'servicedesk-voice-gateway';
const TOKEN_VERSION = 1;
const ALGORITHM = 'HS256';
const DEFAULT_TTL_SECONDS = 300; // 5 minutes
const MAX_TTL_SECONDS = 15 * 60;

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/**
 * A fresh, unguessable call id. One per voice call, never reused.
 */
function newCallId() {
  return `voice_${crypto.randomBytes(18).toString('base64url')}`;
}

/**
 * Mint an assertion for an already-authenticated employee.
 *
 * `identity` must come from the sealed portal session, never from a request
 * body or query string.
 */
function mintVoiceIdentityToken({ identity, callId, secret, ttlSeconds = DEFAULT_TTL_SECONDS, now = Date.now() }) {
  if (!identity || typeof identity.username !== 'string' || identity.username.length === 0) {
    throw new Error('authenticated identity required');
  }
  if (typeof callId !== 'string' || callId.length === 0) {
    throw new Error('callId required');
  }
  if (typeof secret !== 'string' || secret.length < 32) {
    throw new Error('voice signing secret missing or too short');
  }
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
    throw new Error('invalid ttl');
  }

  const issued = Math.floor(now / 1000);
  const payload = {
    ver: TOKEN_VERSION,
    call_id: callId,
    upn: identity.username,
    iat: issued,
    exp: issued + ttlSeconds,
    aud: AUDIENCE,
  };
  // Optional display claims. Signed, therefore trustworthy downstream; the
  // gateway maps them onto the persona that identity_context_tool consumes.
  if (identity.displayName) payload.name = identity.displayName;
  if (identity.objectId) payload.oid = identity.objectId;

  // Keys must be sorted to match the Python side byte-for-byte.
  const header = { alg: ALGORITHM, typ: 'JWT' };
  const signingInput = `${b64url(JSON.stringify(sortKeys(header)))}.${b64url(JSON.stringify(sortKeys(payload)))}`;
  const signature = b64url(crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(signingInput).digest());
  return { token: `${signingInput}.${signature}`, expiresAt: payload.exp, callId };
}

/**
 * JSON.stringify with deterministic key order, so both implementations produce
 * identical signing input.
 */
function sortKeys(obj) {
  return Object.keys(obj)
    .sort()
    .reduce((acc, key) => {
      acc[key] = obj[key];
      return acc;
    }, {});
}

/**
 * Mint a bootstrap for an UNAUTHENTICATED recovery call.
 *
 * The critical difference from mintVoiceIdentityToken: this carries NO `upn`
 * claim. The caller has not proved anything yet. `claimed_upn_hint` is signed
 * only so it cannot be swapped part-way through a call - never so it can be
 * believed. Identity is established later by TOTP, from the enrollment record.
 */
function mintRecoveryBootstrap({ callId, claimedUpn, secret, ttlSeconds = DEFAULT_TTL_SECONDS, now = Date.now() }) {
  if (typeof callId !== 'string' || callId.length === 0) throw new Error('callId required');
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('voice signing secret missing or too short');
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) throw new Error('invalid ttl');

  const issued = Math.floor(now / 1000);
  const payload = {
    ver: TOKEN_VERSION,
    call_id: callId,
    purpose: 'account_recovery',
    iat: issued,
    exp: issued + ttlSeconds,
    aud: AUDIENCE,
  };
  if (claimedUpn) payload.claimed_upn_hint = claimedUpn;

  const header = { alg: ALGORITHM, typ: 'JWT' };
  const signingInput = `${b64url(JSON.stringify(sortKeys(header)))}.${b64url(JSON.stringify(sortKeys(payload)))}`;
  const signature = b64url(crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(signingInput).digest());
  return { token: `${signingInput}.${signature}`, expiresAt: payload.exp, callId };
}

module.exports = { mintVoiceIdentityToken, mintRecoveryBootstrap, newCallId, AUDIENCE, DEFAULT_TTL_SECONDS };
