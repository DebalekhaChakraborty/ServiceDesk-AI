'use strict';

/**
 * Microsoft Entra ID authentication, and nothing else.
 *
 * This module performs the OIDC authorization code flow (with PKCE) against a
 * single tenant using Microsoft's supported MSAL Node library. It exists purely
 * to answer one question: "will Microsoft Entra authenticate this employee
 * right now?"
 *
 * It deliberately does NOT talk to Microsoft Graph. The portal never reads,
 * creates, enables, disables, or otherwise mutates a directory object. Account
 * remediation is the sole responsibility of the existing ServiceDesk AI
 * backend, which holds its own separately governed Graph application identity.
 */

const crypto = require('node:crypto');
const { ConfidentialClientApplication, CryptoProvider, LogLevel } = require('@azure/msal-node');

/**
 * Build the Entra client used by the routes.
 *
 * @param {object} config validated configuration from config.js
 */
function createEntraClient(config) {
  const msalApp = new ConfidentialClientApplication({
    auth: {
      clientId: config.clientId,
      authority: config.authority, // tenant-specific; never common/organizations/consumers
      clientSecret: config.clientSecret,
    },
    system: {
      loggerOptions: {
        // MSAL logging is silenced: its verbose channels can contain tokens.
        loggerCallback: () => {},
        piiLoggingEnabled: false,
        logLevel: LogLevel.Error,
      },
    },
  });

  const cryptoProvider = new CryptoProvider();

  /**
   * Drop every cached token immediately after use. The portal has no reason to
   * retain an ID, access, or refresh token beyond the moment it reads the
   * authenticated identity out of the ID token claims.
   *
   * This matters because MSAL Node always appends `offline_access` to an
   * authorization code request, so Microsoft returns a refresh token whether
   * the portal wants one or not. It is never persisted, never sent to the
   * browser, and is destroyed here within the same request.
   */
  async function purgeTokenCache() {
    try {
      const cache = msalApp.getTokenCache();
      const accounts = await cache.getAllAccounts();
      await Promise.all(accounts.map((account) => cache.removeAccount(account)));
    } catch {
      // Cache hygiene is best-effort and must never fail a request.
    }
  }

  return {
    /**
     * Start an authorization request.
     *
     * @param {{prompt?: string}} options `prompt: 'login'` forces Microsoft to
     *   re-authenticate rather than silently reusing an existing Microsoft
     *   session. This is what makes "Verify Corporate Access" a genuine
     *   re-evaluation of the account.
     * @returns {Promise<{url: string, state: string, nonce: string, codeVerifier: string}>}
     */
    async createAuthorizationRequest({ prompt } = {}) {
      const state = crypto.randomBytes(32).toString('base64url');
      const nonce = crypto.randomBytes(32).toString('base64url');
      const { verifier, challenge } = await cryptoProvider.generatePkceCodes();

      const url = await msalApp.getAuthCodeUrl({
        scopes: [...config.scopes], // openid, profile, email only
        redirectUri: config.redirectUri,
        responseMode: 'query',
        state,
        nonce,
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
        ...(prompt ? { prompt } : {}),
      });

      return { url, state, nonce, codeVerifier: verifier };
    },

    /**
     * Redeem an authorization code and return only safe display claims.
     *
     * Throws if Microsoft does not return a usable, nonce-matching ID token.
     * The caller treats any throw as "authentication did not succeed".
     */
    async redeemAuthorizationCode({ code, codeVerifier, expectedNonce }) {
      let response;
      try {
        response = await msalApp.acquireTokenByCode({
          code,
          codeVerifier,
          scopes: [...config.scopes],
          redirectUri: config.redirectUri,
        });
      } finally {
        await purgeTokenCache();
      }

      const claims = response?.idTokenClaims;
      if (!claims || typeof claims !== 'object') {
        throw new Error('id_token_missing');
      }

      // Replay protection: the ID token must carry back the exact nonce that
      // this browser's authorization request generated.
      if (typeof claims.nonce !== 'string' || claims.nonce !== expectedNonce) {
        throw new Error('nonce_mismatch');
      }

      // Single-tenant enforcement, re-checked on the token itself rather than
      // trusted from the request.
      if (claims.tid !== config.tenantId) {
        throw new Error('tenant_mismatch');
      }

      const username =
        response.account?.username || claims.preferred_username || claims.upn || claims.email || null;
      if (!username) {
        throw new Error('username_missing');
      }

      return {
        displayName: response.account?.name || claims.name || username,
        username,
        tenantId: claims.tid,
        objectId: claims.oid || response.account?.homeAccountId || null,
        authenticatedAt: new Date().toISOString(),
      };
      // Note: `response` (containing the tokens) goes out of scope here and is
      // never persisted, logged, or sent to the browser.
    },
  };
}

module.exports = { createEntraClient };
