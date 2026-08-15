'use strict';

const express = require('express');
const { safeEquals } = require('../session');
const { log, sanitizeCode } = require('../logger');
const { authErrorPage } = require('../views/authError');

/**
 * Microsoft Entra authentication routes.
 *
 * Nothing in this file administers a user. The portal asks Entra to
 * authenticate the employee and believes only the answer it gets back.
 */
function authRoutes({ sessions, entra }) {
  const router = express.Router();

  function renderAuthError(res, status, code) {
    res.status(status).type('html').send(authErrorPage({ code: sanitizeCode(code) }));
  }

  /**
   * Create a fresh authorization request and hand the browser to Microsoft.
   *
   * A new state, nonce and PKCE verifier are generated every time and sealed
   * into a short-lived transaction cookie; they are never reused between
   * attempts.
   */
  async function beginAuthorization(res, { prompt, reason }) {
    const request = await entra.createAuthorizationRequest({ prompt });
    sessions.setAuthTransaction(res, {
      state: request.state,
      nonce: request.nonce,
      codeVerifier: request.codeVerifier,
    });
    log('authorization_request_started', { reason, prompt: prompt || 'default' });
    return res.redirect(302, request.url);
  }

  /**
   * Require a valid session plus a matching CSRF token for state-changing POSTs.
   */
  function requireSessionWithCsrf(req, res, next) {
    const session = sessions.getSession(req);
    if (!session) {
      return res.redirect(302, '/');
    }
    const submitted = typeof req.body?.csrf_token === 'string' ? req.body.csrf_token : '';
    if (!safeEquals(submitted, session.csrf)) {
      log('csrf_rejected', { path: req.path });
      sessions.clearSession(res);
      return res.status(403).type('html').send(authErrorPage({ code: 'invalid_request' }));
    }
    req.portalSession = session;
    return next();
  }

  // --- Sign in -------------------------------------------------------------

  router.get('/auth/signin', async (req, res, next) => {
    try {
      await beginAuthorization(res, { reason: 'signin' });
    } catch (error) {
      next(error);
    }
  });

  // --- Verify Corporate Access ---------------------------------------------

  /**
   * The demonstration's critical route.
   *
   * It discards the portal's own authenticated state and forces Microsoft
   * Entra to authenticate the employee again with `prompt=login`, so the
   * result reflects the account's CURRENT directory state rather than a
   * session established earlier. The portal makes no account-status call of
   * its own: Entra alone decides whether authentication succeeds.
   */
  router.post('/auth/verify', requireSessionWithCsrf, async (req, res, next) => {
    try {
      sessions.clearSession(res);
      sessions.clearAuthTransaction(res);
      await beginAuthorization(res, { prompt: 'login', reason: 'verify_corporate_access' });
    } catch (error) {
      next(error);
    }
  });

  // --- Sign out ------------------------------------------------------------

  router.post('/auth/signout', requireSessionWithCsrf, (req, res) => {
    sessions.clearSession(res);
    sessions.clearAuthTransaction(res);
    log('session_cleared', { reason: 'signout' });
    return res.redirect(303, '/');
  });

  // --- Authorization response ----------------------------------------------

  async function handleAuthorizationResponse(req, res, next) {
    // `query` response mode is what this portal configures, so the callback
    // normally arrives as a top-level GET. The POST form is accepted too for
    // tenants configured with form_post.
    const params = req.method === 'POST' ? req.body || {} : req.query || {};

    const transaction = sessions.getAuthTransaction(req);
    // The transaction is single-use regardless of the outcome.
    sessions.clearAuthTransaction(res);

    // 1. Microsoft reported a failure (for example a disabled account being
    //    refused). Report only what Microsoft actually said.
    const providerError = typeof params.error === 'string' ? params.error : null;
    if (providerError) {
      sessions.clearSession(res);
      const code = sanitizeCode(providerError);
      log('authentication_failed', { source: 'entra', code: code || 'unrecognized' });
      return res.redirect(303, code ? `/auth/error?code=${encodeURIComponent(code)}` : '/auth/error');
    }

    // 2. No in-flight transaction: expired, already used, or never started here.
    if (!transaction) {
      sessions.clearSession(res);
      log('authentication_failed', { source: 'portal', code: 'no_auth_transaction' });
      return renderAuthError(res, 400, 'no_auth_transaction');
    }

    // 3. State must match the value this browser's request generated (CSRF /
    //    authorization-response injection defence).
    const returnedState = typeof params.state === 'string' ? params.state : '';
    if (!safeEquals(returnedState, transaction.state)) {
      sessions.clearSession(res);
      log('authentication_failed', { source: 'portal', code: 'state_mismatch' });
      return renderAuthError(res, 400, 'state_mismatch');
    }

    // 4. An authorization code is mandatory.
    const code = typeof params.code === 'string' ? params.code.trim() : '';
    if (!code) {
      sessions.clearSession(res);
      log('authentication_failed', { source: 'portal', code: 'code_missing' });
      return renderAuthError(res, 400, 'code_missing');
    }

    // 5. Redeem, validating the nonce and tenant on the returned ID token.
    let identity;
    try {
      identity = await entra.redeemAuthorizationCode({
        code,
        codeVerifier: transaction.codeVerifier,
        expectedNonce: transaction.nonce,
      });
    } catch (error) {
      sessions.clearSession(res);
      // Only a sanitized reason is logged; the failed response is not.
      log('authentication_failed', {
        source: 'token_redemption',
        code: sanitizeCode(error?.errorCode) || sanitizeCode(error?.message) || 'redemption_failed',
      });
      return renderAuthError(res, 401, 'authentication_failed');
    }

    sessions.setSession(res, identity);
    log('authentication_succeeded', { tenant_matched: true });
    return res.redirect(302, '/workspace');
  }

  router.get('/auth/redirect', (req, res, next) => {
    handleAuthorizationResponse(req, res, next).catch(next);
  });
  router.post('/auth/redirect', (req, res, next) => {
    handleAuthorizationResponse(req, res, next).catch(next);
  });

  // --- Friendly failure page ------------------------------------------------

  router.get('/auth/error', (req, res) => {
    renderAuthError(res, 200, typeof req.query?.code === 'string' ? req.query.code : null);
  });

  return router;
}

module.exports = { authRoutes };
