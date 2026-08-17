'use strict';

const express = require('express');
const { safeEquals } = require('../session');
const { log } = require('../logger');
const { mintVoiceIdentityToken, newCallId } = require('../voiceIdentity');

/**
 * Voice channel bootstrap.
 *
 * The browser gets exactly two things it could not forge: a fresh call id and
 * a short-lived assertion signed with a secret it never sees. It does NOT get
 * a UPN it can edit — or rather, it may well know its own UPN, but nothing
 * downstream believes a UPN that is not inside the signature.
 *
 * Requires a valid portal session, so an unauthenticated visitor cannot mint
 * an assertion at all.
 */
function voiceRoutes({ config, sessions }) {
  const router = express.Router();

  function requireSessionWithCsrf(req, res) {
    const session = sessions.getSession(req);
    if (!session) return null;
    const submitted = typeof req.body?.csrf_token === 'string' ? req.body.csrf_token : '';
    if (!safeEquals(submitted, session.csrf)) {
      log('csrf_rejected', { path: req.path });
      return null;
    }
    return session;
  }

  /**
   * Start a voice call. One call id and one assertion per press.
   *
   * Deliberately a POST with CSRF: minting is a state-creating action, and a
   * GET would be triggerable cross-site and cacheable.
   */
  router.post('/voice/session', express.urlencoded({ extended: false, limit: '8kb' }), (req, res) => {
    const session = requireSessionWithCsrf(req, res);
    if (!session) {
      return res.status(401).json({ error: 'authentication_required' });
    }
    if (!config.voice?.enabled) {
      return res.status(503).json({ error: 'voice_channel_unavailable' });
    }

    let minted;
    try {
      minted = mintVoiceIdentityToken({
        // Identity comes from the SEALED SESSION, never from the request body.
        identity: session,
        callId: newCallId(),
        secret: config.voice.signingSecret,
        ttlSeconds: config.voice.tokenTtlSeconds,
      });
    } catch (error) {
      // A misconfigured secret must not look like a caller error.
      log('voice_token_mint_failed', { code: 'mint_failed' });
      return res.status(503).json({ error: 'voice_channel_unavailable' });
    }

    log('voice_session_started', { ttl_seconds: config.voice.tokenTtlSeconds });

    // The embed token is public by design (the widget ships it to Dograh), but
    // it is only usable from the allowed origin configured on the token.
    return res.json({
      call_id: minted.callId,
      voice_identity_token: minted.token,
      expires_at: minted.expiresAt,
      embed_token: config.voice.embedToken,
      embed_origin: config.voice.embedOrigin,
      // The widget builds its script URL from this. Omitting it silently
      // produced `apiEndpoint=undefined`, which is why the authenticated voice
      // path failed while /recovery — which always returned it — worked.
      api_endpoint: config.voice.apiEndpoint,
    });
  });

  return router;
}

module.exports = { voiceRoutes };
