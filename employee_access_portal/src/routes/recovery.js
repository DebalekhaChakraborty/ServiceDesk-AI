'use strict';

const express = require('express');
const { safeEquals } = require('../session');
const { log } = require('../logger');
const { mintRecoveryBootstrap, newCallId } = require('../voiceIdentity');
const { enrollPage, recoveryPage } = require('../views/recovery');

/**
 * Account recovery: Duo enrollment (authenticated) and the public entry point.
 *
 * Two very different trust levels live in this file, so the split is explicit:
 *
 *   /recovery/enroll  requires a live Entra session. The tenant id, object id
 *                     and UPN all come from the sealed session and are matched
 *                     against the existing identity-map row by the gateway, so
 *                     nobody can enroll a Duo credential against a colleague.
 *
 *   /recovery         is PUBLIC by necessity - a disabled employee cannot sign
 *                     in. It now sends NOTHING identifying at all: the caller
 *                     states an employee ID by voice instead, which removes the
 *                     last place this page could have leaked whether an account
 *                     exists.
 *
 * The portal never sees a Duo secret, a Duo user id, or a passcode. It relays
 * an activation QR that the gateway fetched, and nothing else.
 */
function recoveryRoutes({ config, sessions }) {
  const router = express.Router();
  const form = express.urlencoded({ extended: false, limit: '8kb' });

  const gateway = config.recovery?.gatewayUrl;
  const adminKey = config.recovery?.adminKey;

  function enabled() {
    return Boolean(config.voice?.enabled && gateway && adminKey);
  }

  async function callGateway(path, body, withAdmin) {
    const headers = { 'Content-Type': 'application/json' };
    if (withAdmin) headers['X-Recovery-Admin-Key'] = adminKey;
    const response = await fetch(`${gateway}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
    return { status: response.status, body: await response.json().catch(() => ({})) };
  }

  function requireSession(req) {
    return sessions.getSession(req);
  }

  function csrfOk(req, session) {
    return safeEquals(
      typeof req.body?.csrf_token === 'string' ? req.body.csrf_token : '',
      session.csrf,
    );
  }

  /**
   * The identity sent to the gateway. Every field is read from the sealed
   * session; there is deliberately no path by which a form field reaches here.
   */
  function sessionIdentity(session) {
    return {
      tenant_id: session.tenantId,
      object_id: session.objectId,
      upn: session.username,
    };
  }

  // --- Duo enrollment (authenticated) --------------------------------------

  router.get('/recovery/enroll', (req, res) => {
    const session = requireSession(req);
    if (!session) return res.redirect(302, '/');
    if (!enabled()) return res.status(503).type('html').send(enrollPage({ session, unavailable: true }));
    return res.type('html').send(enrollPage({ session, csrfToken: session.csrf }));
  });

  router.post('/recovery/enroll/begin', form, async (req, res) => {
    const session = requireSession(req);
    if (!session || !csrfOk(req, session)) return res.redirect(302, '/');
    if (!enabled()) return res.redirect(303, '/recovery/enroll');

    const result = await callGateway('/recovery/enroll/duo/begin', sessionIdentity(session), true);

    if (result.status !== 200) {
      log('recovery_enroll_begin_failed', { status: result.status });
      return res.status(result.status === 404 ? 404 : 502).type('html').send(
        enrollPage({ session, unavailable: true, notMapped: result.status === 404 }),
      );
    }
    log('recovery_enroll_begin', { status: 'pending' });

    // PENDING only. Showing the QR proves nothing; the employee must actually
    // activate Duo Mobile, and only Duo can confirm that.
    return res.type('html').send(enrollPage({
      session,
      csrfToken: session.csrf,
      qrDataUri: result.body.qr_data_uri,
      activationCode: result.body.activation_code,
    }));
  });

  router.post('/recovery/enroll/confirm', form, async (req, res) => {
    const session = requireSession(req);
    if (!session || !csrfOk(req, session)) return res.redirect(302, '/');
    if (!enabled()) return res.redirect(303, '/recovery/enroll');

    const result = await callGateway('/recovery/enroll/duo/status', sessionIdentity(session), true);
    const status = result.status === 200 ? result.body.status : 'invalid';
    log('recovery_enroll_confirm', { result: status });

    return res.type('html').send(enrollPage({
      session,
      csrfToken: session.csrf,
      confirmed: status === 'active',
      stillWaiting: status === 'waiting',
      confirmFailed: status === 'invalid',
    }));
  });

  // --- Public recovery entry ----------------------------------------------

  router.get('/recovery', (req, res) => {
    if (!enabled()) return res.status(503).type('html').send(recoveryPage({ unavailable: true }));
    return res.type('html').send(recoveryPage({}));
  });

  router.post('/recovery/start', form, async (req, res) => {
    if (!enabled()) return res.status(503).json({ error: 'recovery_unavailable' });

    // No identifier is accepted here. Anything a visitor manages to post is
    // ignored rather than forwarded, so this endpoint cannot be probed.
    const callId = newCallId();
    let minted;
    try {
      minted = mintRecoveryBootstrap({
        callId,
        secret: config.voice.signingSecret,
        ttlSeconds: config.voice.tokenTtlSeconds,
      });
    } catch {
      return res.status(503).json({ error: 'recovery_unavailable' });
    }

    const started = await callGateway('/recovery/start', {
      call_id: callId,
      recovery_token: minted.token,
    }, false);

    if (started.status !== 200) {
      log('recovery_start_failed', { status: started.status });
      return res.status(503).json({ error: 'recovery_unavailable' });
    }
    log('recovery_start', {});
    return res.json({
      call_id: callId,
      voice_identity_token: minted.token,
      embed_token: config.voice.embedToken,
      embed_origin: config.voice.embedOrigin,
      api_endpoint: config.voice.apiEndpoint,
    });
  });

  return router;
}

module.exports = { recoveryRoutes };
