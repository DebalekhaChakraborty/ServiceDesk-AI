'use strict';

const express = require('express');
const { landingPage } = require('../views/landing');
const { workspacePage } = require('../views/workspace');

/**
 * The employee-facing pages.
 */
function portalRoutes({ config, sessions }) {
  const router = express.Router();

  function sendHtml(res, status, html) {
    res.status(status).type('html').send(html);
  }

  // Public landing page. An already-authenticated employee goes straight in.
  router.get('/', (req, res) => {
    if (sessions.getSession(req)) {
      return res.redirect(302, '/workspace');
    }
    return sendHtml(res, 200, landingPage());
  });

  // Protected workspace.
  //
  // The only accepted proof of identity is the server-sealed session cookie.
  // Anything the client supplies directly - query parameters, form fields,
  // headers, a hand-written cookie - cannot produce an authenticated render,
  // because a session that does not decrypt under the server key is discarded.
  router.get('/workspace', (req, res) => {
    const session = sessions.getSession(req);
    if (!session) {
      return res.redirect(302, '/auth/signin');
    }
    return sendHtml(
      res,
      200,
      workspacePage({ voiceEnabled: Boolean(config?.voice?.enabled), session, csrfToken: session.csrf }),
    );
  });

  return router;
}

module.exports = { portalRoutes };
