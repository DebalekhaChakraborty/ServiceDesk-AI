'use strict';

const path = require('node:path');
const express = require('express');
const cookieParser = require('cookie-parser');

const { loadConfig } = require('./config');
const { createSessionManager } = require('./session');
const { createEntraClient } = require('./entra');
const { requestLogger, log } = require('./logger');
const { healthRoutes } = require('./routes/health');
const { authRoutes } = require('./routes/auth');
const { voiceRoutes } = require('./routes/voice');
const { recoveryRoutes } = require('./routes/recovery');
const { portalRoutes } = require('./routes/portal');
const { authErrorPage } = require('./views/authError');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

/**
 * Response headers applied to every route.
 *
 * The portal was written with NO client-side JavaScript, so `default-src 'none'`
 * cost nothing and removed an entire class of token-stealing bugs.
 *
 * The Dograh voice widget breaks that assumption: it is third-party script
 * running on an authenticated page that holds a session cookie. The allowances
 * below are therefore the narrowest that let the widget work, and they are only
 * emitted when the voice channel is actually configured — a portal without
 * voice keeps the original `default-src 'none'` policy byte-for-byte.
 *
 * Specifically NOT used: wildcards of any kind, 'unsafe-eval', and
 * 'unsafe-inline' for scripts. The bootstrap is served from /voice-widget.js as
 * a same-origin file precisely so no inline script is needed.
 *
 * The session cookie stays httpOnly, so widget script cannot read it even
 * though it shares the page.
 */
function securityHeaders(config) {
  const voice = config.voice?.enabled ? config.voice : null;

  // Exact origins parsed from configuration; never interpolated user input.
  const widgetOrigin = voice ? new URL(voice.embedOrigin).origin : null;
  const apiOrigin = voice ? new URL(voice.apiEndpoint).origin : null;
  const wsOrigin = apiOrigin ? apiOrigin.replace(/^http/, 'ws') : null;

  const directives = {
    'default-src': ["'none'"],
    'style-src': ["'self'"],
    'img-src': ["'self'", 'data:'],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
    'base-uri': ["'none'"],
  };

  if (voice) {
    // Widget bootstrap is same-origin; the widget itself comes from Dograh.
    directives['script-src'] = ["'self'", widgetOrigin];
    // Embed init + signalling. WebRTC media itself is not governed by CSP.
    directives['connect-src'] = ["'self'", apiOrigin, wsOrigin];
    // Remote audio arrives as a MediaStream/blob, not a network fetch.
    directives['media-src'] = ["'self'", 'blob:'];
    directives['worker-src'] = ["'self'", 'blob:'];
    // The widget injects its own UI; allow its stylesheet, still no wildcard.
    directives['style-src'] = ["'self'", "'unsafe-inline'", widgetOrigin];
  }

  const csp = Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(' ')}`)
    .join('; ');

  return function applySecurityHeaders(req, res, next) {
    res.setHeader('Content-Security-Policy', csp);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    if (config.secureCookies) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  };
}

/**
 * Build the Express application.
 *
 * @param {object} [options]
 * @param {object} [options.config]      pre-validated configuration
 * @param {object} [options.entraClient] Entra client; injectable so tests can
 *   exercise routing and session handling without contacting Microsoft. Live
 *   acceptance testing always runs against the real client.
 */
function createApp({ config = loadConfig(), entraClient } = {}) {
  const app = express();

  app.disable('x-powered-by');
  // Cloud Run terminates TLS at its front end and forwards X-Forwarded-Proto.
  app.set('trust proxy', true);

  const sessions = createSessionManager(config);
  const entra = entraClient || createEntraClient(config);

  app.use(requestLogger);
  app.use(securityHeaders(config));

  // /healthz is mounted first and needs no cookie parsing, no session, and no
  // Entra authentication.
  app.use(healthRoutes());

  app.use(cookieParser());
  app.use(express.urlencoded({ extended: false, limit: '16kb' }));
  app.use(
    express.static(PUBLIC_DIR, {
      index: false,
      maxAge: '1h',
      setHeaders: (res) => res.setHeader('X-Content-Type-Options', 'nosniff'),
    }),
  );

  app.use(authRoutes({ config, sessions, entra }));
  app.use(voiceRoutes({ config, sessions }));
  app.use(recoveryRoutes({ config, sessions }));
  app.use(portalRoutes({ config, sessions }));

  // Unknown path.
  app.use((req, res) => {
    res.status(404).type('html').send(authErrorPage({ code: 'not_found' }));
  });

  // Last-resort handler. The error object itself is never rendered or logged,
  // because provider errors can embed request-level detail.
  // eslint-disable-next-line no-unused-vars
  app.use((error, req, res, next) => {
    log('unhandled_error', { path: req.path, name: error?.name });
    if (res.headersSent) return;
    res.status(500).type('html').send(authErrorPage({ code: 'server_error' }));
  });

  app.locals.config = config;
  return app;
}

module.exports = { createApp, securityHeaders };
