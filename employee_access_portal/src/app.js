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
const { portalRoutes } = require('./routes/portal');
const { authErrorPage } = require('./views/authError');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

/**
 * Response headers applied to every route.
 *
 * The CSP is restrictive because the portal ships no client-side JavaScript at
 * all: pages are server-rendered, so `script-src 'none'` costs nothing and
 * removes an entire class of token-stealing bugs.
 */
function securityHeaders(config) {
  const csp = [
    "default-src 'none'",
    "style-src 'self'",
    "img-src 'self' data:",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');

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
