'use strict';

/**
 * Deliberately minimal logging.
 *
 * Cloud Run captures stdout, so anything written here lands in Cloud Logging.
 * Only the request line and a sanitized event name are ever emitted: no
 * tokens, no authorization codes, no complete authorization responses, no
 * client secret, and no session cookie contents.
 */

// Sanitized error codes are short identifiers such as "access_denied".
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,64}$/;

/**
 * Reduce an arbitrary provider error code to something safe to print and render.
 */
function sanitizeCode(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return SAFE_CODE.test(trimmed) ? trimmed : null;
}

function log(event, fields = {}) {
  const safe = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined || value === null) continue;
    // Only primitives are logged, and strings are length-capped so that a
    // token accidentally passed here could never be reassembled from logs.
    if (typeof value === 'number' || typeof value === 'boolean') {
      safe[key] = value;
    } else if (typeof value === 'string') {
      safe[key] = value.length > 120 ? `${value.slice(0, 120)}...` : value;
    }
  }
  process.stdout.write(`${JSON.stringify({ event, ...safe })}\n`);
}

/**
 * Express middleware: one structured line per request, method/path/status only.
 * The query string is dropped entirely because the authorization response
 * carries the authorization code there.
 */
function requestLogger(req, res, next) {
  const startedAt = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    log('http_request', {
      method: req.method,
      path: req.path, // path only: never req.originalUrl, which includes ?code=
      status: res.statusCode,
      duration_ms: Math.round(durationMs),
    });
  });
  next();
}

module.exports = { log, requestLogger, sanitizeCode };
