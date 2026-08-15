'use strict';

/**
 * Container entrypoint.
 *
 * Cloud Run supplies PORT and expects the process to listen on it promptly and
 * to shut down cleanly on SIGTERM.
 */

const { createApp } = require('./app');
const { loadConfig } = require('./config');
const { log } = require('./logger');

function main() {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    // Configuration errors name the missing variable but never print a value.
    process.stderr.write(`[startup] ${error.message}\n`);
    process.exit(1);
    return;
  }

  const app = createApp({ config });
  const server = app.listen(config.port, () => {
    log('server_started', {
      port: config.port,
      base_url: config.baseUrl,
      redirect_uri: config.redirectUri,
      secure_cookies: config.secureCookies,
    });
  });

  const shutdown = (signal) => {
    log('server_stopping', { signal });
    server.close(() => process.exit(0));
    // Cloud Run allows a short grace period before it kills the container.
    setTimeout(() => process.exit(0), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

if (require.main === module) {
  main();
}

module.exports = { main };
