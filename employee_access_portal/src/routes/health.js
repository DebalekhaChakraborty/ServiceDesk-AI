'use strict';

const express = require('express');

/**
 * Container liveness/readiness probe.
 *
 * Mounted before every authentication concern so that Cloud Run can check the
 * revision without a Microsoft Entra round trip. It exposes no configuration,
 * no identity, and no secret.
 */
function healthRoutes() {
  const router = express.Router();

  router.get('/healthz', (req, res) => {
    res.status(200).json({ status: 'ok', service: 'employee-access-portal' });
  });

  return router;
}

module.exports = { healthRoutes };
