'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createTestApp } = require('./helpers');

test('GET /healthz returns 200 without any Entra authentication', async () => {
  const { app } = createTestApp();

  const res = await request(app).get('/healthz').expect(200);

  assert.equal(res.body.status, 'ok');
  assert.equal(res.body.service, 'employee-access-portal');
});

test('GET /healthz does not issue a session and does not redirect', async () => {
  const { app } = createTestApp();

  const res = await request(app).get('/healthz');

  assert.equal(res.status, 200);
  assert.equal(res.headers['set-cookie'], undefined);
  assert.equal(res.headers.location, undefined);
});

test('GET /healthz leaks no configuration', async () => {
  const { app } = createTestApp();

  const res = await request(app).get('/healthz').expect(200);

  const body = JSON.stringify(res.body);
  assert.ok(!body.includes('CLIENT-SECRET-SENTINEL'));
  assert.ok(!body.includes('SESSION-SECRET-SENTINEL'));
  assert.ok(!/tenant/i.test(body));
});
