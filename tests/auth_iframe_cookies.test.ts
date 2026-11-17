/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Authentication, Cross-Site Iframe Cookie & Proxy Host Normalization Tests
 */

import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createAppServer } from '../server.ts';
import {
  clearAuthCacheForTest,
  hashPassword,
  indexUserInAuthCache,
} from '../server/auth/authService.ts';
import { resetStoreCacheForTest } from '../server/db/index.ts';
import { getDefaultPermissionsForRole } from '../src/types/erp.ts';

describe('Auth Session Cookies & Reverse-Proxy Origin Handling', () => {
  let appServer: http.Server;
  let baseUrl = '';

  before(async () => {
    clearAuthCacheForTest();
    resetStoreCacheForTest();

    const hash = await hashPassword('123456');
    indexUserInAuthCache(
      {
        id: 'shamsul',
        userId: 'shamsul',
        name: 'Shamsul Haque',
        email: 'shamsulhaque.jesbd@gmail.com',
        role: 'Super Admin',
        status: 'Active',
        permissions: getDefaultPermissionsForRole('Super Admin'),
      },
      hash
    );

    const app = createAppServer();
    appServer = http.createServer(app);
    await new Promise<void>((resolve) => {
      appServer.listen(0, '127.0.0.1', () => {
        const addr = appServer.address() as { port: number };
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => appServer.close(() => resolve()));
    clearAuthCacheForTest();
  });

  test('HTTPS proxy login sets SameSite=None; Secure; Partitioned cookies and accepts X-Forwarded-Host with :443', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https, http',
        'X-Forwarded-Host': 'ais-dev-example.asia-east1.run.app:443',
        Origin: 'https://ais-dev-example.asia-east1.run.app',
        'Sec-Fetch-Site': 'same-origin',
      },
      body: JSON.stringify({ identifier: 'shamsul', password: '123456' }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.authenticated, true);
    assert.equal(body.user?.userId, 'shamsul');
    assert.ok(body.csrfToken);

    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    assert.equal(setCookies.length, 2);

    const sessionCookie = setCookies.find((c) => c.startsWith('ensec_erp_session='));
    const csrfCookie = setCookies.find((c) => c.startsWith('ensec_csrf_token='));
    assert.ok(sessionCookie);
    assert.ok(csrfCookie);
    assert.match(sessionCookie, /HttpOnly/i);
    assert.match(sessionCookie, /SameSite=None/i);
    assert.match(sessionCookie, /;\s*Secure/i);
    assert.match(sessionCookie, /;\s*Partitioned/i);
    assert.match(csrfCookie, /SameSite=None/i);
    assert.match(csrfCookie, /;\s*Secure/i);
    assert.match(csrfCookie, /;\s*Partitioned/i);

    const cookiePair = setCookies.map((c) => c.split(';')[0]).join('; ');
    const meRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Cookie: cookiePair, 'X-Forwarded-Proto': 'https' },
    });
    assert.equal(meRes.status, 200);
    const meBody = await meRes.json();
    assert.equal(meBody.authenticated, true);
    assert.equal(meBody.user?.userId, 'shamsul');
    assert.equal(meBody.csrfToken, body.csrfToken);

    const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https',
        Origin: 'https://ais-dev-example.asia-east1.run.app',
        'X-Forwarded-Host': 'ais-dev-example.asia-east1.run.app',
        'X-CSRF-Token': body.csrfToken,
        Cookie: cookiePair,
      },
      body: JSON.stringify({}),
    });
    assert.equal(logoutRes.status, 200);
    const clearCookies = logoutRes.headers.getSetCookie ? logoutRes.headers.getSetCookie() : [];
    assert.equal(clearCookies.length, 2);
    for (const c of clearCookies) {
      assert.match(c, /Max-Age=0/i);
      assert.match(c, /SameSite=None/i);
      assert.match(c, /;\s*Partitioned/i);
    }
  });

  test('Plain HTTP local dev login uses SameSite=Lax without Secure or Partitioned', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'shamsul', password: '123456' }),
    });
    assert.equal(res.status, 200);
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    assert.equal(setCookies.length, 2);
    for (const c of setCookies) {
      assert.match(c, /SameSite=Lax/i);
      assert.doesNotMatch(c, /;\s*Secure/i);
      assert.doesNotMatch(c, /;\s*Partitioned/i);
    }
  });

  test('Explicit CORS_ALLOWED_ORIGINS enables Firebase Hosting cross-origin preflight and login while blocking unlisted origins', async () => {
    const prevCors = process.env.CORS_ALLOWED_ORIGINS;
    process.env.CORS_ALLOWED_ORIGINS = 'https://ensecerp.web.app,https://ensecerp.firebaseapp.com';
    try {
      // Allowed preflight
      const optAllowed = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://ensecerp.web.app',
          'Access-Control-Request-Method': 'POST',
        },
      });
      assert.equal(optAllowed.status, 204);
      assert.equal(optAllowed.headers.get('access-control-allow-origin'), 'https://ensecerp.web.app');
      assert.equal(optAllowed.headers.get('access-control-allow-credentials'), 'true');

      // Allowed cross-site POST login
      const loginAllowed = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://ensecerp.web.app',
          'Sec-Fetch-Site': 'cross-site',
        },
        body: JSON.stringify({ identifier: 'shamsul', password: '123456' }),
      });
      assert.equal(loginAllowed.status, 200);
      assert.equal(loginAllowed.headers.get('access-control-allow-origin'), 'https://ensecerp.web.app');

      // Unlisted cross-site origin remains blocked (403)
      const loginBlocked = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://evil-attacker.example.com',
          'Sec-Fetch-Site': 'cross-site',
        },
        body: JSON.stringify({ identifier: 'shamsul', password: '123456' }),
      });
      assert.equal(loginBlocked.status, 403);
    } finally {
      if (prevCors === undefined) delete process.env.CORS_ALLOWED_ORIGINS;
      else process.env.CORS_ALLOWED_ORIGINS = prevCors;
    }
  });

  test('Unconfigured DB with empty user cache returns 503 DATABASE_NOT_CONFIGURED instead of false invalid-user error', async () => {
    const prevUrl = process.env.SUPABASE_URL;
    const prevKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const prevAnon = process.env.SUPABASE_ANON_KEY;
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    delete process.env.SUPABASE_ANON_KEY;
    clearAuthCacheForTest();

    try {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: 'shamsul', password: '123456' }),
      });
      assert.equal(res.status, 503);
      const body = await res.json();
      assert.equal(body.authenticated, false);
      assert.equal(body.code, 'DATABASE_NOT_CONFIGURED');
      assert.match(body.error, /SUPABASE_URL/i);
    } finally {
      if (prevUrl !== undefined) process.env.SUPABASE_URL = prevUrl;
      if (prevKey !== undefined) process.env.SUPABASE_SERVICE_ROLE_KEY = prevKey;
      if (prevAnon !== undefined) process.env.SUPABASE_ANON_KEY = prevAnon;
    }
  });
});
