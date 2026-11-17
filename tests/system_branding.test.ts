/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * System Settings & Global System Branding Tests
 * Verifies persistence, server-side RBAC enforcement, validation, and global visibility.
 */

import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createAppServer } from '../server.ts';
import {
  clearAuthCacheForTest,
  hashPassword,
  indexUserInAuthCache,
} from '../server/auth/authService.ts';
import { resetStoreCacheForTest } from '../server/db/index.ts';
import { resetSystemSettingsCacheForTest } from '../server/settings/systemSettingsStore.ts';
import { getDefaultPermissionsForRole } from '../src/types/erp.ts';
import { isUserPermittedForModule } from '../src/lib/postLoginRedirect.ts';

const SAMPLE_PNG_DATA_URL =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';

describe('System Settings & Global System Branding', () => {
  let appServer: http.Server;
  let baseUrl = '';
  let tempDir = '';
  let settingsFilePath = '';
  let previousSettingsEnv: string | undefined;

  before(async () => {
    previousSettingsEnv = process.env.ENSEC_SYSTEM_SETTINGS_PATH;
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ensec-branding-test-'));
    settingsFilePath = path.join(tempDir, 'system-settings.json');
    process.env.ENSEC_SYSTEM_SETTINGS_PATH = settingsFilePath;

    resetSystemSettingsCacheForTest();
    clearAuthCacheForTest();
    resetStoreCacheForTest();

    const passHash = await hashPassword('pass1234');

    indexUserInAuthCache(
      {
        id: 'u-superadmin',
        userId: 'ADMIN',
        name: 'Super Admin User',
        email: 'admin@ensecbd.com',
        role: 'Super Admin',
        status: 'Active',
        permissions: getDefaultPermissionsForRole('Super Admin'),
      },
      passHash
    );

    indexUserInAuthCache(
      {
        id: 'u-admin',
        userId: 'SYSADMIN',
        name: 'System Admin User',
        email: 'sysadmin@ensecbd.com',
        role: 'Admin' as any,
        status: 'Active',
        permissions: getDefaultPermissionsForRole('Sales Head'),
      },
      passHash
    );

    indexUserInAuthCache(
      {
        id: 'u-sales',
        userId: 'SALES1',
        name: 'Sales User',
        email: 'sales1@ensecbd.com',
        role: 'Sales Head',
        status: 'Active',
        permissions: getDefaultPermissionsForRole('Sales Head'),
      },
      passHash
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
    resetSystemSettingsCacheForTest();
    if (previousSettingsEnv === undefined) {
      delete process.env.ENSEC_SYSTEM_SETTINGS_PATH;
    } else {
      process.env.ENSEC_SYSTEM_SETTINGS_PATH = previousSettingsEnv;
    }
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  async function loginAs(identifier: string, password: string) {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: baseUrl,
        'Sec-Fetch-Site': 'same-origin',
      },
      body: JSON.stringify({ identifier, password }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    const cookieHeader = setCookies.map((c) => c.split(';')[0]).join('; ');
    return {
      cookieHeader,
      csrfToken: String(body.csrfToken || ''),
      user: body.user,
    };
  }

  test('Public /api/system/branding defaults to Ensec with null logo', async () => {
    const res = await fetch(`${baseUrl}/api/system/branding`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.branding?.softwareName, 'Ensec');
    assert.equal(body.branding?.logoDataUrl, null);
  });

  test('Unauthenticated requests to /api/system/settings and PUT branding are rejected with 401', async () => {
    const getRes = await fetch(`${baseUrl}/api/system/settings`);
    assert.equal(getRes.status, 401);

    const putRes = await fetch(`${baseUrl}/api/system/settings/branding`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Origin: baseUrl,
      },
      body: JSON.stringify({ softwareName: 'Hijacked ERP' }),
    });
    assert.equal(putRes.status, 401);
  });

  test('Non-admin users are blocked from accessing Settings or modifying System Branding (403)', async () => {
    const salesSession = await loginAs('SALES1', 'pass1234');
    assert.equal(isUserPermittedForModule(salesSession.user, 'settings'), false);
    assert.equal(isUserPermittedForModule(salesSession.user, 'settings-database-management'), false);

    const getRes = await fetch(`${baseUrl}/api/system/settings`, {
      headers: { Cookie: salesSession.cookieHeader },
    });
    assert.equal(getRes.status, 403);

    const putRes = await fetch(`${baseUrl}/api/system/settings/branding`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Cookie: salesSession.cookieHeader,
        'X-CSRF-Token': salesSession.csrfToken,
        Origin: baseUrl,
      },
      body: JSON.stringify({ softwareName: 'Unauthorized ERP' }),
    });
    assert.equal(putRes.status, 403);
  });

  test('Admin users can update Software Name and Logo, and changes persist across restarts & logout', async () => {
    const adminSession = await loginAs('SYSADMIN', 'pass1234');
    assert.equal(isUserPermittedForModule(adminSession.user, 'settings'), true);
    assert.equal(isUserPermittedForModule(adminSession.user, 'settings-database-management'), false);

    // Reject malicious SVG payload with <script>
    const badSvg = `data:image/svg+xml;base64,${Buffer.from('<svg><script>alert(1)</script></svg>').toString('base64')}`;
    const badSvgRes = await fetch(`${baseUrl}/api/system/settings/branding`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminSession.cookieHeader,
        'X-CSRF-Token': adminSession.csrfToken,
        Origin: baseUrl,
      },
      body: JSON.stringify({ softwareName: 'Aman ERP', logoDataUrl: badSvg }),
    });
    assert.equal(badSvgRes.status, 400);

    // Reject empty softwareName
    const emptyNameRes = await fetch(`${baseUrl}/api/system/settings/branding`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminSession.cookieHeader,
        'X-CSRF-Token': adminSession.csrfToken,
        Origin: baseUrl,
      },
      body: JSON.stringify({ softwareName: '   ' }),
    });
    assert.equal(emptyNameRes.status, 400);

    // Valid update: Software Name "Aman ERP" + custom PNG logo
    const updateRes = await fetch(`${baseUrl}/api/system/settings/branding`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminSession.cookieHeader,
        'X-CSRF-Token': adminSession.csrfToken,
        Origin: baseUrl,
      },
      body: JSON.stringify({
        softwareName: 'Aman ERP',
        logoDataUrl: SAMPLE_PNG_DATA_URL,
      }),
    });
    assert.equal(updateRes.status, 200);
    const updatedBody = await updateRes.json();
    assert.equal(updatedBody.ok, true);
    assert.equal(updatedBody.branding?.softwareName, 'Aman ERP');
    assert.equal(updatedBody.branding?.logoDataUrl, SAMPLE_PNG_DATA_URL);

    // Simulate server restart by clearing in-memory settings cache so disk file must reload
    resetSystemSettingsCacheForTest();

    // Unauthenticated / logged-out client (Login Page) sees updated branding
    const publicRes = await fetch(`${baseUrl}/api/system/branding`);
    assert.equal(publicRes.status, 200);
    const publicBody = await publicRes.json();
    assert.equal(publicBody.branding?.softwareName, 'Aman ERP');
    assert.equal(publicBody.branding?.logoDataUrl, SAMPLE_PNG_DATA_URL);

    // Super Admin can also reset logo back to default while keeping Software Name
    const superAdminSession = await loginAs('ADMIN', 'pass1234');
    assert.equal(isUserPermittedForModule(superAdminSession.user, 'settings'), true);
    assert.equal(
      isUserPermittedForModule(superAdminSession.user, 'settings-database-management'),
      true
    );

    const resetLogoRes = await fetch(`${baseUrl}/api/system/settings/branding`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Cookie: superAdminSession.cookieHeader,
        'X-CSRF-Token': superAdminSession.csrfToken,
        Origin: baseUrl,
      },
      body: JSON.stringify({
        softwareName: 'Aman ERP',
        resetLogo: true,
      }),
    });
    assert.equal(resetLogoRes.status, 200);
    const resetLogoBody = await resetLogoRes.json();
    assert.equal(resetLogoBody.branding?.softwareName, 'Aman ERP');
    assert.equal(resetLogoBody.branding?.logoDataUrl, null);
  });

  test('formatNonJsonApiError converts Firebase Hosting HTML 404 and 200 SPA fallback into actionable messages', async () => {
    const { formatNonJsonApiError } = await import('../src/lib/apiClient.ts');
    const firebase404Html =
      '<!DOCTYPE html> <html> <head><title>Page Not Found</title></head> <body><h2>404</h2><h1>Page Not Found</h1></body> </html>';
    const formatted404 = formatNonJsonApiError(
      '/api/auth/login',
      404,
      firebase404Html,
      'text/html; charset=utf-8'
    );
    assert.ok(formatted404);
    assert.equal(formatted404.code, 'BACKEND_API_UNAVAILABLE');
    assert.match(formatted404.message, /Static Firebase Hosting only serves frontend files/i);
    assert.doesNotMatch(formatted404.message, /<!DOCTYPE html>/i);

    const spa200Html = '<!doctype html><html><body><div id="root"></div></body></html>';
    const formatted200 = formatNonJsonApiError(
      '/api/auth/login',
      200,
      spa200Html,
      'text/html'
    );
    assert.ok(formatted200);
    assert.equal(formatted200.code, 'BACKEND_API_UNAVAILABLE');
    assert.match(formatted200.message, /VITE_API_BASE_URL/i);
  });
});
