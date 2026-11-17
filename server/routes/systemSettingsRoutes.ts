/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized System Settings & Branding API Routes
 * - GET /api/system/branding (Public read-only for Login page & active users)
 * - GET /api/system/settings (Admin-authenticated full settings read)
 * - PUT /api/system/settings/branding (Admin-authenticated + CSRF-protected branding update)
 */

import type express from 'express';
import { resolveRequestUser } from '../auth/authService.ts';
import { recordDbAuditEvent } from '../db/index.ts';
import {
  canAccessSystemSettings,
  canManageSystemBranding,
} from '../../src/types/pagePermissions.ts';
import {
  getPublicSystemBranding,
  getSystemSettings,
  updateSystemBranding,
  validateBrandingInput,
} from '../settings/systemSettingsStore.ts';
import { emitSystemBrandingEvent } from './events.ts';

export function registerSystemSettingsRoutes(app: express.Application) {
  // Public read-only branding endpoint so Login Page and all users always reflect global branding
  app.get('/api/system/branding', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({
      ok: true,
      branding: getPublicSystemBranding(),
    });
  });

  // Admin-only full system settings endpoint
  app.get('/api/system/settings', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        ok: false,
        code: 'SETTINGS_UNAUTHORIZED',
        error: 'Authentication required to view system settings.',
      });
    }
    if (!canAccessSystemSettings(caller)) {
      return res.status(403).json({
        ok: false,
        code: 'SETTINGS_FORBIDDEN',
        error: 'Forbidden: Only authorized Admin users can access System Settings.',
      });
    }
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({
      ok: true,
      settings: getSystemSettings(),
    });
  });

  // Admin-only System Branding mutation endpoint
  app.put('/api/system/settings/branding', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        ok: false,
        code: 'SETTINGS_UNAUTHORIZED',
        error: 'Authentication required to update system branding.',
      });
    }
    if (!canManageSystemBranding(caller)) {
      return res.status(403).json({
        ok: false,
        code: 'SETTINGS_BRANDING_FORBIDDEN',
        error: 'Forbidden: Only authorized Admin users can modify System Branding.',
      });
    }

    const body = req.body || {};
    const validation = validateBrandingInput({
      softwareName: body.softwareName,
      logoDataUrl: body.logoDataUrl,
      resetLogo: body.resetLogo,
    });

    if (!validation.valid || !validation.softwareName) {
      return res.status(400).json({
        ok: false,
        code: 'INVALID_BRANDING_INPUT',
        error: validation.error || 'Invalid System Branding payload.',
      });
    }

    try {
      const updatedBranding = updateSystemBranding(
        {
          softwareName: validation.softwareName,
          logoDataUrl: body.logoDataUrl,
          resetLogo: Boolean(body.resetLogo),
        },
        {
          id: caller.id,
          name: caller.name,
          role: caller.role,
        }
      );

      recordDbAuditEvent({
        eventType: 'DB_CONFIG_LOADED',
        actorId: caller.id,
        actorName: caller.name,
        actorRole: caller.role,
        outcome: 'success',
        details: `Updated global System Branding: softwareName="${updatedBranding.softwareName}", customLogo=${Boolean(updatedBranding.logoDataUrl)}.`,
      });

      const publicBranding = {
        softwareName: updatedBranding.softwareName,
        logoDataUrl: updatedBranding.logoDataUrl,
        updatedAt: updatedBranding.updatedAt,
      };
      emitSystemBrandingEvent(publicBranding);

      return res.status(200).json({
        ok: true,
        branding: publicBranding,
        settings: getSystemSettings(),
      });
    } catch (err: any) {
      return res.status(400).json({
        ok: false,
        code: 'BRANDING_UPDATE_FAILED',
        error: err?.message || 'Failed to update System Branding.',
      });
    }
  });
}
