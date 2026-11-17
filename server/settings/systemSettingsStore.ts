/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized Persistent System Settings Store
 * Persists global system configuration (starting with System Branding)
 * on the server so all users and unauthenticated pages (e.g. Login)
 * always receive authoritative, persistent configuration across
 * logouts, refreshes, and server restarts.
 */

import fs from 'fs';
import path from 'path';

export interface SystemBrandingConfig {
  softwareName: string;
  logoDataUrl: string | null;
  updatedAt: string | null;
  updatedBy: string | null;
}

export interface SystemSettingsConfig {
  schemaVersion: 1;
  branding: SystemBrandingConfig;
}

export const DEFAULT_SOFTWARE_NAME = 'Ensec';
export const MAX_SOFTWARE_NAME_LENGTH = 80;
export const MAX_LOGO_DATA_URL_LENGTH = 2_400_000; // ~1.75 MB binary image encoded as base64

const ALLOWED_IMAGE_DATA_URL_REGEX =
  /^data:image\/(png|jpeg|jpg|webp|gif|svg\+xml|x-icon|vnd\.microsoft\.icon);base64,[A-Za-z0-9+/=]+$/i;

const DEFAULT_SETTINGS_FILE = path.resolve(
  process.cwd(),
  '.ensec-server-state',
  'system-settings.json'
);

function resolveSettingsFilePath(): string {
  const custom = (process.env.ENSEC_SYSTEM_SETTINGS_PATH || '').trim();
  return custom ? path.resolve(custom) : DEFAULT_SETTINGS_FILE;
}

export function getDefaultSystemSettings(): SystemSettingsConfig {
  return {
    schemaVersion: 1,
    branding: {
      softwareName: DEFAULT_SOFTWARE_NAME,
      logoDataUrl: null,
      updatedAt: null,
      updatedBy: null,
    },
  };
}

let inMemorySettingsCache: SystemSettingsConfig | null = null;
let loadedSettingsPath = '';

export function resetSystemSettingsCacheForTest(): void {
  inMemorySettingsCache = null;
  loadedSettingsPath = '';
}

function sanitizeLoadedSettings(raw: any): SystemSettingsConfig {
  const defaults = getDefaultSystemSettings();
  if (!raw || typeof raw !== 'object') {
    return defaults;
  }

  const rawBranding = raw.branding && typeof raw.branding === 'object' ? raw.branding : {};
  const name =
    typeof rawBranding.softwareName === 'string' && rawBranding.softwareName.trim().length > 0
      ? rawBranding.softwareName.trim().slice(0, MAX_SOFTWARE_NAME_LENGTH)
      : DEFAULT_SOFTWARE_NAME;

  const logo =
    typeof rawBranding.logoDataUrl === 'string' &&
    rawBranding.logoDataUrl.length <= MAX_LOGO_DATA_URL_LENGTH &&
    ALLOWED_IMAGE_DATA_URL_REGEX.test(rawBranding.logoDataUrl)
      ? rawBranding.logoDataUrl
      : null;

  return {
    schemaVersion: 1,
    branding: {
      softwareName: name,
      logoDataUrl: logo,
      updatedAt: typeof rawBranding.updatedAt === 'string' ? rawBranding.updatedAt : null,
      updatedBy: typeof rawBranding.updatedBy === 'string' ? rawBranding.updatedBy : null,
    },
  };
}

function loadSettingsFromDisk(): SystemSettingsConfig {
  const filePath = resolveSettingsFilePath();
  if (inMemorySettingsCache && loadedSettingsPath === filePath) {
    return inMemorySettingsCache;
  }

  loadedSettingsPath = filePath;
  try {
    if (!fs.existsSync(filePath)) {
      inMemorySettingsCache = getDefaultSystemSettings();
      return inMemorySettingsCache;
    }
    const rawText = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(rawText);
    inMemorySettingsCache = sanitizeLoadedSettings(parsed);
    return inMemorySettingsCache;
  } catch {
    inMemorySettingsCache = getDefaultSystemSettings();
    return inMemorySettingsCache;
  }
}

function persistSettingsToDisk(settings: SystemSettingsConfig): void {
  const filePath = resolveSettingsFilePath();
  loadedSettingsPath = filePath;
  inMemorySettingsCache = settings;

  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const tempPath = `${filePath}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(settings, null, 2), { mode: 0o600 });
  fs.renameSync(tempPath, filePath);
}

export function validateBrandingInput(input: {
  softwareName?: unknown;
  logoDataUrl?: unknown;
  resetLogo?: unknown;
}): {
  valid: boolean;
  error?: string;
  softwareName?: string;
  logoDataUrl?: string | null;
  shouldUpdateLogo?: boolean;
} {
  const rawName = typeof input.softwareName === 'string' ? input.softwareName.trim() : '';
  if (!rawName) {
    return { valid: false, error: 'Software Name is required and cannot be empty.' };
  }
  if (rawName.length > MAX_SOFTWARE_NAME_LENGTH) {
    return {
      valid: false,
      error: `Software Name must be ${MAX_SOFTWARE_NAME_LENGTH} characters or fewer.`,
    };
  }

  const resetLogo = Boolean(input.resetLogo);
  if (resetLogo) {
    return {
      valid: true,
      softwareName: rawName,
      logoDataUrl: null,
      shouldUpdateLogo: true,
    };
  }

  if (input.logoDataUrl === undefined) {
    return {
      valid: true,
      softwareName: rawName,
      shouldUpdateLogo: false,
    };
  }

  if (input.logoDataUrl === null || input.logoDataUrl === '') {
    return {
      valid: true,
      softwareName: rawName,
      logoDataUrl: null,
      shouldUpdateLogo: true,
    };
  }

  if (typeof input.logoDataUrl !== 'string') {
    return { valid: false, error: 'Invalid logo image payload.' };
  }

  const trimmedLogo = input.logoDataUrl.trim();
  if (trimmedLogo.length > MAX_LOGO_DATA_URL_LENGTH) {
    return {
      valid: false,
      error: 'Uploaded logo image is too large. Please upload an image under 1.5 MB.',
    };
  }

  if (!ALLOWED_IMAGE_DATA_URL_REGEX.test(trimmedLogo)) {
    return {
      valid: false,
      error: 'Unsupported logo format. Allowed formats: PNG, JPG, WEBP, SVG, GIF, or ICO.',
    };
  }

  // Protect against embedded scripts inside SVG uploads
  if (/^data:image\/svg\+xml;base64,/i.test(trimmedLogo)) {
    try {
      const b64 = trimmedLogo.split(',')[1] || '';
      const svgText = Buffer.from(b64, 'base64').toString('utf8');
      if (/<script\b/i.test(svgText) || /\bon[a-z]+\s*=/i.test(svgText) || /javascript:/i.test(svgText)) {
        return {
          valid: false,
          error: 'SVG logo contains disallowed active script content.',
        };
      }
    } catch {
      return { valid: false, error: 'Invalid SVG logo encoding.' };
    }
  }

  return {
    valid: true,
    softwareName: rawName,
    logoDataUrl: trimmedLogo,
    shouldUpdateLogo: true,
  };
}

export function getSystemSettings(): SystemSettingsConfig {
  const current = loadSettingsFromDisk();
  return {
    schemaVersion: 1,
    branding: { ...current.branding },
  };
}

export function getPublicSystemBranding(): Pick<
  SystemBrandingConfig,
  'softwareName' | 'logoDataUrl' | 'updatedAt'
> {
  const { branding } = loadSettingsFromDisk();
  return {
    softwareName: branding.softwareName,
    logoDataUrl: branding.logoDataUrl,
    updatedAt: branding.updatedAt,
  };
}

export function updateSystemBranding(
  input: {
    softwareName: string;
    logoDataUrl?: string | null;
    resetLogo?: boolean;
  },
  actor: { id: string; name: string; role: string }
): SystemBrandingConfig {
  const validation = validateBrandingInput(input);
  if (!validation.valid || !validation.softwareName) {
    throw new Error(validation.error || 'Invalid system branding payload.');
  }

  const current = loadSettingsFromDisk();
  const nextLogo = validation.shouldUpdateLogo
    ? (validation.logoDataUrl ?? null)
    : current.branding.logoDataUrl;

  const updatedBranding: SystemBrandingConfig = {
    softwareName: validation.softwareName,
    logoDataUrl: nextLogo,
    updatedAt: new Date().toISOString(),
    updatedBy: `${actor.name} (${actor.role})`,
  };

  const nextSettings: SystemSettingsConfig = {
    ...current,
    schemaVersion: 1,
    branding: updatedBranding,
  };

  persistSettingsToDisk(nextSettings);
  return { ...updatedBranding };
}
