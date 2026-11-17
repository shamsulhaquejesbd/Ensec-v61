/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Centralized System Settings & Branding Context
 * Fetches, caches, broadcasts, and synchronizes global system branding
 * (Software Name, Software Logo/Icon, browser document.title, and favicon)
 * across the Login page, Sidebar, Navbar, and all ERP modules.
 */

import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { apiRequest } from '../lib/apiClient.ts';

export interface SystemBranding {
  softwareName: string;
  logoDataUrl: string | null;
  updatedAt: string | null;
}

export interface UpdateBrandingPayload {
  softwareName: string;
  logoDataUrl?: string | null;
  resetLogo?: boolean;
}

export const DEFAULT_SYSTEM_BRANDING: SystemBranding = {
  softwareName: 'Ensec',
  logoDataUrl: null,
  updatedAt: null,
};

interface SystemSettingsContextValue {
  branding: SystemBranding;
  isLoadingBranding: boolean;
  refreshBranding: () => Promise<SystemBranding>;
  updateBranding: (payload: UpdateBrandingPayload) => Promise<SystemBranding>;
}

const SystemSettingsContext = createContext<SystemSettingsContextValue>({
  branding: DEFAULT_SYSTEM_BRANDING,
  isLoadingBranding: false,
  refreshBranding: async () => DEFAULT_SYSTEM_BRANDING,
  updateBranding: async () => DEFAULT_SYSTEM_BRANDING,
});

const BRANDING_BROADCAST_CHANNEL = 'ensec_system_branding';

function normalizeBranding(raw: any): SystemBranding {
  const name =
    typeof raw?.softwareName === 'string' && raw.softwareName.trim().length > 0
      ? raw.softwareName.trim()
      : DEFAULT_SYSTEM_BRANDING.softwareName;
  const logoDataUrl =
    typeof raw?.logoDataUrl === 'string' && raw.logoDataUrl.startsWith('data:image/')
      ? raw.logoDataUrl
      : null;
  const updatedAt = typeof raw?.updatedAt === 'string' ? raw.updatedAt : null;

  return {
    softwareName: name,
    logoDataUrl,
    updatedAt,
  };
}

function buildDocumentTitle(softwareName: string): string {
  const clean = (softwareName || '').trim() || DEFAULT_SYSTEM_BRANDING.softwareName;
  if (clean.toLowerCase() === 'ensec') {
    return 'Ensec ERP & Distribution Management Platform';
  }
  return `${clean} — ERP & Management Platform`;
}

function syncFavicon(logoDataUrl: string | null) {
  if (typeof document === 'undefined') return;
  const existingDynamic = document.querySelector<HTMLLinkElement>('link[data-ensec-dynamic-favicon="true"]');
  if (!logoDataUrl) {
    if (existingDynamic) {
      existingDynamic.remove();
    }
    return;
  }
  const link = existingDynamic || document.createElement('link');
  link.rel = 'icon';
  link.setAttribute('data-ensec-dynamic-favicon', 'true');
  link.href = logoDataUrl;
  if (!existingDynamic) {
    document.head.appendChild(link);
  }
}

export const SystemSettingsProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [branding, setBranding] = useState<SystemBranding>(DEFAULT_SYSTEM_BRANDING);
  const [isLoadingBranding, setIsLoadingBranding] = useState<boolean>(true);

  const applyBrandingLocally = useCallback((next: SystemBranding) => {
    setBranding(next);
  }, []);

  const refreshBranding = useCallback(async (): Promise<SystemBranding> => {
    try {
      const response = await fetch('/api/system/branding', {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
      });
      if (!response.ok) {
        return branding;
      }
      const data = await response.json();
      if (data?.branding) {
        const normalized = normalizeBranding(data.branding);
        applyBrandingLocally(normalized);
        return normalized;
      }
    } catch {
      // Keep current/default branding on transient network errors
    } finally {
      setIsLoadingBranding(false);
    }
    return branding;
  }, [applyBrandingLocally, branding]);

  const updateBranding = useCallback(
    async (payload: UpdateBrandingPayload): Promise<SystemBranding> => {
      const res = await apiRequest<{
        ok: boolean;
        branding: SystemBranding;
      }>('/api/system/settings/branding', {
        method: 'PUT',
        body: JSON.stringify(payload),
      });

      const normalized = normalizeBranding(res?.branding);
      applyBrandingLocally(normalized);

      if (typeof window !== 'undefined' && typeof BroadcastChannel !== 'undefined') {
        try {
          const channel = new BroadcastChannel(BRANDING_BROADCAST_CHANNEL);
          channel.postMessage(normalized);
          channel.close();
        } catch {
          // Ignore BroadcastChannel errors
        }
      }

      return normalized;
    },
    [applyBrandingLocally]
  );

  // Sync browser page title & favicon globally whenever branding changes
  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.title = buildDocumentTitle(branding.softwareName);
    }
    syncFavicon(branding.logoDataUrl);
  }, [branding.softwareName, branding.logoDataUrl]);

  // Initial fetch + live SSE & multi-tab BroadcastChannel synchronization
  useEffect(() => {
    let active = true;

    (async () => {
      try {
        const response = await fetch('/api/system/branding', {
          method: 'GET',
          credentials: 'include',
          cache: 'no-store',
        });
        if (active && response.ok) {
          const data = await response.json();
          if (data?.branding) {
            applyBrandingLocally(normalizeBranding(data.branding));
          }
        }
      } catch {
        // Fallback to default branding
      } finally {
        if (active) setIsLoadingBranding(false);
      }
    })();

    const handleSseBranding = (evt: Event) => {
      const custom = evt as CustomEvent;
      if (custom?.detail) {
        applyBrandingLocally(normalizeBranding(custom.detail));
      }
    };
    window.addEventListener('ensec-system-branding-updated', handleSseBranding);

    let channel: BroadcastChannel | null = null;
    if (typeof BroadcastChannel !== 'undefined') {
      try {
        channel = new BroadcastChannel(BRANDING_BROADCAST_CHANNEL);
        channel.onmessage = (msg: MessageEvent) => {
          if (msg?.data) {
            applyBrandingLocally(normalizeBranding(msg.data));
          }
        };
      } catch {
        channel = null;
      }
    }

    return () => {
      active = false;
      window.removeEventListener('ensec-system-branding-updated', handleSseBranding);
      if (channel) {
        channel.close();
      }
    };
  }, [applyBrandingLocally]);

  return (
    <SystemSettingsContext.Provider
      value={{
        branding,
        isLoadingBranding,
        refreshBranding,
        updateBranding,
      }}
    >
      {children}
    </SystemSettingsContext.Provider>
  );
};

export function useSystemSettings(): SystemSettingsContextValue {
  return useContext(SystemSettingsContext);
}
