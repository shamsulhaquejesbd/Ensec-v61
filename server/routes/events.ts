import type express from 'express';
import { resolveRequestUser, type AuthenticatedErpUser } from '../auth/authService.ts';
import { authorizeTableOperation, sanitizeRowForCaller } from './erpGateway.ts';

export interface ErpRealtimeEventPayload {
  table: string;
  eventType: 'INSERT' | 'UPDATE' | 'DELETE';
  newRow?: Record<string, any> | null;
  oldRow?: Record<string, any> | null;
  timestamp: string;
}

interface SseClient {
  id: string;
  user: AuthenticatedErpUser;
  res: express.Response;
}

const activeSseClients = new Map<string, SseClient>();

export function emitErpTableEvent(event: Omit<ErpRealtimeEventPayload, 'timestamp'>) {
  if (activeSseClients.size === 0) return;

  const timestamp = new Date().toISOString();
  for (const [clientId, client] of activeSseClients.entries()) {
    const auth = authorizeTableOperation(client.user, event.table, 'select');
    if (!auth.allowed) {
      continue;
    }

    const payload: ErpRealtimeEventPayload = {
      table: event.table,
      eventType: event.eventType,
      newRow: event.newRow ? sanitizeRowForCaller(event.table, event.newRow, client.user) : null,
      oldRow: event.oldRow ? sanitizeRowForCaller(event.table, event.oldRow, client.user) : null,
      timestamp,
    };

    const frame = `event: db-change\ndata: ${JSON.stringify(payload)}\n\n`;
    try {
      client.res.write(frame);
    } catch {
      activeSseClients.delete(clientId);
    }
  }
}

export function emitSystemBrandingEvent(branding: {
  softwareName: string;
  logoDataUrl: string | null;
  updatedAt: string | null;
}) {
  if (activeSseClients.size === 0) return;

  const frame = `event: system-branding\ndata: ${JSON.stringify({
    branding,
    timestamp: new Date().toISOString(),
  })}\n\n`;

  for (const [clientId, client] of activeSseClients.entries()) {
    try {
      client.res.write(frame);
    } catch {
      activeSseClients.delete(clientId);
    }
  }
}

export function registerEventsRoutes(app: express.Application) {
  app.get('/api/erp/events', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        ok: false,
        code: 'EVENTS_UNAUTHORIZED',
        error: 'Authentication required to subscribe to real-time ERP updates.',
      });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof (res as any).flushHeaders === 'function') {
      (res as any).flushHeaders();
    }

    const clientId = `sse-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    activeSseClients.set(clientId, {
      id: clientId,
      user: caller,
      res,
    });

    res.write(
      `event: connected\ndata: ${JSON.stringify({
        ok: true,
        clientId,
        timestamp: new Date().toISOString(),
      })}\n\n`
    );

    const heartbeat = setInterval(() => {
      try {
        res.write(`event: ping\ndata: ${JSON.stringify({ ts: Date.now() })}\n\n`);
      } catch {
        clearInterval(heartbeat);
        activeSseClients.delete(clientId);
      }
    }, 25000);

    req.on('close', () => {
      clearInterval(heartbeat);
      activeSseClients.delete(clientId);
    });
  });
}
