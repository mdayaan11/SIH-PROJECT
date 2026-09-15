/**
 * Native WebSocket client for ENCLIVRA backend.
 * Backend: FastAPI /ws/alerts endpoint (native WS, NOT Socket.IO)
 * Reconnects automatically with exponential backoff.
 */
import { useStore } from '../store/useStore';

const DEFAULT_BACKEND_URL = 'https://sih-project-d3r8.onrender.com';
const WS_BASE = (() => {
  const base = import.meta.env.VITE_API_URL || import.meta.env.VITE_WS_URL || DEFAULT_BACKEND_URL;
  return base.replace(/^http/, 'ws').replace(/\/+$/, '');
})();

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectDelay = 1000;
let shouldReconnect = true;

// Poll REST /api/status every 5s as the primary data source
let statusPollTimer: ReturnType<typeof setInterval> | null = null;
// Poll REST /api/alerts every 5s for initial data + refresh
let alertsPollTimer: ReturnType<typeof setInterval> | null = null;

async function pollStatus() {
  try {
    const res = await fetch(`${DEFAULT_BACKEND_URL}/api/status`, { signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      const data = await res.json();
      if (data && typeof data.uptime_seconds === 'number') {
        useStore.getState().setStatus(data);
      }
    }
  } catch (_) {}
}

async function pollAlerts() {
  try {
    const res = await fetch(`${DEFAULT_BACKEND_URL}/api/alerts?limit=100`, { signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      const data = await res.json();
      const alerts = Array.isArray(data) ? data : (data?.alerts ?? []);
      if (Array.isArray(alerts)) {
        useStore.getState().setAlerts(alerts);
      }
    }
  } catch (_) {}
}

function connectWsSocket() {
  if (!shouldReconnect) return;

  try {
    ws = new WebSocket(`${WS_BASE}/ws/alerts`);

    ws.onopen = () => {
      console.log('[ENCLIVRA] WebSocket connected to', WS_BASE);
      useStore.getState().setWsConnected(true);
      reconnectDelay = 1000; // reset backoff on success
    };

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        const { type, data } = msg;

        if (type === 'alert' && data) {
          useStore.getState().addAlert(data);
        } else if (type === 'event' && data) {
          useStore.getState().addLiveEvent(data);
        } else if (type === 'status' && data) {
          useStore.getState().setStatus(data);
        }
      } catch (_) {}
    };

    ws.onerror = () => {
      // Will trigger onclose
    };

    ws.onclose = () => {
      ws = null;
      useStore.getState().setWsConnected(false);
      if (shouldReconnect) {
        // Exponential backoff capped at 15s
        reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
        console.log(`[ENCLIVRA] WS closed, reconnecting in ${Math.round(reconnectDelay / 1000)}s…`);
        reconnectTimer = setTimeout(connectWsSocket, reconnectDelay);
      }
    };
  } catch (err) {
    console.warn('[ENCLIVRA] WebSocket init error:', err);
    useStore.getState().setWsConnected(false);
    reconnectTimer = setTimeout(connectWsSocket, reconnectDelay);
  }
}

export const connectWs = () => {
  shouldReconnect = true;

  // 1. Immediately start REST polling (works even when WS is asleep on Render free tier)
  pollStatus();
  pollAlerts();
  statusPollTimer = setInterval(pollStatus, 5000);
  alertsPollTimer = setInterval(pollAlerts, 7000);

  // 2. Also try live WebSocket for real-time push
  connectWsSocket();

  // Return cleanup
  return () => {
    shouldReconnect = false;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (statusPollTimer) clearInterval(statusPollTimer);
    if (alertsPollTimer) clearInterval(alertsPollTimer);
    if (ws) {
      ws.close();
      ws = null;
    }
  };
};
