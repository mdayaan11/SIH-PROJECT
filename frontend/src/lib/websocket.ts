import { useStore } from '../store/useStore';

let ws: WebSocket | null = null;
let reconnectTimer: any = null;

export const connectWs = () => {
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
  
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = import.meta.env.VITE_WS_URL || `${protocol}//${window.location.host}/ws/alerts`;
  ws = new WebSocket(wsUrl);
  
  ws.onopen = () => {
    useStore.getState().setWsConnected(true);
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };
  
  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'alert') {
      useStore.getState().addAlert(data.data);
    } else if (data.type === 'event') {
      useStore.getState().addLiveEvent(data.data);
    } else if (data.type === 'status') {
      useStore.getState().setStatus(data.data);
    }
  };
  
  ws.onclose = () => {
    useStore.getState().setWsConnected(false);
    reconnectTimer = setTimeout(connectWs, 3000);
  };
  
  ws.onerror = () => {
    ws?.close();
  };
  
  return () => {
    if (ws) ws.close();
  };
};
