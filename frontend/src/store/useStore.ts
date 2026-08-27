import { create } from 'zustand';
import { ThreatAlert, SystemStatus } from '../types';

interface AppState {
  alerts: ThreatAlert[];
  status: SystemStatus | null;
  wsConnected: boolean;
  liveEvents: any[];
  selectedPage: string;
  setAlerts: (alerts: ThreatAlert[]) => void;
  addAlert: (alert: ThreatAlert) => void;
  setStatus: (status: SystemStatus) => void;
  setWsConnected: (connected: boolean) => void;
  addLiveEvent: (event: any) => void;
  setSelectedPage: (page: string) => void;
}

export const useStore = create<AppState>((set) => ({
  alerts: [],
  status: null,
  wsConnected: false,
  liveEvents: [],
  selectedPage: 'overview',
  setAlerts: (alerts) => set({ alerts }),
  addAlert: (alert) => set((state) => ({ alerts: [alert, ...state.alerts].slice(0, 1000) })),
  setStatus: (status) => set({ status }),
  setWsConnected: (connected) => set({ wsConnected: connected }),
  addLiveEvent: (event) => set((state) => ({ liveEvents: [event, ...state.liveEvents].slice(0, 100) })),
  setSelectedPage: (page) => set({ selectedPage: page }),
}));
