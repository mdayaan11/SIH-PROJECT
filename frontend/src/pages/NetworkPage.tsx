import React, { useEffect } from 'react';
import { ReactFlow, Controls, Background, useNodesState, useEdgesState, MarkerType } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { api } from '../lib/api';
import { Network, RefreshCw, Shield, Server, Cpu, Database, Laptop, Lock } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';

const initialTopologyNodes = [
  {
    id: 'router-1',
    position: { x: 420, y: 40 },
    data: { label: '🛡️ Enclave Gateway (10.0.0.1)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #0284c7',
      borderRadius: '16px',
      padding: '12px 20px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(2, 132, 199, 0.15)',
    }
  },
  {
    id: 'fw-1',
    position: { x: 420, y: 160 },
    data: { label: '🔥 NextGen Firewall (10.0.0.2)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #dc2626',
      borderRadius: '16px',
      padding: '12px 20px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(220, 38, 38, 0.15)',
    }
  },
  {
    id: 'switch-1',
    position: { x: 420, y: 280 },
    data: { label: '🔀 Core Switch (10.0.0.10)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #059669',
      borderRadius: '16px',
      padding: '12px 20px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(5, 150, 105, 0.15)',
    }
  },
  {
    id: 'detect-1',
    position: { x: 100, y: 400 },
    data: { label: '⚡ AI Threat Engine (10.0.0.50)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #7c3aed',
      borderRadius: '16px',
      padding: '12px 20px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(124, 58, 237, 0.15)',
    }
  },
  {
    id: 'db-1',
    position: { x: 420, y: 400 },
    data: { label: '🗄️ Encrypted DB Enclave (10.0.0.100)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #0284c7',
      borderRadius: '16px',
      padding: '12px 20px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(2, 132, 199, 0.15)',
    }
  },
  {
    id: 'web-1',
    position: { x: 740, y: 400 },
    data: { label: '🌐 SOC App Node (10.0.0.150)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #059669',
      borderRadius: '16px',
      padding: '12px 20px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(5, 150, 105, 0.15)',
    }
  },
  {
    id: 'ws-1',
    position: { x: 80, y: 520 },
    data: { label: '💻 Analyst Workstation A (192.168.1.50)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #475569',
      borderRadius: '16px',
      padding: '12px 18px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(71, 85, 105, 0.15)',
    }
  },
  {
    id: 'ws-2',
    position: { x: 420, y: 520 },
    data: { label: '💻 Analyst Workstation B (192.168.1.75)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #ea580c',
      borderRadius: '16px',
      padding: '12px 18px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(234, 88, 12, 0.15)',
    }
  },
  {
    id: 'trap-1',
    position: { x: 740, y: 520 },
    data: { label: '🚨 Quarantine Trap (172.16.0.45)' },
    style: {
      background: '#ffffff',
      color: '#0f172a',
      border: '2px solid #dc2626',
      borderRadius: '16px',
      padding: '12px 18px',
      fontWeight: '900',
      fontSize: '12px',
      boxShadow: '0 10px 25px rgba(220, 38, 38, 0.15)',
    }
  }
];

const initialTopologyEdges = [
  { id: 'e1', source: 'router-1', target: 'fw-1', animated: true, label: '10 Gbps Inbound Diode', style: { stroke: '#0284c7', strokeWidth: 3 } },
  { id: 'e2', source: 'fw-1', target: 'switch-1', animated: true, label: 'Filtered Stream', style: { stroke: '#059669', strokeWidth: 3 } },
  { id: 'e3', source: 'switch-1', target: 'detect-1', animated: true, label: 'SPAN Mirroring', style: { stroke: '#7c3aed', strokeWidth: 3 } },
  { id: 'e4', source: 'switch-1', target: 'db-1', animated: true, label: 'Encrypted TLS 1.3', style: { stroke: '#0284c7', strokeWidth: 3 } },
  { id: 'e5', source: 'switch-1', target: 'web-1', animated: true, label: 'HTTP/2 App Data', style: { stroke: '#059669', strokeWidth: 3 } },
  { id: 'e6', source: 'detect-1', target: 'ws-1', animated: true, label: 'Live Telemetry', style: { stroke: '#7c3aed', strokeWidth: 2 } },
  { id: 'e7', source: 'switch-1', target: 'ws-2', animated: true, label: 'Internal LAN', style: { stroke: '#ea580c', strokeWidth: 2 } },
  { id: 'e8', source: 'fw-1', target: 'trap-1', animated: true, label: 'Isolated Sinkhole', style: { stroke: '#dc2626', strokeWidth: 2 } },
];

export default function NetworkPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState<any>(initialTopologyNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>(initialTopologyEdges);

  useEffect(() => {
    api.fetchBaselines().then(baselines => {
      if (Array.isArray(baselines) && baselines.length > 0) {
        const extraNodes = baselines.map((b: any, idx: number) => ({
          id: `dyn-${b.ip_address}`,
          position: { x: (idx % 3) * 260 + 100, y: Math.floor(idx / 3) * 160 + 640 },
          data: { label: `📡 ${b.ip_address}` },
          style: {
            background: '#ffffff',
            color: '#0f172a',
            border: '2px solid #0284c7',
            borderRadius: '16px',
            padding: '12px 18px',
            fontWeight: '900',
            fontSize: '12px',
            boxShadow: '0 10px 25px rgba(2, 132, 199, 0.12)'
          }
        }));
        setNodes(prev => [...prev, ...extraNodes]);
      }
    }).catch(err => {
      console.warn('Using default network topology nodes:', err);
    });
  }, [setNodes]);

  return (
    <div className="space-y-6 h-full flex flex-col max-w-7xl mx-auto pb-8 text-slate-950 font-sans">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/80 backdrop-blur-2xl border border-slate-300 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-100 border border-cyan-500 text-cyan-950 shadow-xs">
            <Network className="w-6 h-6 text-cyan-900" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-950 tracking-tight">Network Enclave Topology Map</h1>
            <p className="text-xs text-slate-800 font-extrabold mt-0.5">Interactive node topological diagram of active monitored network endpoints, gateways, and isolated threat traps.</p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono">
          <Badge variant="outline" className="border-cyan-500 text-cyan-950 bg-cyan-50 text-xs py-1 px-3 font-black">
            9 ACTIVE NODES
          </Badge>
          <Badge variant="outline" className="border-emerald-500 text-emerald-950 bg-emerald-50 text-xs py-1 px-3 font-black">
            8 LIVE EDGES
          </Badge>
        </div>
      </div>

      {/* Graph Area Container */}
      <div className="flex-1 glass-light-card rounded-3xl border border-slate-300 overflow-hidden relative shadow-xl min-h-[580px]">
        <ReactFlow 
          nodes={nodes} 
          edges={edges} 
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          attributionPosition="bottom-right"
        >
          <Background color="#cbd5e1" gap={24} size={1.5} />
          <Controls className="bg-white border-slate-300 fill-slate-950 rounded-2xl shadow-lg p-1" />
        </ReactFlow>
      </div>

    </div>
  );
}
