import React, { useEffect, useState, useMemo } from 'react';
import { ReactFlow, Controls, Background, useNodesState, useEdgesState } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { api } from '../lib/api';

export default function NetworkPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    // Simulated fetching for the node map
    api.fetchBaselines().then(baselines => {
      const generatedNodes = baselines.map((b: any, idx: number) => ({
        id: b.ip_address,
        position: { x: (idx % 4) * 150, y: Math.floor(idx / 4) * 150 },
        data: { label: b.ip_address },
        style: {
          background: '#1e293b',
          color: '#e2e8f0',
          border: '1px solid #334155',
          borderRadius: '8px',
          padding: '10px'
        }
      }));
      setNodes(generatedNodes);
    });
  }, []);

  return (
    <div className="space-y-4 h-full flex flex-col">
      <h1 className="text-2xl font-bold">Network Graph</h1>
      <div className="flex-1 bg-navy-800/50 rounded-lg border border-navy-700 overflow-hidden relative">
        <ReactFlow 
          nodes={nodes} 
          edges={edges} 
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
        >
          <Background color="#334155" gap={16} />
          <Controls className="bg-navy-700 border-navy-600 fill-white" />
        </ReactFlow>
      </div>
    </div>
  );
}
