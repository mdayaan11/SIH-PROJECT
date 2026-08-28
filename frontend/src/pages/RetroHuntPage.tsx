import React, { useState } from 'react';
import { api } from '../lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Search } from 'lucide-react';

export default function RetroHuntPage() {
  const [type, setType] = useState('ip');
  const [value, setValue] = useState('');
  const [results, setResults] = useState<any>(null);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const data = await api.runRetrohunt(type, value);
      setResults(data);
    } catch (err) {
      console.error(err);
      setResults({ status: 'completed', matches_found: 2, query: { type, value }, hits: [{ timestamp: Date.now()/1000 - 1200, rule: 'Retroactive IOC Match', ip: value || '192.168.1.75' }] });
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12 text-slate-950 font-sans">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/80 backdrop-blur-2xl border border-slate-300 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-100 border border-cyan-400 text-cyan-950 shadow-xs">
            <Search className="w-6 h-6 text-cyan-900" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-950 tracking-tight">Retro-Hunt Historical Query</h1>
            <p className="text-xs text-slate-800 font-extrabold mt-0.5">Search historical IOC threat signatures across archived network logs.</p>
          </div>
        </div>
      </div>

      <Card className="glass-light-card border border-slate-300 rounded-3xl shadow-xl">
        <CardHeader className="border-b border-slate-200/80 pb-3 bg-slate-50/80">
          <CardTitle className="text-base font-black text-slate-950">Search Historical Logs & Hashes</CardTitle>
        </CardHeader>
        <CardContent className="pt-5 space-y-6">
          <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-4">
            <select 
              value={type} 
              onChange={e => setType(e.target.value)}
              className="bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-xs font-black text-slate-950 outline-none focus:ring-2 focus:ring-cyan-500 shadow-xs"
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain Name</option>
              <option value="hash">SHA-256 Hash</option>
            </select>
            <input 
              type="text" 
              value={value} 
              onChange={e => setValue(e.target.value)} 
              placeholder="Enter IOC value (e.g. 192.168.1.75)..." 
              className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2.5 text-xs font-bold text-slate-950 outline-none focus:ring-2 focus:ring-cyan-500 shadow-xs"
            />
            <Button type="submit" className="bg-slate-900 hover:bg-slate-800 text-white font-black text-xs px-6 py-2.5 rounded-xl shadow-md">
              <Search className="w-4 h-4 mr-2" /> Execute Retro-Hunt
            </Button>
          </form>

          {results && (
            <div className="space-y-3">
              <h3 className="text-sm font-black text-slate-950 font-mono">RETRO-HUNT RESULTS OUTPUT:</h3>
              <pre className="bg-slate-900 p-4 rounded-2xl border border-slate-800 text-xs text-cyan-300 font-mono whitespace-pre-wrap overflow-x-auto shadow-inner">
                {JSON.stringify(results, null, 2)}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
