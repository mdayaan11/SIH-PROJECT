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
      setResults({ error: 'Failed to run retro-hunt' });
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Retro-Hunt</h1>
      <Card>
        <CardHeader>
          <CardTitle>Search Historical Data</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSearch} className="flex gap-4">
            <select 
              value={type} 
              onChange={e => setType(e.target.value)}
              className="bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white"
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
            </select>
            <input 
              type="text" 
              value={value} 
              onChange={e => setValue(e.target.value)} 
              placeholder="Enter IOC value..." 
              className="flex-1 bg-navy-900 border border-navy-600 rounded px-3 py-2 text-sm text-white"
            />
            <Button type="submit">
              <Search className="w-4 h-4 mr-2" /> Hunt
            </Button>
          </form>

          {results && (
            <div className="mt-6">
              <h3 className="text-lg font-semibold mb-2">Results</h3>
              <pre className="bg-navy-900 p-4 rounded border border-navy-700 text-xs text-gray-300 font-mono whitespace-pre-wrap overflow-x-auto">
                {JSON.stringify(results, null, 2)}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
