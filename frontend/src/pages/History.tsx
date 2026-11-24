import { useEffect, useState } from 'react';
import { Search, ExternalLink, Trash2, Calendar, FileText } from 'lucide-react';
import { useNavigate } from 'react-router-dom'; // Tambahkan import ini
import { api } from '../api/client';
import { useThreatStore } from '../store/useThreatStore';
import type { Scenario, WorkspaceSummary } from '../types/api';

export default function History() {
  const [history, setHistory] = useState<Scenario[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [filter, setFilter] = useState('');
  
  const navigate = useNavigate(); // Inisialisasi navigasi
  const loadParseResult = useThreatStore((state) => state.loadParseResult);

  useEffect(() => {
    setIsLoading(true);
    api.scenarios(filter || undefined)
      .then(data => {
        setHistory(data);
        setIsLoading(false);
      })
      .catch(err => {
        setErrorMsg(err.message);
        setIsLoading(false);
      });
  }, [filter]);

  useEffect(() => { api.workspaces().then(setWorkspaces).catch(() => setWorkspaces([])); }, []);
  const shareable = workspaces.filter((w) => w.role !== 'viewer');

  const handleShare = async (item: Scenario, workspaceId: string) => {
    try {
      const updated = await api.shareScenario(item.id, workspaceId || null);
      setHistory((rows) => rows.map((row) => (row.id === item.id ? { ...row, ...updated } : row)));
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Gagal membagikan skenario.');
    }
  };

  // --- FUNGSI DELETE ---
  const handleDelete = async (id: string) => {
    // Tampilkan konfirmasi sebelum menghapus
    if (!window.confirm("Apakah Anda yakin ingin menghapus skenario ini?")) return;

    try {
      await api.deleteScenario(id);
      // Hapus data dari state React agar langsung hilang dari layar tanpa perlu refresh
      setHistory(prevHistory => prevHistory.filter(item => item.id !== id));
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Gagal menghapus skenario di database.');
    }
  };

  // --- FUNGSI LOAD ---
  const handleLoad = async (item: Scenario) => {
    // Load the stored CIR directly: no LLM re-parse (costly and non-deterministic).
    try {
      const scenario = await api.scenario(item.id);
      await loadParseResult(
        { cir: scenario.cir_graph_data, id: scenario.id, validation: { valid: true, errors: [], warnings: [] }, repair_attempts: [] },
        scenario.original_input,
      );
      navigate('/threat-modeling');
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Gagal memuat skenario.');
    }
  };

  const filteredHistory = history.filter(item => 
    (item.original_input || "").toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-6 text-gray-100 h-full flex flex-col">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Attack History</h2>
          <p className="text-gray-400 text-sm">Your scenarios plus those shared with you in a workspace. Unshared scenarios are private to your account.</p>
        </div>
        
        <div className="flex gap-3 items-center">
        <select aria-label="Filter by workspace" value={filter} onChange={(e) => setFilter(e.target.value)} className="bg-gray-900 border border-gray-700 text-gray-200 text-sm rounded-lg p-2.5">
          <option value="">All scenarios</option>
          <option value="personal">Personal (not shared)</option>
          {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
        </select>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-4 w-4 text-gray-500" />
          </div>
          <input
            type="text"
            className="bg-gray-900 border border-gray-700 text-gray-200 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-64 pl-10 p-2.5"
            placeholder="Search scenarios..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {isLoading && <div className="text-gray-500 text-center py-10">Memuat data dari backend...</div>}
        
        {errorMsg && (
          <div className="text-red-500 text-center py-10 bg-red-900/20 border border-red-500 rounded-lg">
            Gagal memuat data: {errorMsg}
          </div>
        )}

        {!isLoading && !errorMsg && filteredHistory.length === 0 && (
          <div className="text-gray-500 text-center py-10">Tidak ada skenario yang ditemukan.</div>
        )}

        {!isLoading && !errorMsg && filteredHistory.length > 0 && (
          <div className="space-y-4">
            {filteredHistory.map((item) => (
              <div key={item.id} className="bg-gray-800 border border-gray-700 rounded-lg p-5 hover:border-blue-500 transition-colors">
                <div className="flex justify-between items-start gap-4">
                  
                  <div className="space-y-3 flex-1 overflow-hidden">
                    <p className="text-gray-300 text-sm flex items-start gap-2">
                      <FileText className="w-5 h-5 text-gray-500 flex-shrink-0 mt-0.5" /> 
                      <span className="line-clamp-2 leading-relaxed">
                        {item.original_input || "[No Input]"}
                      </span>
                    </p>
                    
                    <p className="text-gray-500 text-xs flex items-center gap-1">
                      <Calendar className="w-3 h-3" /> 
                      {new Date(item.created_at).toLocaleString()}
                      {item.workspace_name && <span className="ml-2 px-2 py-0.5 rounded bg-blue-500/10 text-blue-300">{item.workspace_name}</span>}
                      {item.is_owner === false && item.owner_username && <span className="ml-2 text-gray-400">by {item.owner_username}</span>}
                    </p>
                  </div>

                  <div className="flex gap-2 flex-shrink-0 items-center">
                    {item.is_owner && (shareable.length > 0 || item.workspace_id) && (
                      <select aria-label={`Share ${item.id}`} value={item.workspace_id ?? ''} onChange={(e) => handleShare(item, e.target.value)} className="bg-gray-900 border border-gray-700 text-gray-300 text-xs rounded-md p-1.5">
                        <option value="">Private</option>
                        {shareable.map((w) => <option key={w.id} value={w.id}>Share: {w.name}</option>)}
                      </select>
                    )}
                    <button 
                      onClick={() => handleLoad(item)} // Panggil fungsi Load
                      className="flex items-center gap-1.5 bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 px-3 py-1.5 rounded-md text-sm transition-colors cursor-pointer"
                    >
                      <ExternalLink className="w-4 h-4" /> Load
                    </button>
                    {item.can_edit !== false && <button 
                      onClick={() => handleDelete(item.id)} // Panggil fungsi Delete
                      className="flex items-center gap-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 px-3 py-1.5 rounded-md text-sm transition-colors cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>}
                  </div>
                  
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
