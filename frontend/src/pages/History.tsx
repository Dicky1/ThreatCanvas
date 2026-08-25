import { useEffect, useState } from 'react';
import { Search, ExternalLink, Trash2, Calendar, FileText } from 'lucide-react';
import { useNavigate } from 'react-router-dom'; // Tambahkan import ini
import { api } from '../api/client';

interface Scenario {
  id: string;
  original_input: string;
  created_at: string;
  cir_graph_data?: any; // Menambahkan tipe untuk data grafiknya
}

export default function History() {
  const [history, setHistory] = useState<Scenario[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  
  const navigate = useNavigate(); // Inisialisasi navigasi

  useEffect(() => {
    api.scenarios()
      .then(data => {
        setHistory(data);
        setIsLoading(false);
      })
      .catch(err => {
        setErrorMsg(err.message);
        setIsLoading(false);
      });
  }, []);

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
  const handleLoad = (item: Scenario) => {
    // Berpindah ke halaman Dashboard ("/") sambil membawa data skenario (item)
    navigate('/threat-modeling', { state: { loadedScenario: item } });
  };

  const filteredHistory = history.filter(item => 
    (item.original_input || "").toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-6 text-gray-100 h-full flex flex-col">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Attack History</h2>
          <p className="text-gray-400 text-sm">View, search, and reload your previously generated threat scenarios.</p>
        </div>
        
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
                    </p>
                  </div>

                  <div className="flex gap-2 flex-shrink-0">
                    <button 
                      onClick={() => handleLoad(item)} // Panggil fungsi Load
                      className="flex items-center gap-1.5 bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 px-3 py-1.5 rounded-md text-sm transition-colors cursor-pointer"
                    >
                      <ExternalLink className="w-4 h-4" /> Load
                    </button>
                    <button 
                      onClick={() => handleDelete(item.id)} // Panggil fungsi Delete
                      className="flex items-center gap-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 px-3 py-1.5 rounded-md text-sm transition-colors cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
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
