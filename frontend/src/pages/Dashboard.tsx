import { useState, useEffect } from 'react';
import { useThreatStore } from '../store/useThreatStore';
import { Send, Loader2, Database, ShieldAlert } from 'lucide-react';
import ThreatGraph from '../components/ThreatGraph';
import ArtifactViewer from '../components/ArtifactViewer';
import { useLocation } from 'react-router-dom';

export default function Dashboard() {
  const { 
    scenarioInput, setScenarioInput, processScenario, 
    isProcessing, cirData, error, artifacts, fetchArtifacts 
    // Catatan: Jika Anda ingin grafiknya langsung muncul, pastikan Anda juga 
    // mengekspor fungsi seperti `setCirData` dari useThreatStore Anda.
  } = useThreatStore();
  
  const [activeTab, setActiveTab] = useState<'graph' | 'artifacts'>('graph');
  const [selectedArtifact, setSelectedArtifact] = useState<'sigma' | 'kql' | 'spl'>('sigma');

  // 1. Panggil useLocation untuk membaca state yang dilempar dari router
  const location = useLocation();

  // 2. Tangkap data dari History saat komponen pertama kali di-render
  useEffect(() => {
    if (location.state && location.state.loadedScenario) {
      const scenario = location.state.loadedScenario;
      
      // Isi textarea dengan input historis
      setScenarioInput(scenario.original_input);

      // (Opsional tapi sangat disarankan) 
      // Jika di useThreatStore Anda punya fungsi untuk mengeset data grafik secara manual,
      // panggil di sini agar analis tidak perlu menekan tombol "Generate" ulang.
      // Contoh:
      // if (scenario.cir_graph_data && setCirData) {
      //   setCirData(scenario.cir_graph_data);
      // }

      // 3. Bersihkan router state agar data tidak me-load berulang kali jika user me-refresh browser (F5)
      window.history.replaceState({}, document.title);
    }
  }, [location, setScenarioInput]);

  // Trigger fetch data ke backend saat pindah tab
  const handleTabChange = (tab: 'graph' | 'artifacts') => {
    setActiveTab(tab);
    if (tab === 'artifacts' && cirData) {
      // Menggunakan 'scenario-id' yang sesuai dengan sistem penyimpanan DB Anda
      fetchArtifacts('scenario-id', selectedArtifact);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <header>
        <h2 className="text-2xl font-bold text-white mb-2">Threat Narrative Processor</h2>
        <p className="text-gray-400">Transform natural language attack scenarios into deterministic CIR graphs.</p>
      </header>

      {/* Input Section */}
      <div className="bg-surface border border-gray-800 rounded-xl p-6 shadow-xl">
        <textarea
          rows={6}
          className="w-full bg-background border border-gray-700 rounded-lg p-4 text-gray-100 outline-none focus:ring-2 focus:ring-primary transition-all"
          placeholder="Example: Attacker sends phishing email, steals credentials..."
          value={scenarioInput}
          onChange={(e) => setScenarioInput(e.target.value)}
        />
        <button 
          onClick={processScenario}
          className="mt-4 flex items-center px-6 py-2.5 bg-primary text-white rounded-lg hover:bg-blue-600 transition-colors"
        >
          {isProcessing ? <Loader2 className="animate-spin mr-2" /> : <Send className="mr-2" />}
          Generate Artifacts
        </button>
      </div>

      {/* Results Section */}
      {cirData && (
        <div className="bg-surface border border-gray-800 rounded-xl p-6 shadow-xl animate-in fade-in duration-500">
          <div className="flex space-x-6 mb-6 border-b border-gray-700">
            <button 
              onClick={() => handleTabChange('graph')} 
              className={`pb-2 ${activeTab === 'graph' ? 'text-primary border-b-2 border-primary' : 'text-gray-400 hover:text-white'}`}
            >
              Attack Graph
            </button>
            <button 
              onClick={() => handleTabChange('artifacts')} 
              className={`pb-2 ${activeTab === 'artifacts' ? 'text-primary border-b-2 border-primary' : 'text-gray-400 hover:text-white'}`}
            >
              Detection Artifacts
            </button>
          </div>

          {activeTab === 'graph' ? (
            <div className="h-[400px]">
              <ThreatGraph data={cirData} />
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex space-x-2">
                {(['sigma', 'kql', 'spl'] as const).map((type) => (
                  <button 
                    key={type} 
                    onClick={() => {
                      setSelectedArtifact(type);
                      fetchArtifacts('scenario-id', type);
                    }} 
                    className={`px-4 py-1.5 rounded text-sm uppercase transition-colors ${
                      selectedArtifact === type 
                        ? 'bg-primary text-white' 
                        : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
              <ArtifactViewer 
                code={artifacts[selectedArtifact] || 'Click button to compile artifact...'} 
                language={selectedArtifact.toUpperCase()} 
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}