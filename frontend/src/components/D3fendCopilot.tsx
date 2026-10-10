import { useEffect, useState } from "react";
import { api } from "../api/client";
import { Shield, ShieldAlert, CheckCircle2, ChevronDown, ChevronRight, Loader2 } from "lucide-react";

interface Countermeasure {
  defensive_technique: string;
  rationale: string;
  source: string;
  confidence: number;
}

interface Remediation {
  technique_id: string;
  technique_name: string;
  countermeasures: Countermeasure[];
}

export default function D3fendCopilot({ scenarioId }: { scenarioId: string }) {
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedTech, setExpandedTech] = useState<string | null>(null);

  useEffect(() => {
    async function fetchData() {
      setIsLoading(true);
      try {
        const data = await api.d3fend(scenarioId);
        setRemediations(data.remediations);
        if (data.remediations.length > 0) {
          setExpandedTech(data.remediations[0].technique_id);
        }
      } catch (err) {
        setError("Gagal memuat data remediasi D3FEND.");
      } finally {
        setIsLoading(false);
      }
    }
    fetchData();
  }, [scenarioId]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        <Loader2 className="animate-spin mr-2" />
        Memuat D3FEND Remediation...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64 text-red-400 bg-gray-900 border border-gray-800 rounded-lg p-4">
        <ShieldAlert className="mr-2" /> {error}
      </div>
    );
  }

  if (remediations.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400 bg-gray-900 border border-gray-800 rounded-lg p-4">
        <CheckCircle2 className="mr-2 text-green-500" />
        Tidak ada pemetaan teknik yang ditemukan untuk skenario ini.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="bg-surface border border-gray-800 rounded-xl p-6 shadow-md mb-6">
        <h2 className="text-xl font-semibold text-white flex items-center mb-2">
          <Shield className="text-primary mr-2" size={24} />
          D3FEND Remediation Copilot
        </h2>
        <p className="text-gray-400 text-sm">
          Rekomendasi kontrol pertahanan berbasis MITRE D3FEND yang dipetakan secara otomatis terhadap teknik ATT&CK yang ditemukan pada skenario ini.
        </p>
      </div>

      <div className="space-y-4">
        {remediations.map((rem) => {
          const isExpanded = expandedTech === rem.technique_id;
          return (
            <div key={rem.technique_id} className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden transition-all">
              <button
                onClick={() => setExpandedTech(isExpanded ? null : rem.technique_id)}
                className="w-full flex items-center justify-between p-4 bg-gray-800 hover:bg-gray-700 transition-colors text-left"
              >
                <div className="flex items-center">
                  {isExpanded ? <ChevronDown size={18} className="text-gray-400 mr-2" /> : <ChevronRight size={18} className="text-gray-400 mr-2" />}
                  <span className="font-semibold text-white mr-3">{rem.technique_id}</span>
                  <span className="text-gray-300">{rem.technique_name || "Unknown Technique"}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded-full">
                    {rem.countermeasures.length} Kontrol
                  </span>
                </div>
              </button>
              
              {isExpanded && (
                <div className="p-4 bg-gray-900 border-t border-gray-800">
                  {rem.countermeasures.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {rem.countermeasures.map((cm, idx) => (
                        <div key={idx} className="bg-surface border border-gray-700 rounded-md p-4 shadow-sm hover:border-primary/50 transition-colors">
                          <div className="flex justify-between items-start mb-2">
                            <span className="font-bold text-primary font-mono bg-primary/10 px-2 py-1 rounded text-sm">
                              {cm.defensive_technique}
                            </span>
                            <span className="text-xs text-gray-500 flex flex-col items-end">
                              <span>Conf: {(cm.confidence * 100).toFixed(0)}%</span>
                              <span className="truncate max-w-[100px]" title={cm.source}>{cm.source.split('/').pop() || cm.source}</span>
                            </span>
                          </div>
                          <p className="text-sm text-gray-300 leading-relaxed">
                            {cm.rationale}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-gray-500 italic p-2">
                      Belum ada pemetaan D3FEND spesifik untuk teknik ini di database.
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
