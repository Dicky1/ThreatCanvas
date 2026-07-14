import { create } from 'zustand';

/**
 * Interface untuk struktur CIR (Cyber Intermediate Representation)
 */
export interface CIRNode {
  step_id: string;
  tactic: string;
  technique: string;
  actor: string;
  target: string;
  action_type: string;
}

export interface CIRGraph {
  nodes: CIRNode[];
  edges: { from: string; to: string; relationship: string }[];
}

/**
 * Interface untuk state aplikasi
 */
interface ThreatState {
  scenarioInput: string;
  isProcessing: boolean;
  cirData: CIRGraph | null;
  // State untuk menyimpan hasil kompilasi (Sigma, KQL, SPL)
  artifacts: { [key: string]: string }; 
  error: string | null;
  
  setScenarioInput: (input: string) => void;
  processScenario: () => Promise<void>;
  fetchArtifacts: (scenarioId: string, type: 'sigma' | 'kql' | 'spl') => Promise<void>;
  reset: () => void;
}

export const useThreatStore = create<ThreatState>((set, get) => ({
  scenarioInput: '',
  isProcessing: false,
  cirData: null,
  artifacts: {},
  error: null,

  setScenarioInput: (input: string) => set({ scenarioInput: input }),

  // 1. Mengirim narasi ke Backend untuk mendapatkan CIR Graph
  processScenario: async () => {
    const { scenarioInput } = get();
    if (!scenarioInput.trim()) return;

    set({ isProcessing: true, error: null, cirData: null, artifacts: {} });

    try {
      const response = await fetch('http://localhost:8000/api/v1/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioInput }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Gagal terhubung ke backend');
      }
      
      const data = await response.json();
      set({ cirData: data.attack_graph, isProcessing: false });
    } catch (err: any) {
      set({ 
        error: err.message || 'Error saat memproses skenario.', 
        isProcessing: false 
      });
    }
  },

  // 2. Mengambil artefak kompilasi (Sigma/KQL/SPL) dari Backend
  fetchArtifacts: async (scenarioId: string, type: 'sigma' | 'kql' | 'spl') => {
    try {
      const response = await fetch(`http://localhost:8000/api/v1/compile/${type}/${scenarioId}`);
      if (!response.ok) throw new Error(`Gagal mengambil ${type.toUpperCase()}`);
      
      const data = await response.json();
      const content = data.content || data.query; // Menangani perbedaan key di response backend

      set((state) => ({
        artifacts: { ...state.artifacts, [type]: content }
      }));
    } catch (err: any) {
      console.error(err);
      set({ error: `Gagal memuat artefak ${type}` });
    }
  },

  reset: () => set({ scenarioInput: '', cirData: null, artifacts: {}, error: null })
}));