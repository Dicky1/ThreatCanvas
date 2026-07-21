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
 * Interface untuk hasil validasi dari Backend
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Interface untuk Coverage Report (Phase 3)
 */
export interface CoverageReport {
  overall_score: number;
  threat_completeness: number;
  graph_integrity: number;
  total_nodes: number;
  total_edges: number;
  covered_tactics: string[];
  missing_tactics: string[];
  covered_techniques: string[];
  recommendations: string[];
}

/**
 * Interface untuk state aplikasi
 */
interface ThreatState {
  scenarioInput: string;
  isProcessing: boolean;
  cirData: CIRGraph | null;
  scenarioId: string | null;
  artifacts: { [key: string]: string }; 
  error: string | null;
  validation: ValidationResult | null;
  coverageData: CoverageReport | null; // <-- State untuk Phase 3
  
  setScenarioInput: (input: string) => void;
  processScenario: () => Promise<void>;
  fetchArtifacts: (scenarioId: string, type: 'sigma' | 'kql' | 'spl') => Promise<void>;
  fetchCoverage: (scenarioId: string) => Promise<void>; // <-- Method untuk Phase 3
  reset: () => void;
}

export const useThreatStore = create<ThreatState>((set, get) => ({
  scenarioInput: '',
  isProcessing: false,
  cirData: null,
  scenarioId: null,
  artifacts: {},
  error: null,
  validation: null,
  coverageData: null, // <-- Inisialisasi awal

  setScenarioInput: (input: string) => set({ scenarioInput: input }),

  processScenario: async () => {
    const { scenarioInput } = get();
    if (!scenarioInput.trim()) return;

    set({ 
      isProcessing: true, 
      error: null, 
      cirData: null, 
      scenarioId: null, 
      artifacts: {}, 
      validation: null,
      coverageData: null 
    });

    try {
      const response = await fetch('http://localhost:8000/api/v1/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioInput }),
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 400 && data.detail?.validation) {
            set({ 
                isProcessing: false, 
                validation: data.detail.validation, 
                error: 'Validasi CIR gagal' 
            });
        } else {
            throw new Error(data.detail || 'Gagal terhubung ke backend');
        }
        return;
      }
      
      set({ 
        cirData: data.cir.attack_graph, 
        scenarioId: data.id, 
        validation: data.validation,
        isProcessing: false 
      });
      
      // Auto-fetch coverage setelah proses berhasil
      await get().fetchCoverage(data.id);
      
    } catch (err: any) {
      set({ 
        error: err.message || 'Error saat memproses skenario.', 
        isProcessing: false 
      });
    }
  },

  fetchArtifacts: async (scenarioId: string, type: 'sigma' | 'kql' | 'spl') => {
    try {
      const response = await fetch(`http://localhost:8000/api/v1/compile/${type}/${scenarioId}`);
      if (!response.ok) throw new Error(`Gagal mengambil ${type.toUpperCase()}`);
      
      const data = await response.json();
      const content = data.content || data.query;

      set((state) => ({
        artifacts: { ...state.artifacts, [type]: content }
      }));
    } catch (err: any) {
      console.error(err);
      set({ error: `Gagal memuat artefak ${type}` });
    }
  },

  // 3. Method untuk mengambil laporan Coverage (Phase 3)
  fetchCoverage: async (scenarioId: string) => {
    try {
      const response = await fetch(`http://localhost:8000/api/v1/coverage/${scenarioId}`);
      if (!response.ok) throw new Error('Gagal memuat analisis coverage');
      
      const data: CoverageReport = await response.json();
      set({ coverageData: data });
    } catch (err: any) {
      console.error(err);
      set({ error: 'Gagal memuat data coverage' });
    }
  },

  reset: () => set({ 
    scenarioInput: '', 
    cirData: null, 
    scenarioId: null, 
    artifacts: {}, 
    error: null,
    validation: null,
    coverageData: null
  })
}));