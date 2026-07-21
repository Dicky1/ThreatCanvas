import { create } from 'zustand';
import { useNotificationStore } from './useNotificationStore';

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
  coverageData: CoverageReport | null;

  setScenarioInput: (input: string) => void;
  processScenario: () => Promise<void>;
  fetchArtifacts: (scenarioId: string, type: 'sigma' | 'kql' | 'spl') => Promise<void>;
  fetchCoverage: (scenarioId: string) => Promise<void>;
  reset: () => void;
}

// Helper singkat untuk memotong teks skenario panjang saat dipakai di notifikasi
function truncate(text: string, maxLength = 60): string {
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}

export const useThreatStore = create<ThreatState>((set, get) => ({
  scenarioInput: '',
  isProcessing: false,
  cirData: null,
  scenarioId: null,
  artifacts: {},
  error: null,
  validation: null,
  coverageData: null,

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
      coverageData: null,
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
            error: 'Validasi CIR gagal',
          });

          useNotificationStore.getState().addNotification({
            title: 'Validasi CIR gagal',
            message: `Skenario "${truncate(scenarioInput)}" tidak lolos validasi graph.`,
            type: 'error',
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
        isProcessing: false,
      });

      useNotificationStore.getState().addNotification({
        title: 'Parsing selesai',
        message: `Skenario "${truncate(scenarioInput)}" berhasil dikonversi ke CIR graph.`,
        type: 'success',
      });

      // Auto-fetch coverage setelah proses berhasil
      await get().fetchCoverage(data.id);
    } catch (err: any) {
      const message = err.message || 'Error saat memproses skenario.';
      set({ error: message, isProcessing: false });

      useNotificationStore.getState().addNotification({
        title: 'Gagal memproses skenario',
        message,
        type: 'error',
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
        artifacts: { ...state.artifacts, [type]: content },
      }));

      useNotificationStore.getState().addNotification({
        title: `Artefak ${type.toUpperCase()} dihasilkan`,
        message: `Rule ${type.toUpperCase()} siap direview di History.`,
        type: 'success',
      });
    } catch (err: any) {
      console.error(err);
      set({ error: `Gagal memuat artefak ${type}` });

      useNotificationStore.getState().addNotification({
        title: `Gagal membuat artefak ${type.toUpperCase()}`,
        message: err.message || `Terjadi kesalahan saat compile ${type}.`,
        type: 'error',
      });
    }
  },

  fetchCoverage: async (scenarioId: string) => {
    try {
      const response = await fetch(`http://localhost:8000/api/v1/coverage/${scenarioId}`);
      if (!response.ok) throw new Error('Gagal memuat analisis coverage');

      const data: CoverageReport = await response.json();
      set({ coverageData: data });

      useNotificationStore.getState().addNotification({
        title: 'Coverage report siap',
        message: `Skor coverage: ${Math.round(data.overall_score)}%. ${
          data.missing_tactics.length > 0
            ? `${data.missing_tactics.length} taktik belum tercover.`
            : 'Semua taktik utama tercover.'
        }`,
        type: data.missing_tactics.length > 0 ? 'info' : 'success',
      });
    } catch (err: any) {
      console.error(err);
      set({ error: 'Gagal memuat data coverage' });

      useNotificationStore.getState().addNotification({
        title: 'Gagal memuat coverage',
        message: err.message || 'Terjadi kesalahan saat analisis coverage.',
        type: 'error',
      });
    }
  },

  reset: () =>
    set({
      scenarioInput: '',
      cirData: null,
      scenarioId: null,
      artifacts: {},
      error: null,
      validation: null,
      coverageData: null,
    }),
}));