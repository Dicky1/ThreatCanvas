import { create } from 'zustand';
import { useNotificationStore } from './useNotificationStore';
import { api } from '../api/client';
import type { CIRGraph, CIRSpecification, CoverageReport as ApiCoverageReport } from '../types/api';
export type { CIRGraph, CIRNode } from '../types/api';

/**
 * Interface untuk struktur CIR (Cyber Intermediate Representation)
 */
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
  cirSpec: CIRSpecification | null;
  scenarioId: string | null;
  attackVersion: string | null;
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
  cirSpec: null,
  scenarioId: null,
  attackVersion: null,
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
      cirSpec: null,
      scenarioId: null,
      artifacts: {},
      validation: null,
      coverageData: null,
    });

    try {
      const data = await api.parse(scenarioInput);
      set({
        cirData: data.cir.attack_graph,
        cirSpec: data.cir,
        scenarioId: data.id,
        attackVersion: data.cir.attack_version || null,
        validation: data.validation as unknown as ValidationResult,
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
      const data = await api.artifact(scenarioId, type);
      const content = data.content;

      set((state) => ({
        artifacts: { ...state.artifacts, [type]: content },
        error: null,
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
      const data: ApiCoverageReport = await api.coverage(scenarioId);
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
      cirSpec: null,
      scenarioId: null,
      attackVersion: null,
      artifacts: {},
      error: null,
      validation: null,
      coverageData: null,
    }),
}));
