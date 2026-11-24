import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '../api/client';
import { useThreatStore } from './useThreatStore';

const cir = { cir_version: '2.0', scenario_id: 'x', attack_graph: { nodes: [], edges: [] } };

describe('processScenario self-repair handling', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    useThreatStore.getState().reset();
  });

  it('keeps the repair log of a successful parse', async () => {
    vi.spyOn(api, 'parse').mockResolvedValue({
      cir: cir as never,
      id: 'scn-1',
      validation: { valid: true, errors: [], warnings: [] },
      repair_attempts: [{ attempt: 1, stage: 'validation', errors: ['MITRE: Unknown ATT&CK technique: T9999'] }],
    });
    vi.spyOn(api, 'coverage').mockRejectedValue(new Error('skip'));
    useThreatStore.setState({ scenarioInput: 'narrative' });
    await useThreatStore.getState().processScenario();
    const state = useThreatStore.getState();
    expect(state.scenarioId).toBe('scn-1');
    expect(state.repairAttempts).toHaveLength(1);
  });

  it('surfaces the validation report when repair is exhausted', async () => {
    const detail = {
      message: 'Validation Failed',
      validation: { valid: false, errors: ['MITRE: Unknown ATT&CK technique: T9999'], warnings: [] },
      repair_attempts: [1, 2, 3].map((attempt) => ({ attempt, stage: 'validation', errors: ['MITRE: x'] })),
    };
    vi.spyOn(api, 'parse').mockRejectedValue(new ApiError(400, 'Validation Failed', detail));
    useThreatStore.setState({ scenarioInput: 'narrative' });
    await useThreatStore.getState().processScenario();
    const state = useThreatStore.getState();
    expect(state.scenarioId).toBeNull();
    expect(state.validation?.valid).toBe(false);
    expect(state.repairAttempts).toHaveLength(3);
    expect(state.error).toContain('3 percobaan');
  });
});
