import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { useThreatStore } from '../store/useThreatStore';
import History from './History';

describe('History', () => {
  afterEach(() => { vi.restoreAllMocks(); useThreatStore.getState().reset(); });

  it('loads the stored CIR without re-running the LLM parser', async () => {
    const cir = { cir_version: '2.0', scenario_id: 'x', attack_graph: { nodes: [], edges: [] } };
    vi.spyOn(api, 'scenarios').mockResolvedValue([{ id: 's1', original_input: '[SIEM alerts] a.json', created_at: '2026-11-24T10:00:00Z' }]);
    vi.spyOn(api, 'scenario').mockResolvedValue({ id: 's1', original_input: '[SIEM alerts] a.json', created_at: '', cir_graph_data: cir as never });
    vi.spyOn(api, 'coverage').mockRejectedValue(new Error('skip'));
    const parse = vi.spyOn(api, 'parse');
    render(<MemoryRouter><History /></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: /Load/ }));
    await waitFor(() => expect(useThreatStore.getState().scenarioId).toBe('s1'));
    expect(parse).not.toHaveBeenCalled();
  });
});
