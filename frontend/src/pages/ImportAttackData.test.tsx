import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '../api/client';
import { useThreatStore } from '../store/useThreatStore';
import ImportAttackData from './ImportAttackData';

const cir = { cir_version: '2.0', scenario_id: 'alerts', attack_graph: { nodes: [{ step_id: 'a1' }, { step_id: 'a2' }], edges: [] } };

describe('ImportAttackData', () => {
  afterEach(() => { vi.restoreAllMocks(); useThreatStore.getState().reset(); });

  it('turns an alert export into the active scenario', async () => {
    vi.spyOn(api, 'coverage').mockRejectedValue(new Error('skip'));
    const ingest = vi.spyOn(api, 'ingestAlerts').mockResolvedValue({
      cir: cir as never, id: 'scn-9', validation: { valid: true, errors: [], warnings: [] }, repair_attempts: [],
      method: 'deterministic', stats: { alerts: 4, alerts_with_techniques: 3, skipped_techniques: ['T9999'] },
    });
    render(<MemoryRouter><ImportAttackData /></MemoryRouter>);
    const input = screen.getByLabelText(/Alert export/);
    fireEvent.change(input, { target: { files: [new File(['[]'], 'alerts.json', { type: 'application/json' })] } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Build attack graph' })[0]);
    await waitFor(() => expect(ingest).toHaveBeenCalledWith(expect.any(File), false));
    expect(await screen.findByText('2 attack steps from 4 alerts')).toBeInTheDocument();
    expect(screen.getByText('DETERMINISTIC')).toBeInTheDocument();
    expect(useThreatStore.getState().scenarioId).toBe('scn-9');
  });

  it('explains when the AI cannot produce a valid CIR from a report', async () => {
    vi.spyOn(api, 'ingestCti').mockRejectedValue(new ApiError(400, 'Validation Failed', { repair_attempts: [{}, {}, {}] }));
    render(<MemoryRouter><ImportAttackData /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText('Report URL'), { target: { value: 'https://vendor.example/apt' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Build attack graph' })[1]);
    expect(await screen.findByText(/failed validation after 3 attempt/)).toBeInTheDocument();
  });
});
