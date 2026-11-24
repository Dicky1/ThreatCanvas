import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { useThreatStore } from '../store/useThreatStore';
import PurpleTeam from './PurpleTeam';

const plan = {
  platform: 'windows', platforms: ['windows', 'linux', 'macos'], coverage: { steps: 2, steps_with_tests: 1 },
  steps: [
    { step_id: 's1', technique: 'T1059.001', technique_name: 'PowerShell', tactic: 'TA0002', from_parent: false,
      tests: [{ guid: 'g1', test_number: 1, name: 'Mimikatz', executor: 'powershell', platforms: ['windows'] }, { guid: 'g2', test_number: 2, name: 'BloodHound', executor: 'powershell', platforms: ['windows'] }] },
    { step_id: 's2', technique: 'T1486', technique_name: null, tactic: 'TA0040', from_parent: false, tests: [] },
  ],
};
const run = {
  id: 'r1', scenario_id: 'scn', dataset_id: 'd1', dataset_name: 'lab', platform: 'windows', created_at: '2026-11-24T10:00:00Z', executions: null,
  summary: { techniques: 2, detected: 1, missed: 0, no_rule: 1, not_executed: 0, unverified: 0, detection_rate: 1, execution_log: false, executions: 0 },
  techniques: [
    { technique: 'T1059.001', technique_name: 'PowerShell', tactic: 'TA0002', rules: 1, alerts: 3, executed: null, status: 'DETECTED' as const },
    { technique: 'T1486', technique_name: null, tactic: 'TA0040', rules: 0, alerts: 0, executed: null, status: 'NO_RULE' as const },
  ],
};

describe('PurpleTeam', () => {
  afterEach(() => { vi.restoreAllMocks(); useThreatStore.getState().reset(); });

  it('exports the selected atomic tests and shows run results', async () => {
    useThreatStore.setState({ scenarioId: 'scn' });
    vi.spyOn(api, 'purplePlan').mockResolvedValue(plan);
    vi.spyOn(api, 'datasets').mockResolvedValue([{ id: 'd1', name: 'lab', label: 'malicious', technique_ids: [], source_filename: 'x', event_count: 10, created_at: '' }]);
    vi.spyOn(api, 'purpleRuns').mockResolvedValue([]);
    const exportPurple = vi.spyOn(api, 'exportPurple').mockResolvedValue({ blob: new Blob(['x']), filename: 'plan.ps1' });
    const createRun = vi.spyOn(api, 'createPurpleRun').mockResolvedValue(run);
    URL.createObjectURL = vi.fn(() => 'blob:x');
    URL.revokeObjectURL = vi.fn();

    render(<MemoryRouter><PurpleTeam /></MemoryRouter>);
    expect(await screen.findByText(/No Atomic Red Team test/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText('Select BloodHound'));
    fireEvent.click(screen.getByRole('button', { name: /PowerShell \(Invoke-AtomicRedTeam\)/ }));
    await waitFor(() => expect(exportPurple).toHaveBeenCalledWith('scn', { format: 'invoke-atomic', platform: 'windows', test_guids: ['g1', 'g2'] }));

    fireEvent.click(await screen.findByRole('button', { name: /Match rules against telemetry/ }));
    await waitFor(() => expect(createRun).toHaveBeenCalledWith({ scenarioId: 'scn', datasetId: 'd1', platform: 'windows', executionLog: null }));
    expect(await screen.findByText('DETECTED')).toBeInTheDocument();
    expect(screen.getByText('NO RULE')).toBeInTheDocument();
  });
});
