import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { useThreatStore } from '../store/useThreatStore';
import CoverageGaps from './CoverageGaps';

describe('CoverageGaps', () => {
  afterEach(() => { vi.restoreAllMocks(); useThreatStore.getState().reset(); });

  it('shows real coverage and saves the data source selection', async () => {
    useThreatStore.setState({ scenarioId: 'scn' });
    vi.spyOn(api, 'inventorySummary').mockResolvedValue({ rules: 2180, techniques: 410, top_techniques: [['T1059.001', 181]], files: [] });
    vi.spyOn(api, 'dataSources').mockResolvedValue({ configured: false, components: [], source: null, catalog: ['Process Creation', 'Windows Registry Key Modification'] });
    const save = vi.spyOn(api, 'saveDataSources').mockResolvedValue({ components: ['Process Creation'], source: 'manual' });
    vi.spyOn(api, 'gapAnalysis').mockResolvedValue({
      summary: { techniques: 2, covered: 1, coverage: 0.5, blind: 1, rule_without_telemetry: 0, telemetry_without_rule: 0, inventory_rules: 2180, data_source_profile: true },
      top_missing_data_components: [{ data_component: 'File Modification', techniques: 1 }],
      techniques: [
        { technique: 'T1059.001', technique_name: 'PowerShell', tactic: 'TA0002', status: 'COVERED', existing_rules: [{ title: 'PowerShell download', match: 'exact' }], existing_rule_count: 1, generated_rule_available: true, required_data_components: ['Process Creation'], available_data_components: ['Process Creation'], missing_data_components: [], log_sources: ['WinEventLog:Sysmon'] },
        { technique: 'T1486', technique_name: 'Data Encrypted for Impact', tactic: 'TA0040', status: 'BLIND', existing_rules: [], existing_rule_count: 0, generated_rule_available: false, required_data_components: ['File Modification'], available_data_components: [], missing_data_components: ['File Modification'], log_sources: [] },
      ],
    });
    render(<CoverageGaps />);
    expect(await screen.findByText('50%')).toBeInTheDocument();
    expect(screen.getByText('BLIND')).toBeInTheDocument();
    expect(screen.getByText('PowerShell download')).toBeInTheDocument();
    expect(screen.getByText('File Modification · 1')).toBeInTheDocument();
    fireEvent.click(await screen.findByLabelText('Process Creation'));
    fireEvent.click(screen.getByRole('button', { name: /Save selection/ }));
    await waitFor(() => expect(save).toHaveBeenCalledWith(['Process Creation']));
  });
});
