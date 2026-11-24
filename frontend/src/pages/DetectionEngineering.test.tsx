import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { useThreatStore } from '../store/useThreatStore';
import DetectionEngineering from './DetectionEngineering';

const dataset = { id: 'd1', name: 'empire_launcher_vbs', label: 'malicious' as const, technique_ids: ['T1059.005'], source_filename: 'e.zip', event_count: 2067, created_at: '2026-11-24' };

describe('DetectionEngineering', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    useThreatStore.getState().reset();
  });

  it('converts scenario rules and measures them on a selected dataset', async () => {
    useThreatStore.setState({ scenarioId: 'scn-1' });
    vi.spyOn(api, 'detectionTargets').mockResolvedValue([{ key: 'kql', label: 'Defender KQL', language: 'kql', description: '' }]);
    const convert = vi.spyOn(api, 'convertScenario').mockResolvedValue({
      target: 'kql', language: 'kql', sigma: 'title: PowerShell', errors: ['Other: not supported'],
      rules: [{ title: 'PowerShell', rule_id: null, techniques: ['T1059.001'], queries: ['DeviceProcessEvents | where FolderPath endswith "\\\\powershell.exe"'], error: null }],
    });
    vi.spyOn(api, 'validateArtifact').mockResolvedValue({ artifact_type: 'sigma', state: 'TESTED', stage_results: { syntax: true }, errors: [], metrics: { tp: 0, fp: 0, tn: 0, fn: 0, precision: 0, recall: 0, f1: 0 } });
    vi.spyOn(api, 'datasets').mockResolvedValue([dataset]);
    const evaluate = vi.spyOn(api, 'evaluateRules').mockResolvedValue({
      summary: { rules: 1, rules_with_errors: 0, malicious_datasets: 1, benign_datasets: 0, detected_malicious_datasets: 1, dataset_recall: 1, malicious_alerts: 2, benign_alerts: 0, alert_precision: 1 },
      rules: [{ title: 'PowerShell', rule_id: null, techniques: ['T1059.001'], error: null, malicious_hits: 2, benign_hits: 0, datasets: [{ dataset_id: 'd1', name: 'x', label: 'malicious', hits: 2, samples: [{ CommandLine: 'powershell -enc AAA' }] }] }],
      datasets: [{ dataset_id: 'd1', name: 'empire_launcher_vbs', label: 'malicious', technique_ids: [], event_count: 2067, alerts: 2, detected: true, relevant_rules: 1 }],
      techniques: [], truncated: false, elapsed_ms: 12, sigma: '',
    });

    render(<DetectionEngineering />);
    expect(await screen.findByText('title: PowerShell')).toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Defender KQL' }));
    await waitFor(() => expect(convert).toHaveBeenLastCalledWith('kql', 'scn-1'));
    expect(await screen.findByText(/FolderPath endswith/)).toBeInTheDocument();
    expect(screen.getByText('Other: not supported')).toBeInTheDocument();

    fireEvent.click(await screen.findByLabelText('Select empire_launcher_vbs'));
    fireEvent.click(screen.getByRole('button', { name: /Evaluate on 1 dataset/ }));
    await waitFor(() => expect(evaluate).toHaveBeenCalledWith({ scenario_id: 'scn-1', dataset_ids: ['d1'] }));
    expect(await screen.findByText('DETECTED')).toBeInTheDocument();
    expect(screen.getByText('powershell -enc AAA')).toBeInTheDocument();
  });

  it('works without an active scenario using custom Sigma', async () => {
    vi.spyOn(api, 'datasets').mockResolvedValue([dataset]);
    render(<DetectionEngineering />);
    expect(await screen.findByText('No active scenario')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Active scenario rules' })).toBeDisabled();
  });
});
