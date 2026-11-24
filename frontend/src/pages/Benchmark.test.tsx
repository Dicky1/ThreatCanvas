import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import Benchmark from './Benchmark';

const summary = { cases: 1, valid_rate: 1, exact_f1: 0.9, exact_precision: 1, exact_recall: 0.8, parent_f1: 1, ordering: 1, avg_repair_attempts: 0.5, avg_latency_ms: 2100, errors: 0 };

describe('Benchmark', () => {
  afterEach(() => vi.restoreAllMocks());

  it('starts a model comparison and shows the report', async () => {
    vi.spyOn(api, 'benchmarkCases').mockResolvedValue([{ id: 'c1', title: 'Web shell', tags: [], narrative: 'x', expected_techniques: ['T1190'] }]);
    vi.spyOn(api, 'llmProfiles').mockResolvedValue({ default: 'gpt-4o', profiles: [{ name: 'gpt-4o', model: 'gpt-4o', mode: 'tools', local: false }, { name: 'llama', model: 'llama3.1', mode: 'json', local: true }] });
    vi.spyOn(api, 'benchmarkRuns').mockResolvedValue([]);
    const start = vi.spyOn(api, 'startBenchmark').mockResolvedValue({
      id: 'r1', status: 'done', profiles: ['gpt-4o', 'llama'], case_ids: null, error: null, created_at: '2026-11-24T10:00:00Z', finished_at: null,
      report: { cases: ['c1'], profiles: { 'gpt-4o': { summary, results: [] }, llama: { summary: { ...summary, exact_f1: 0.4 }, results: [] } } },
    });
    render(<Benchmark />);
    fireEvent.click(await screen.findByLabelText('Benchmark llama'));
    fireEvent.click(screen.getByRole('button', { name: /Run benchmark/ }));
    await waitFor(() => expect(start).toHaveBeenCalledWith(['gpt-4o', 'llama'], []));
    expect(await screen.findByText('90%')).toBeInTheDocument();
    expect(screen.getByText('40%')).toBeInTheDocument();
  });
});
