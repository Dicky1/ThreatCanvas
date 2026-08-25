import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { MetricCard, PageHeader, StatusBadge } from './Primitives';

describe('shared security UI primitives', () => {
  it('renders page context and semantic status', () => {
    render(<><PageHeader eyebrow="Analysis" title="Attack Graph" description="Graph overview" /><StatusBadge tone="good">ATT&CK VERIFIED</StatusBadge></>);
    expect(screen.getByRole('heading', { name: 'Attack Graph' })).toBeInTheDocument();
    expect(screen.getByText('ATT&CK VERIFIED')).toHaveClass('status-good');
  });

  it('renders metric values without inventing a fallback', () => {
    render(<MetricCard label="Current risk" value="Not available" detail="Backend support required" />);
    expect(screen.getByText('Not available')).toBeInTheDocument();
    expect(screen.getByText('Backend support required')).toBeInTheDocument();
  });
});
