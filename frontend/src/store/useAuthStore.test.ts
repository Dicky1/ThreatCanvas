import { describe, expect, it } from 'vitest';
import { useAuthStore } from './useAuthStore';
import { useThreatStore } from './useThreatStore';

describe('useAuthStore', () => {
  it('clears the active scenario on logout so it never leaks to the next account', () => {
    useThreatStore.setState({ scenarioId: 'alice-scenario', scenarioInput: 'secret narrative' });
    useAuthStore.getState().logout();
    expect(useThreatStore.getState().scenarioId).toBeNull();
    expect(useThreatStore.getState().scenarioInput).toBe('');
  });

  it('clears the active scenario when the API reports 401', () => {
    useThreatStore.setState({ scenarioId: 'stale' });
    window.dispatchEvent(new CustomEvent('tc:unauthorized'));
    expect(useThreatStore.getState().scenarioId).toBeNull();
  });
});
