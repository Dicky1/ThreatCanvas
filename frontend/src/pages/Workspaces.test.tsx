import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import Workspaces from './Workspaces';

describe('Workspaces', () => {
  afterEach(() => vi.restoreAllMocks());

  it('creates a workspace and adds a member', async () => {
    const ws = { id: 'w1', name: 'SOC Team', role: 'owner' as const, members: 1, scenarios: 0, created_at: '' };
    vi.spyOn(api, 'workspaces').mockResolvedValueOnce([]).mockResolvedValue([ws]);
    const create = vi.spyOn(api, 'createWorkspace').mockResolvedValue(ws);
    vi.spyOn(api, 'workspaceMembers').mockResolvedValue([{ user_id: 'u1', username: 'alice', full_name: 'Alice', role: 'owner', you: true }]);
    const add = vi.spyOn(api, 'addWorkspaceMember').mockResolvedValue({});
    render(<Workspaces />);
    fireEvent.change(await screen.findByPlaceholderText('e.g. SOC Team'), { target: { value: 'SOC Team' } });
    fireEvent.click(screen.getByRole('button', { name: /Create workspace/ }));
    await waitFor(() => expect(create).toHaveBeenCalledWith('SOC Team'));
    expect(await screen.findByText('alice (you)')).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'bob' } });
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'editor' } });
    fireEvent.click(screen.getByRole('button', { name: /Add member/ }));
    await waitFor(() => expect(add).toHaveBeenCalledWith('w1', 'bob', 'editor'));
  });
});
