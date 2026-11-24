import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Plus, Trash2, UserPlus, Users } from 'lucide-react';
import { api } from '../api/client';
import type { WorkspaceMemberInfo, WorkspaceRole, WorkspaceSummary } from '../types/api';
import { EmptyState, ErrorState, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';

const message = (reason: unknown, fallback: string) => (reason instanceof Error ? reason.message : fallback);
const ROLES: WorkspaceRole[] = ['owner', 'editor', 'viewer'];

function Members({ workspace, onChange }: { workspace: WorkspaceSummary; onChange: () => void }) {
  const [members, setMembers] = useState<WorkspaceMemberInfo[]>([]);
  const [username, setUsername] = useState('');
  const [role, setRole] = useState<WorkspaceRole>('viewer');
  const [error, setError] = useState<string | null>(null);
  const isOwner = workspace.role === 'owner';

  const load = useCallback(() => {
    api.workspaceMembers(workspace.id).then(setMembers).catch((reason) => setError(message(reason, 'Unable to load members.')));
  }, [workspace.id]);
  useEffect(load, [load]);

  const act = async (action: () => Promise<unknown>) => {
    setError(null);
    try { await action(); load(); onChange(); } catch (reason) { setError(message(reason, 'Action failed.')); }
  };
  const add = (event: FormEvent) => {
    event.preventDefault();
    if (!username.trim()) return;
    act(async () => { await api.addWorkspaceMember(workspace.id, username.trim(), role); setUsername(''); });
  };

  return (
    <div style={{ marginTop: 12 }}>
      {error && <p className="form-error">{error}</p>}
      <div className="data-list">
        {members.map((member) => (
          <div className="data-row" key={member.user_id}>
            <div><strong>{member.username}{member.you ? ' (you)' : ''}</strong><small>{member.full_name}</small></div>
            <div className="inline-actions">
              {isOwner && !member.you ? (
                <select aria-label={`Role of ${member.username}`} value={member.role} onChange={(e) => act(() => api.updateWorkspaceMember(workspace.id, member.user_id, e.target.value as WorkspaceRole))} className="bg-background border border-gray-700 rounded-md px-2 py-1 text-gray-100 text-xs">
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              ) : <StatusBadge tone={member.role === 'owner' ? 'info' : 'neutral'}>{member.role.toUpperCase()}</StatusBadge>}
              {(isOwner || member.you) && (
                <button className="button button-quiet" aria-label={member.you ? 'Leave workspace' : `Remove ${member.username}`} onClick={() => { if (window.confirm(member.you ? 'Leave this workspace?' : `Remove ${member.username}?`)) act(() => api.removeWorkspaceMember(workspace.id, member.user_id)); }}><Trash2 size={14} /></button>
              )}
            </div>
          </div>
        ))}
      </div>
      {isOwner && (
        <form className="form-grid" style={{ marginTop: 12 }} onSubmit={add}>
          <label><span>Add member (username)</span><input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" maxLength={100} /></label>
          <label><span>Role</span><select value={role} onChange={(e) => setRole(e.target.value as WorkspaceRole)}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select></label>
          <div className="span-2"><button className="button button-secondary" disabled={!username.trim()}><UserPlus size={14} />Add member</button></div>
        </form>
      )}
    </div>
  );
}

export default function Workspaces() {
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.workspaces().then((rows) => { setWorkspaces(rows); setError(null); }).catch((reason) => setError(message(reason, 'Unable to load workspaces.')));
  }, []);
  useEffect(load, [load]);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    try { const created = await api.createWorkspace(name.trim()); setName(''); setOpen(created.id); load(); } catch (reason) { setError(message(reason, 'Unable to create workspace.')); }
  };
  const remove = async (workspace: WorkspaceSummary) => {
    if (!window.confirm(`Delete "${workspace.name}"? Shared scenarios go back to their creators.`)) return;
    try { await api.deleteWorkspace(workspace.id); load(); } catch (reason) { setError(message(reason, 'Unable to delete workspace.')); }
  };

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Manage / Team" title="Workspaces" description="Share scenarios with your team. Owners manage members; editors can share and delete scenarios; viewers can analyze them." action={<span className="page-icon"><Users size={18} /></span>} />
      {error && <ErrorState message={error} onRetry={load} />}
      <Panel title="Create a workspace">
        <form className="form-grid" onSubmit={create}>
          <label className="span-2"><span>Name</span><input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. SOC Team" maxLength={80} /></label>
          <div className="span-2"><button className="button button-primary" disabled={!name.trim()}><Plus size={14} />Create workspace</button></div>
        </form>
      </Panel>
      <Panel title="Your workspaces" description="Share a scenario from the Scenarios page.">
        {workspaces.length === 0 ? <EmptyState title="No workspaces yet" description="Create one, add colleagues, then share scenarios into it." /> : (
          <div className="data-list">
            {workspaces.map((workspace) => (
              <div key={workspace.id} className="panel" style={{ padding: 12 }}>
                <div className="data-row" style={{ border: 0, padding: 0 }}>
                  <button className="text-left" onClick={() => setOpen(open === workspace.id ? null : workspace.id)}>
                    <strong>{workspace.name}</strong><small>{workspace.members} member(s) · {workspace.scenarios} shared scenario(s)</small>
                  </button>
                  <div className="inline-actions">
                    <StatusBadge tone={workspace.role === 'owner' ? 'info' : 'neutral'}>{workspace.role.toUpperCase()}</StatusBadge>
                    {workspace.role === 'owner' && <button className="button button-quiet" aria-label={`Delete ${workspace.name}`} onClick={() => remove(workspace)}><Trash2 size={14} /></button>}
                  </div>
                </div>
                {open === workspace.id && <Members workspace={workspace} onChange={load} />}
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
