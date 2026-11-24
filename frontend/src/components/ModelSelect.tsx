import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { LLMProfileInfo } from '../types/api';
import { useThreatStore } from '../store/useThreatStore';

/** LLM model picker; hidden when the server has only one profile. */
export default function ModelSelect() {
  const { modelProfile, setModelProfile } = useThreatStore();
  const [profiles, setProfiles] = useState<LLMProfileInfo[]>([]);
  const [fallback, setFallback] = useState<string>('');

  useEffect(() => {
    api.llmProfiles()
      .then((result) => {
        setProfiles(result.profiles);
        setFallback(result.default);
        // Forget a stored choice the server no longer offers.
        if (modelProfile && !result.profiles.some((p) => p.name === modelProfile)) setModelProfile(null);
      })
      .catch(() => setProfiles([]));
  }, [modelProfile, setModelProfile]);

  if (profiles.length < 2) return null;
  return (
    <label className="inline-actions" style={{ fontSize: '.78rem', color: '#9fb3bd' }}>
      Model
      <select
        aria-label="LLM model"
        value={modelProfile ?? fallback}
        onChange={(e) => setModelProfile(e.target.value === fallback ? null : e.target.value)}
        className="bg-background border border-gray-700 rounded-md px-2 py-1 text-gray-100"
      >
        {profiles.map((p) => <option key={p.name} value={p.name}>{p.name}{p.local ? ' (local)' : ''}{p.name === fallback ? ' · default' : ''}</option>)}
      </select>
    </label>
  );
}
