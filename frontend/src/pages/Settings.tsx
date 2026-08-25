import React, { useState } from 'react';
import { Save, Key, Palette, Shield } from 'lucide-react';

export default function Settings() {
  // State untuk menyimpan nilai input pengaturan
  const [config, setConfig] = useState({
    llmModel: 'gpt-4-turbo',
    defaultArtifact: 'sigma',
    mitreVersion: 'v14.1',
    theme: 'dark'
  });

  const [isSaving, setIsSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setConfig(prev => ({ ...prev, [name]: value }));
  };

  const handleSave = () => {
    setIsSaving(true);
    localStorage.setItem('tc_preferences', JSON.stringify(config));
    setIsSaving(false);
    setSaved(true);
  };

  return (
    <div className="p-6 text-gray-100 h-full flex flex-col overflow-auto">
      {/* Header */}
      <div className="mb-8 flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Settings</h2>
          <p className="text-gray-400 text-sm">Konfigurasi engine ThreatCanvas, API keys, dan preferensi deteksi.</p>
        </div>
        <button 
          onClick={handleSave}
          disabled={isSaving}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          {isSaving ? 'Menyimpan...' : saved ? 'Tersimpan lokal' : 'Simpan Perubahan'}
        </button>
      </div>

      <div className="max-w-4xl space-y-6">
        
        {/* API & Engine Configuration */}
        <section className="bg-surface border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4 border-b border-gray-700 pb-3">
            <Key className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-medium text-gray-200">API & Engine Configuration</h3>
          </div>
          
          <div className="grid grid-cols-1 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">LLM API Key</label>
              <input
                type="text"
                value="Managed by backend environment"
                readOnly
                aria-label="API key management status"
                className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-gray-200 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
                placeholder="Masukkan API Key Anda..."
              />
              <p className="text-xs text-gray-500 mt-1">No API key is displayed or stored in the browser. Configure provider credentials through the backend environment.</p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">Default LLM Model</label>
              <select 
                name="llmModel"
                value={config.llmModel}
                onChange={handleChange}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-gray-200 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
              >
                <option value="gpt-4-turbo">GPT-4 Turbo (Recommended)</option>
                <option value="gpt-3.5-turbo">GPT-3.5 Turbo (Faster)</option>
                <option value="claude-3-opus">Claude 3 Opus</option>
                <option value="local-llama3">Local Llama 3 (Ollama)</option>
              </select>
            </div>
          </div>
        </section>

        {/* Detection Preferences */}
        <section className="bg-surface border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4 border-b border-gray-700 pb-3">
            <Shield className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-medium text-gray-200">Detection Preferences</h3>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">Format Artefak Default</label>
              <select 
                name="defaultArtifact"
                value={config.defaultArtifact}
                onChange={handleChange}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-gray-200 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
              >
                <option value="sigma">Sigma Rule (Generic)</option>
                <option value="kql">Kusto Query Language (KQL / Sentinel)</option>
                <option value="spl">Splunk Processing Language (SPL)</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">MITRE ATT&CK Framework</label>
              <select 
                name="mitreVersion"
                value={config.mitreVersion}
                onChange={handleChange}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-gray-200 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
              >
                <option value="v14.1">Version 14.1 (Latest)</option>
                <option value="v13.1">Version 13.1</option>
                <option value="v12">Version 12</option>
              </select>
            </div>
          </div>
        </section>

        {/* UI / Appearance */}
        <section className="bg-surface border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4 border-b border-gray-700 pb-3">
            <Palette className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-medium text-gray-200">Appearance</h3>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Tema Antarmuka</label>
            <select 
              name="theme"
              value={config.theme}
              onChange={handleChange}
              className="w-full md:w-1/2 bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-gray-200 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
            >
              <option value="dark">Dark Mode (Default)</option>
              <option value="light" disabled>Light Mode (Coming Soon)</option>
            </select>
          </div>
        </section>

      </div>
    </div>
  );
}