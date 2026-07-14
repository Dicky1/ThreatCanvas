import React, { useState } from 'react';
import { Search, BookOpen, ExternalLink, Terminal, ShieldAlert, Cloud, Copy } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

// --- DATA MOCKUP LIBRARY ---
// Anda bisa memindahkan ini ke database nantinya, tapi untuk sekarang kita hardcode.
const CATEGORIES = ['All', 'Ransomware', 'APT Campaigns', 'Insider Threat', 'Cloud Security'];

const PROMPT_DATABASE = [
  {
    id: 'lib-1',
    title: 'Basic Ransomware Lifecycle',
    category: 'Ransomware',
    icon: ShieldAlert,
    description: 'Simulasi alur serangan ransomware standar dari initial access hingga enkripsi.',
    prompt: 'An employee receives a phishing email with a malicious ZIP attachment. Upon extraction, a payload is executed that disables local antivirus, connects to a C2 server, and encrypts all files in the Documents folder, leaving a ransom note.'
  },
  {
    id: 'lib-2',
    title: 'APT29 (Cozy Bear) Stealth Access',
    category: 'APT Campaigns',
    icon: Terminal,
    description: 'Fokus pada teknik initial access yang senyap dan lateral movement menggunakan Pass-the-Hash.',
    prompt: 'Adversary gains initial access by exploiting a vulnerable public-facing web server (CVE-2023-XXXX). They drop a web shell for persistence, dump LSASS memory to steal credentials, and use pass-the-hash to move laterally to the domain controller.'
  },
  {
    id: 'lib-3',
    title: 'Data Exfiltration by Insider',
    category: 'Insider Threat',
    icon: BookOpen,
    description: 'Skenario di mana karyawan mencuri data sensitif sebelum keluar dari perusahaan.',
    prompt: 'An internal user connects a personal USB flash drive. They compress sensitive financial PDFs and Excel files into a password-protected 7z archive, and upload it to a personal Google Drive account before deleting the local event logs.'
  },
  {
    id: 'lib-4',
    title: 'AWS S3 Bucket Compromise',
    category: 'Cloud Security',
    icon: Cloud,
    description: 'Simulasi eksploitasi miskonfigurasi pada penyimpanan cloud publik.',
    prompt: 'Attacker discovers a misconfigured public AWS S3 bucket. They enumerate the bucket contents, download sensitive customer data, and attempt to upload a malicious payload to compromise other users.'
  }
];

export default function PromptLibrary() {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');
  const navigate = useNavigate();

  // Filter berdasarkan pencarian ATAU kategori
  const filteredPrompts = PROMPT_DATABASE.filter(item => {
    const matchesSearch = item.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          item.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = activeCategory === 'All' || item.category === activeCategory;
    return matchesSearch && matchesCategory;
  });

  const handleLoad = (promptText: string) => {
    // Kita mengirim format data yang sama seperti halaman History ({ original_input: ... })
    // Sehingga kode di Dashboard.tsx yang kita buat sebelumnya bisa langsung membacanya tanpa diubah!
    navigate('/', { state: { loadedScenario: { original_input: promptText } } });
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Prompt disalin ke clipboard!');
  };

  return (
    <div className="p-6 text-gray-100 h-full flex flex-col">
      {/* Header */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Prompt Library</h2>
          <p className="text-gray-400 text-sm">Koleksi skenario ancaman standar (templates) untuk diuji coba di Canvas.</p>
        </div>
        
        {/* Search */}
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-4 w-4 text-gray-500" />
          </div>
          <input
            type="text"
            className="bg-gray-900 border border-gray-700 text-gray-200 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-64 pl-10 p-2.5"
            placeholder="Cari template..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
        {CATEGORIES.map(cat => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap ${
              activeCategory === cat 
                ? 'bg-blue-600 text-white border border-blue-500' 
                : 'bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-700 hover:text-gray-200'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Prompt Grid */}
      <div className="flex-1 overflow-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredPrompts.map((item) => (
            <div key={item.id} className="bg-surface border border-gray-700 rounded-xl p-5 flex flex-col hover:border-blue-500 transition-all group">
              
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-gray-800 rounded-lg text-blue-400">
                  <item.icon className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-medium text-gray-200 group-hover:text-blue-400 transition-colors">{item.title}</h3>
                  <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded border border-gray-700">{item.category}</span>
                </div>
              </div>

              <p className="text-gray-400 text-sm mb-4 flex-1">
                {item.description}
              </p>

              <div className="bg-gray-900 rounded-lg p-3 text-sm text-gray-300 font-mono text-xs border border-gray-800 mb-4 line-clamp-3">
                {item.prompt}
              </div>

              <div className="flex justify-end gap-2 mt-auto">
                <button 
                  onClick={() => handleCopy(item.prompt)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded-md text-sm transition-colors"
                >
                  <Copy className="w-4 h-4" /> Copy
                </button>
                <button 
                  onClick={() => handleLoad(item.prompt)}
                  className="flex items-center gap-1.5 bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 px-4 py-1.5 rounded-md text-sm transition-colors font-medium"
                >
                  <ExternalLink className="w-4 h-4" /> Use Template
                </button>
              </div>

            </div>
          ))}
          
          {filteredPrompts.length === 0 && (
            <div className="col-span-2 text-center py-10 text-gray-500">
              Tidak ada template yang cocok dengan pencarian Anda.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}