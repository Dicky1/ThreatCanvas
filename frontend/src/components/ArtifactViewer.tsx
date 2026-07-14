import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface ArtifactViewerProps {
  code: string;
  language: string;
}

export default function ArtifactViewer({ code, language }: ArtifactViewerProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group bg-background border border-gray-700 rounded-lg overflow-hidden">
      <div className="flex justify-between items-center px-4 py-2 bg-gray-800/50 border-b border-gray-700">
        <span className="text-xs font-mono text-gray-400 uppercase">{language}</span>
        <button 
          onClick={handleCopy}
          className="text-gray-400 hover:text-white transition-colors"
        >
          {copied ? <Check className="w-4 h-4 text-accent" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>
      <pre className="p-4 text-sm font-mono text-gray-300 overflow-x-auto min-h-[100px]">
        <code>{code || 'No artifact generated yet.'}</code>
      </pre>
    </div>
  );
}