import React, { useState, useRef, useEffect } from 'react';
import { Bot, Send, User, Loader2 } from 'lucide-react';
import { api } from '../api/client';
import ReactMarkdown from 'react-markdown';

interface ScenarioChatProps {
  scenarioId: string;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export default function ScenarioChat({ scenarioId }: ScenarioChatProps) {
  const [messages, setMessages] = useState<Message[]>([
    { role: 'assistant', content: 'Halo! Saya AI Copilot Anda. Ada yang ingin ditanyakan terkait skenario ancaman ini?' }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;
    
    const userMsg = input.trim();
    setInput('');
    const newMessages: Message[] = [...messages, { role: 'user', content: userMsg }];
    setMessages(newMessages);
    setIsLoading(true);

    try {
      const response = await api.copilotChat(scenarioId, newMessages);
      setMessages([...newMessages, { role: 'assistant', content: response.reply }]);
    } catch (err) {
      console.error(err);
      setMessages([...newMessages, { role: 'assistant', content: '*Maaf, terjadi kesalahan saat menghubungi AI.*' }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="flex flex-col h-[700px] bg-background border border-gray-800 rounded-xl overflow-hidden shadow-xl">
      <div className="bg-gray-800 p-4 flex items-center border-b border-gray-700">
        <Bot className="text-primary mr-3" />
        <h3 className="text-lg font-semibold text-white">AI Copilot</h3>
      </div>
      
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, idx) => (
          <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`flex max-w-[80%] ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
              <div className={`flex-shrink-0 h-8 w-8 rounded-full flex items-center justify-center ${msg.role === 'user' ? 'bg-primary ml-3' : 'bg-gray-700 mr-3'}`}>
                {msg.role === 'user' ? <User size={16} className="text-white" /> : <Bot size={16} className="text-primary" />}
              </div>
              <div className={`p-3 rounded-lg ${msg.role === 'user' ? 'bg-primary text-white' : 'bg-gray-800 text-gray-200'}`}>
                <div className="prose prose-invert prose-sm">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              </div>
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex justify-start">
            <div className="flex max-w-[80%] flex-row">
              <div className="flex-shrink-0 h-8 w-8 rounded-full flex items-center justify-center bg-gray-700 mr-3">
                <Bot size={16} className="text-primary" />
              </div>
              <div className="p-3 rounded-lg bg-gray-800 text-gray-200 flex items-center">
                <Loader2 size={16} className="animate-spin text-primary" />
                <span className="ml-2 text-sm">Mengetik...</span>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <div className="p-4 bg-gray-900 border-t border-gray-800 flex gap-2">
        <textarea
          rows={1}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Tanyakan sesuatu tentang grafik ancaman ini..."
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg p-3 text-white focus:ring-2 focus:ring-primary outline-none resize-none"
        />
        <button
          onClick={handleSend}
          disabled={!input.trim() || isLoading}
          className="bg-primary hover:bg-blue-600 text-white p-3 rounded-lg flex items-center justify-center disabled:opacity-50 transition-colors"
        >
          <Send size={20} />
        </button>
      </div>
    </div>
  );
}
