'use client';

import { useState } from 'react';
import { Play, Upload, ArrowLeft, MessageCircle } from 'lucide-react';
import CodeEditor from '@/components/CodeEditor';
import RiskDashboard from '@/components/RiskDashboard';
import { useAnalyzeCode, useHealth } from '@/hooks/useAnalysis';
import { AnalysisResult } from '@/utils/api';

interface AnalysisPageProps {
  onBack: () => void;
  onOpenChat: () => void;
  analysisContext?: AnalysisResult | null;
}

export default function AnalysisPage({ onBack, onOpenChat, analysisContext }: AnalysisPageProps) {
  const [code, setCode] = useState('// Paste your code here for security analysis\nfunction processUserInput(userInput) {\n  // Potentially unsafe code example\n  eval(userInput);\n  document.innerHTML = userInput;\n  return userInput;\n}');
  const [language, setLanguage] = useState('javascript');
  const [result, setResult] = useState<AnalysisResult | null>(analysisContext || null);

  const analyzeCodeMutation = useAnalyzeCode();
  const { data: healthData } = useHealth();

  const handleAnalyze = async () => {
    if (!code.trim()) {
      alert('Please enter some code to analyze');
      return;
    }

    try {
      const result = await analyzeCodeMutation.mutateAsync({
        code,
        language,
        model: 'gpt_oss_20b'
      });
      setResult(result);
    } catch (error) {
      console.error('Analysis failed:', error);
      alert('Analysis failed. Please check your connection and try again.');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Navigation Bar */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 sm:px-6 lg:px-8 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="flex items-center gap-2 px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Welcome
            </button>
            <div className="h-6 w-px bg-gray-300 dark:bg-gray-600" />
            <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
              Security Analysis
            </h1>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
              <div className={`w-2 h-2 rounded-full ${healthData?.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'}`}></div>
              {healthData?.status === 'healthy' ? 'Backend Online' : 'Backend Offline'}
            </div>
            <button
              onClick={onOpenChat}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
            >
              <MessageCircle className="w-4 h-4" />
              Ask Expert
            </button>
          </div>
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left Column - Code Editor */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Code Editor</h2>
              <div className="flex items-center gap-2">
                <select
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                  className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  <option value="javascript">JavaScript</option>
                  <option value="python">Python</option>
                  <option value="typescript">TypeScript</option>
                  <option value="java">Java</option>
                  <option value="go">Go</option>
                  <option value="rust">Rust</option>
                </select>
              </div>
            </div>
            
            <CodeEditor
              value={code}
              onChange={setCode}
              language={language}
              theme="light"
              className="min-h-[400px]"
            />

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <button
                  onClick={handleAnalyze}
                  disabled={analyzeCodeMutation.isPending || !code.trim()}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg transition-colors"
                >
                  <Play size={16} />
                  {analyzeCodeMutation.isPending ? 'Analyzing...' : 'Analyze Code'}
                </button>
                
                <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg transition-colors">
                  <Upload size={16} />
                  Upload File
                </button>
              </div>
            </div>

            <div className="text-sm text-gray-500 dark:text-gray-400">
              Lines: {code.split('\n').length} | Characters: {code.length}
            </div>
          </div>

          {/* Right Column - Risk Dashboard */}
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Security Analysis</h2>
            <RiskDashboard 
              result={result} 
              isLoading={analyzeCodeMutation.isPending}
            />
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-12 pt-8 border-t border-gray-200 dark:border-gray-700 text-center text-sm text-gray-600 dark:text-gray-400">
          <p>AuditMind - Powered by AI Security Analysis</p>
        </footer>
      </main>
    </div>
  );
}