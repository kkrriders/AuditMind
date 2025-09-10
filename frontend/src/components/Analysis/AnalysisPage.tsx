'use client';

import { useState } from 'react';
import { Play, Upload, ArrowLeft, MessageCircle } from 'lucide-react';
import CodeEditor from '@/components/CodeEditor';
import RiskDashboard from '@/components/RiskDashboard';
import { useAnalyzeCode } from '@/hooks/useAnalysis';
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
    <div className="min-h-screen" style={{backgroundColor: 'var(--bg-primary)'}}>
      {/* Navigation Bar */}
      <div className="border-b px-4 sm:px-6 lg:px-8 py-4" style={{backgroundColor: 'var(--bg-card)', borderBottomColor: 'var(--border-default)'}}>
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="flex items-center gap-2 px-4 py-2 transition-colors hover:transform hover:scale-105"
              style={{color: 'var(--text-secondary)'}}
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Welcome
            </button>
            <div className="h-6 w-px" style={{backgroundColor: 'var(--border-default)'}} />
            <h1 className="text-xl font-semibold text-white">
              Security Analysis
            </h1>
          </div>
          
          <div className="flex items-center gap-4">
            <button
              onClick={onOpenChat}
              className="btn-secondary flex items-center gap-2 px-4 py-2 rounded-lg hover:transform hover:scale-105"
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