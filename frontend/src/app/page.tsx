'use client';

import { useState } from 'react';
import WelcomeSection from '@/components/Landing/WelcomeSection';
import AnalysisPage from '@/components/Analysis/AnalysisPage';
import Chatbot from '@/components/Chatbot';
import { Header } from '@/components/Layout';
import { AnalysisResult } from '@/utils/api';

export default function Home() {
  const [currentView, setCurrentView] = useState<'welcome' | 'analysis'>('welcome');
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [result] = useState<AnalysisResult | null>(null);
  const [isChatOpen, setIsChatOpen] = useState(false);

  const handleStartAnalysis = () => {
    setCurrentView('analysis');
  };

  const handleBackToWelcome = () => {
    setCurrentView('welcome');
  };

  const handleThemeToggle = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    document.documentElement.classList.toggle('dark', newTheme === 'dark');
  };

  return (
    <div className={`${theme === 'dark' ? 'dark' : ''}`}>
      {currentView === 'analysis' && (
        <Header theme={theme} onThemeToggle={handleThemeToggle} />
      )}
      
      {currentView === 'welcome' ? (
        <WelcomeSection 
          onStartAnalysis={handleStartAnalysis}
          onOpenChat={() => setIsChatOpen(true)}
        />
      ) : (
        <AnalysisPage 
          onBack={handleBackToWelcome}
          onOpenChat={() => setIsChatOpen(true)}
          analysisContext={result}
        />
      )}

      {/* Chatbot */}
      <Chatbot
        isOpen={isChatOpen}
        onClose={() => setIsChatOpen(false)}
        analysisContext={result ? JSON.stringify({
          summary: result.summary,
          risksFound: result.total_risks || 0,
          riskBreakdown: result.risk_breakdown,
          risks: result.risks.slice(0, 5),
          analysisMethod: result.analysis_method
        }, null, 2) : undefined}
      />
    </div>
  );
}
