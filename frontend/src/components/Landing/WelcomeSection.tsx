'use client';

import { Shield, Zap, Search, MessageSquare, ArrowRight, Play } from 'lucide-react';

interface WelcomeSectionProps {
  onStartAnalysis: () => void;
  onOpenChat: () => void;
}

export default function WelcomeSection({ onStartAnalysis, onOpenChat }: WelcomeSectionProps) {
  return (
    <div className="min-h-screen gradient-primary">
      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
        <div className="text-center">
          <div className="flex justify-center mb-8">
            <div className="relative">
              <div className="w-24 h-24 gradient-accent rounded-full flex items-center justify-center shadow-xl">
                <Shield className="w-12 h-12 text-white" />
              </div>
              <div className="absolute -top-2 -right-2 w-8 h-8 rounded-full flex items-center justify-center" style={{backgroundColor: 'var(--accent-secondary)'}}>
                <Zap className="w-4 h-4 text-white" />
              </div>
            </div>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            Welcome to{' '}
            <span className="text-accent">
              AuditMind
            </span>
          </h1>
          
          <p className="text-xl mb-8 max-w-3xl mx-auto leading-relaxed" style={{color: 'var(--text-secondary)'}}>
            Your AI-powered security companion that analyzes code, documents, and systems to identify 
            vulnerabilities before they become problems. Get instant insights and actionable recommendations.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <button
              onClick={onStartAnalysis}
              className="group btn-primary flex items-center gap-2 px-8 py-4 rounded-xl text-lg hover:transform hover:scale-105"
            >
              <Play className="w-5 h-5" />
              Start Security Analysis
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            
            <button
              onClick={onOpenChat}
              className="btn-secondary flex items-center gap-2 px-8 py-4 rounded-xl text-lg hover:transform hover:scale-105"
            >
              <MessageSquare className="w-5 h-5" />
              Ask Security Expert
            </button>
          </div>
        </div>
      </div>
      
      {/* Features Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Why Choose AuditMind?
          </h2>
          <p className="text-lg max-w-2xl mx-auto" style={{color: 'var(--text-secondary)'}}>
            Powered by advanced AI and security expertise, AuditMind provides comprehensive analysis that goes beyond simple pattern matching.
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {/* Feature 1 */}
          <div className="pro-card p-8 rounded-2xl transition-all duration-200 hover:transform hover:scale-105">
            <div className="w-12 h-12 rounded-lg flex items-center justify-center mb-6" style={{backgroundColor: 'var(--accent-primary)'}}>
              <Search className="w-6 h-6 text-white" />
            </div>
            <h3 className="text-xl font-semibold text-white mb-4">
              Deep Code Analysis
            </h3>
            <p className="leading-relaxed" style={{color: 'var(--text-secondary)'}}>
              Advanced pattern recognition and AI analysis to detect security vulnerabilities, 
              privacy issues, and compliance violations in your code.
            </p>
          </div>
          
          {/* Feature 2 */}
          <div className="pro-card p-8 rounded-2xl transition-all duration-200 hover:transform hover:scale-105">
            <div className="w-12 h-12 rounded-lg flex items-center justify-center mb-6" style={{backgroundColor: 'var(--accent-purple)'}}>
              <MessageSquare className="w-6 h-6 text-white" />
            </div>
            <h3 className="text-xl font-semibold text-white mb-4">
              AI Security Expert
            </h3>
            <p className="leading-relaxed" style={{color: 'var(--text-secondary)'}}>
              Chat with our AI security assistant to get personalized recommendations, 
              understand vulnerabilities, and learn best practices.
            </p>
          </div>
          
          {/* Feature 3 */}
          <div className="pro-card p-8 rounded-2xl transition-all duration-200 hover:transform hover:scale-105">
            <div className="w-12 h-12 rounded-lg flex items-center justify-center mb-6" style={{backgroundColor: 'var(--accent-secondary)'}}>
              <Zap className="w-6 h-6 text-white" />
            </div>
            <h3 className="text-xl font-semibold text-white mb-4">
              Instant Insights
            </h3>
            <p className="leading-relaxed" style={{color: 'var(--text-secondary)'}}>
              Get immediate feedback with detailed explanations, severity ratings, 
              and actionable mitigation strategies for every identified risk.
            </p>
          </div>
        </div>
      </div>
      
      {/* CTA Section */}
      <div className="gradient-accent py-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
            Ready to Secure Your Code?
          </h2>
          <p className="text-xl mb-8 max-w-2xl mx-auto" style={{color: 'rgba(255, 255, 255, 0.9)'}}>
            Join thousands of developers who trust AuditMind to keep their applications secure. 
            Start your first security analysis now.
          </p>
          <button
            onClick={onStartAnalysis}
            className="group inline-flex items-center gap-2 px-8 py-4 bg-white rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 text-lg font-semibold hover:bg-gray-100 hover:transform hover:scale-105"
            style={{color: 'var(--accent-primary)'}}
          >
            <Shield className="w-5 h-5" />
            Begin Security Analysis
            <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
          </button>
        </div>
      </div>
    </div>
  );
}