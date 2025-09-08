'use client';

import { Shield, Zap, Search, MessageSquare, ArrowRight, Play } from 'lucide-react';

interface WelcomeSectionProps {
  onStartAnalysis: () => void;
  onOpenChat: () => void;
}

export default function WelcomeSection({ onStartAnalysis, onOpenChat }: WelcomeSectionProps) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
        <div className="text-center">
          <div className="flex justify-center mb-8">
            <div className="relative">
              <div className="w-24 h-24 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full flex items-center justify-center shadow-xl">
                <Shield className="w-12 h-12 text-white" />
              </div>
              <div className="absolute -top-2 -right-2 w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                <Zap className="w-4 h-4 text-white" />
              </div>
            </div>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-bold text-gray-900 dark:text-white mb-6">
            Welcome to{' '}
            <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              AuditMind
            </span>
          </h1>
          
          <p className="text-xl text-gray-600 dark:text-gray-300 mb-8 max-w-3xl mx-auto leading-relaxed">
            Your AI-powered security companion that analyzes code, documents, and systems to identify 
            vulnerabilities before they become problems. Get instant insights and actionable recommendations.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <button
              onClick={onStartAnalysis}
              className="group flex items-center gap-2 px-8 py-4 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 text-lg font-semibold"
            >
              <Play className="w-5 h-5" />
              Start Security Analysis
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            
            <button
              onClick={onOpenChat}
              className="flex items-center gap-2 px-8 py-4 border-2 border-gray-300 dark:border-gray-600 hover:border-purple-500 dark:hover:border-purple-400 text-gray-700 dark:text-gray-300 hover:text-purple-600 dark:hover:text-purple-400 rounded-xl transition-all duration-200 text-lg font-semibold bg-white dark:bg-gray-800"
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
          <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
            Why Choose AuditMind?
          </h2>
          <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
            Powered by advanced AI and security expertise, AuditMind provides comprehensive analysis that goes beyond simple pattern matching.
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {/* Feature 1 */}
          <div className="bg-white dark:bg-gray-800 p-8 rounded-2xl shadow-lg hover:shadow-xl transition-shadow duration-200 border border-gray-100 dark:border-gray-700">
            <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center mb-6">
              <Search className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Deep Code Analysis
            </h3>
            <p className="text-gray-600 dark:text-gray-300 leading-relaxed">
              Advanced pattern recognition and AI analysis to detect security vulnerabilities, 
              privacy issues, and compliance violations in your code.
            </p>
          </div>
          
          {/* Feature 2 */}
          <div className="bg-white dark:bg-gray-800 p-8 rounded-2xl shadow-lg hover:shadow-xl transition-shadow duration-200 border border-gray-100 dark:border-gray-700">
            <div className="w-12 h-12 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center mb-6">
              <MessageSquare className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              AI Security Expert
            </h3>
            <p className="text-gray-600 dark:text-gray-300 leading-relaxed">
              Chat with our AI security assistant to get personalized recommendations, 
              understand vulnerabilities, and learn best practices.
            </p>
          </div>
          
          {/* Feature 3 */}
          <div className="bg-white dark:bg-gray-800 p-8 rounded-2xl shadow-lg hover:shadow-xl transition-shadow duration-200 border border-gray-100 dark:border-gray-700">
            <div className="w-12 h-12 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center mb-6">
              <Zap className="w-6 h-6 text-green-600 dark:text-green-400" />
            </div>
            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Instant Insights
            </h3>
            <p className="text-gray-600 dark:text-gray-300 leading-relaxed">
              Get immediate feedback with detailed explanations, severity ratings, 
              and actionable mitigation strategies for every identified risk.
            </p>
          </div>
        </div>
      </div>
      
      {/* CTA Section */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-600 py-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
            Ready to Secure Your Code?
          </h2>
          <p className="text-xl text-blue-100 mb-8 max-w-2xl mx-auto">
            Join thousands of developers who trust AuditMind to keep their applications secure. 
            Start your first security analysis now.
          </p>
          <button
            onClick={onStartAnalysis}
            className="group inline-flex items-center gap-2 px-8 py-4 bg-white text-blue-600 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 text-lg font-semibold hover:bg-gray-50"
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