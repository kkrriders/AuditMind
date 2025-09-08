'use client';

import { Moon, Sun, Shield } from 'lucide-react';

interface HeaderProps {
  theme: 'light' | 'dark';
  onThemeToggle: () => void;
}

export default function Header({ theme, onThemeToggle }: HeaderProps) {
  return (
    <header className="border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">AuditMind</h1>
              <p className="text-sm text-gray-600 dark:text-gray-400">Security Code Analyzer</p>
            </div>
          </div>
          
          <button
            onClick={onThemeToggle}
            className="p-2 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            aria-label="Toggle theme"
          >
            {theme === 'light' ? (
              <Moon className="w-5 h-5 text-gray-600 dark:text-gray-400" />
            ) : (
              <Sun className="w-5 h-5 text-gray-600 dark:text-gray-400" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}