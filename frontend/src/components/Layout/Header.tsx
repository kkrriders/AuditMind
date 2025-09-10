'use client';

import { Moon, Sun, Shield } from 'lucide-react';

interface HeaderProps {
  theme: 'light' | 'dark';
  onThemeToggle: () => void;
}

export default function Header({ theme, onThemeToggle }: HeaderProps) {
  return (
    <header style={{borderBottomColor: 'var(--border-default)', backgroundColor: 'var(--bg-card)'}} className="border-b">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{backgroundColor: 'var(--accent-primary)'}}>
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">AuditMind</h1>
              <p className="text-sm" style={{color: 'var(--text-secondary)'}}>Security Code Analyzer</p>
            </div>
          </div>
          
          <button
            onClick={onThemeToggle}
            className="p-2 rounded-lg border transition-colors hover:transform hover:scale-105"
            style={{borderColor: 'var(--border-default)', backgroundColor: 'transparent'}}
            aria-label="Toggle theme"
          >
            {theme === 'light' ? (
              <Moon className="w-5 h-5" style={{color: 'var(--text-secondary)'}} />
            ) : (
              <Sun className="w-5 h-5" style={{color: 'var(--text-secondary)'}} />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}