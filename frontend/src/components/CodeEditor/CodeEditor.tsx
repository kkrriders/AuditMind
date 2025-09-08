'use client';

import { Editor } from '@monaco-editor/react';
import { useState } from 'react';

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language?: string;
  theme?: 'light' | 'dark';
  className?: string;
}

export default function CodeEditor({ 
  value, 
  onChange, 
  language = 'javascript', 
  theme = 'light',
  className = '' 
}: CodeEditorProps) {
  const [isLoading, setIsLoading] = useState(true);

  const handleEditorDidMount = () => {
    setIsLoading(false);
  };

  const handleChange = (value: string | undefined) => {
    onChange(value || '');
  };

  return (
    <div className={`relative border rounded-lg overflow-hidden ${className}`}>
      {isLoading && (
        <div className="absolute inset-0 bg-gray-100 dark:bg-gray-800 flex items-center justify-center z-10">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      )}
      <Editor
        height="400px"
        language={language}
        theme={theme === 'dark' ? 'vs-dark' : 'light'}
        value={value}
        onChange={handleChange}
        onMount={handleEditorDidMount}
        options={{
          minimap: { enabled: false },
          fontSize: 14,
          lineNumbers: 'on',
          roundedSelection: false,
          scrollBeyondLastLine: false,
          automaticLayout: true,
          wordWrap: 'on',
          bracketPairColorization: {
            enabled: true
          }
        }}
      />
    </div>
  );
}