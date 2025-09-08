'use client';

import { User, Bot, Copy, Check, File as FileIcon, AlertTriangle, Shield, Info } from 'lucide-react';
import { useState } from 'react';
import { AnalysisResult } from '@/utils/api';

export interface Message extends Record<string, unknown> {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  isLoading?: boolean;
  attachedFile?: {
    name: string;
    size: number;
    type: string;
  };
  analysisResult?: AnalysisResult;
  fileInfo?: {
    filename: string;
    size: number;
    risks_found: number;
  };
}

interface ChatMessageProps {
  message: Message;
}

export default function ChatMessage({ message }: ChatMessageProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <AlertTriangle className="text-red-600" size={14} />;
      case 'high':
        return <AlertTriangle className="text-orange-600" size={14} />;
      case 'medium':
        return <AlertTriangle className="text-yellow-600" size={14} />;
      case 'low':
        return <Info className="text-blue-600" size={14} />;
      default:
        return <Shield className="text-gray-600" size={14} />;
    }
  };

  const isUser = message.role === 'user';

  return (
    <div className={`flex gap-3 p-4 ${isUser ? 'bg-blue-50 dark:bg-blue-900/10' : 'bg-gray-50 dark:bg-gray-800/50'}`}>
      <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
        isUser 
          ? 'bg-blue-600 text-white' 
          : 'bg-purple-600 text-white'
      }`}>
        {isUser ? <User size={16} /> : <Bot size={16} />}
      </div>
      
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {isUser ? 'You' : 'AuditMind AI'}
          </span>
          <span className="text-xs text-gray-500 dark:text-gray-400">
            {message.timestamp.toLocaleTimeString()}
          </span>
        </div>

        {/* File attachment display */}
        {message.attachedFile && (
          <div className="mb-3 p-3 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg">
            <div className="flex items-center gap-2">
              <FileIcon size={16} className="text-purple-600 dark:text-purple-400" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                  {message.attachedFile.name}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {formatFileSize(message.attachedFile.size)}
                </p>
              </div>
            </div>
          </div>
        )}
        
        <div className="prose prose-sm dark:prose-invert max-w-none">
          {message.isLoading ? (
            <div className="flex items-center gap-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-purple-600"></div>
              <span className="text-gray-500 dark:text-gray-400">AI is analyzing...</span>
            </div>
          ) : (
            <div className="whitespace-pre-wrap text-gray-700 dark:text-gray-300">
              {message.content}
            </div>
          )}
        </div>

        {/* Analysis results summary */}
        {message.fileInfo && message.analysisResult && (
          <div className="mt-3 p-3 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Shield size={16} className="text-purple-600 dark:text-purple-400" />
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                Analysis Summary
              </span>
            </div>
            
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="text-gray-600 dark:text-gray-400">
                File: <span className="font-medium">{message.fileInfo.filename}</span>
              </div>
              <div className="text-gray-600 dark:text-gray-400">
                Risks: <span className="font-medium">{message.fileInfo.risks_found}</span>
              </div>
            </div>

            {message.analysisResult.risks && message.analysisResult.risks.length > 0 && (
              <div className="mt-2">
                <p className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Top Risks:
                </p>
                <div className="space-y-1">
                  {message.analysisResult.risks.slice(0, 3).map((risk, index) => (
                    <div key={index} className="flex items-start gap-2 text-xs">
                      {getSeverityIcon(risk.severity)}
                      <span className="text-gray-600 dark:text-gray-400 line-clamp-2">
                        {risk.issue}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        
        {!message.isLoading && !isUser && (
          <button
            onClick={handleCopy}
            className="mt-2 flex items-center gap-1 px-2 py-1 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
          >
            {copied ? <Check size={12} /> : <Copy size={12} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
        )}
      </div>
    </div>
  );
}