'use client';

import { useState, useRef, useEffect } from 'react';
import { Send, X, MessageCircle, Trash2, Paperclip, File as FileIcon } from 'lucide-react';
import ChatMessage, { Message } from './ChatMessage';
import { useChatMessage, useFileAnalysis } from '@/hooks/useChat';
import FileUpload, { UploadedFile } from './FileUpload';

interface ChatbotProps {
  isOpen: boolean;
  onClose: () => void;
  analysisContext?: string; // Current analysis results to provide context
}

export default function Chatbot({ isOpen, onClose, analysisContext }: ChatbotProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      role: 'assistant',
      content: 'Hello! I\'m your AI security assistant. I can help you understand security vulnerabilities, provide recommendations, explain analysis results, or answer any security-related questions. You can also upload files for analysis! How can I help you today?',
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [, setIsTyping] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [showFileUpload, setShowFileUpload] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const chatMutation = useChatMessage();
  const fileAnalysisMutation = useFileAnalysis();

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  const handleFileUpload = (file: UploadedFile) => {
    setUploadedFiles(prev => [...prev, file]);
  };

  const handleFileRemove = (fileId: string) => {
    setUploadedFiles(prev => prev.filter(file => file.id !== fileId));
  };

  const handleSendFile = async (file: UploadedFile, customMessage?: string) => {
    const message = customMessage || `Please analyze this file: ${file.name}`;
    
    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: message,
      timestamp: new Date(),
      attachedFile: {
        name: file.name,
        size: file.size,
        type: file.type
      }
    };

    const loadingMessage: Message = {
      id: (Date.now() + 1).toString(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      isLoading: true
    };

    setMessages(prev => [...prev, userMessage, loadingMessage]);
    setIsTyping(true);
    setShowFileUpload(false);

    try {
      const response = await fileAnalysisMutation.mutateAsync({
        filename: file.name,
        content: file.content,
        message: message,
        context: analysisContext,
        history: messages.slice(-6)
      });

      setMessages(prev => 
        prev.map(msg => 
          msg.id === loadingMessage.id 
            ? { 
                ...msg, 
                content: response.response, 
                isLoading: false,
                analysisResult: response.analysis_result,
                fileInfo: response.file_info
              }
            : msg
        )
      );

      // Remove the uploaded file after successful analysis
      setUploadedFiles(prev => prev.filter(f => f.id !== file.id));
    } catch {
      setMessages(prev => 
        prev.map(msg => 
          msg.id === loadingMessage.id 
            ? { 
                ...msg, 
                content: 'Sorry, I encountered an error analyzing your file. Please try again or check your connection.', 
                isLoading: false 
              }
            : msg
        )
      );
    } finally {
      setIsTyping(false);
    }
  };

  const handleSend = async () => {
    if (!input.trim() || chatMutation.isPending || fileAnalysisMutation.isPending) return;

    // If there are uploaded files, analyze them with the user's message
    if (uploadedFiles.length > 0) {
      for (const file of uploadedFiles) {
        await handleSendFile(file, input.trim() || undefined);
      }
      setInput('');
      return;
    }

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date()
    };

    const loadingMessage: Message = {
      id: (Date.now() + 1).toString(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      isLoading: true
    };

    setMessages(prev => [...prev, userMessage, loadingMessage]);
    setInput('');
    setIsTyping(true);

    try {
      const response = await chatMutation.mutateAsync({
        message: input.trim(),
        context: analysisContext,
        history: messages.slice(-6) // Last 6 messages for context
      });

      setMessages(prev => 
        prev.map(msg => 
          msg.id === loadingMessage.id 
            ? { ...msg, content: response.response, isLoading: false }
            : msg
        )
      );
    } catch {
      setMessages(prev => 
        prev.map(msg => 
          msg.id === loadingMessage.id 
            ? { 
                ...msg, 
                content: 'Sorry, I encountered an error. Please try again or check your connection.', 
                isLoading: false 
              }
            : msg
        )
      );
    } finally {
      setIsTyping(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const clearChat = () => {
    setMessages([{
      id: '1',
      role: 'assistant',
      content: 'Chat cleared! How can I help you with security analysis today?',
      timestamp: new Date()
    }]);
  };

  const suggestedQuestions = [
    "Explain the security risks found in my code",
    "How can I fix SQL injection vulnerabilities?",
    "What are best practices for API security?",
    "How do I implement secure authentication?",
    "What is XSS and how do I prevent it?"
  ];

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 backdrop-blur-sm flex items-end justify-end p-4 z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md h-[600px] flex flex-col border border-gray-200 dark:border-gray-700">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center">
              <MessageCircle size={16} className="text-white" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">Security Assistant</h3>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {chatMutation.isPending ? 'Typing...' : 'Online'}
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <button
              onClick={clearChat}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
              title="Clear chat"
            >
              <Trash2 size={16} />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto">
          <div className="space-y-0">
            {messages.map((message) => (
              <ChatMessage key={message.id} message={message} />
            ))}
            <div ref={messagesEndRef} />
          </div>

          {/* Suggested Questions (shown when no conversation) */}
          {messages.length <= 1 && (
            <div className="p-4 border-t border-gray-200 dark:border-gray-700">
              <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Suggested questions:
              </p>
              <div className="space-y-2">
                {suggestedQuestions.slice(0, 3).map((question, index) => (
                  <button
                    key={index}
                    onClick={() => setInput(question)}
                    className="block w-full text-left p-2 text-sm text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors"
                  >
                    {question}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* File Upload Section */}
        {showFileUpload && (
          <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
            <FileUpload
              onFileUpload={handleFileUpload}
              onFileRemove={handleFileRemove}
              uploadedFiles={uploadedFiles}
              disabled={chatMutation.isPending || fileAnalysisMutation.isPending}
            />
          </div>
        )}

        {/* Input */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <div className="flex gap-2">
            <div className="flex-1">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={uploadedFiles.length > 0 
                  ? "Ask me about the uploaded files..." 
                  : "Ask me about security, vulnerabilities, or upload files for analysis..."
                }
                className="w-full resize-none rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                rows={1}
                style={{ minHeight: '40px', maxHeight: '100px' }}
                disabled={chatMutation.isPending || fileAnalysisMutation.isPending}
              />
            </div>
            <div className="flex flex-col gap-1">
              <button
                onClick={() => setShowFileUpload(!showFileUpload)}
                className={`p-2 rounded-lg transition-colors flex items-center justify-center ${
                  showFileUpload 
                    ? 'bg-purple-100 text-purple-600 dark:bg-purple-900 dark:text-purple-400'
                    : 'text-gray-500 hover:text-purple-600 dark:text-gray-400 dark:hover:text-purple-400'
                }`}
                title="Upload file"
                disabled={chatMutation.isPending || fileAnalysisMutation.isPending}
              >
                <Paperclip size={16} />
              </button>
              <button
                onClick={handleSend}
                disabled={(!input.trim() && uploadedFiles.length === 0) || chatMutation.isPending || fileAnalysisMutation.isPending}
                className="px-3 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white rounded-lg transition-colors flex items-center justify-center"
              >
                <Send size={16} />
              </button>
            </div>
          </div>
          
          {/* Show pending files */}
          {uploadedFiles.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {uploadedFiles.map((file) => (
                <div
                  key={file.id}
                  className="flex items-center gap-1 px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded-full text-xs"
                >
                  <FileIcon size={12} />
                  <span className="truncate max-w-[100px]">{file.name}</span>
                </div>
              ))}
            </div>
          )}
          
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            {uploadedFiles.length > 0 
              ? "Files ready for analysis. Press Enter to analyze or add a message."
              : "Press Enter to send, Shift+Enter for new line"
            }
          </p>
        </div>
      </div>
    </div>
  );
}