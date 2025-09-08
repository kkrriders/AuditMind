'use client';

import { useState, useRef } from 'react';
import { Upload, X, File as FileIcon, AlertCircle } from 'lucide-react';

export interface UploadedFile {
  id: string;
  name: string;
  size: number;
  type: string;
  content: string;
  lastModified: number;
}

interface FileUploadProps {
  onFileUpload: (file: UploadedFile) => void;
  onFileRemove: (fileId: string) => void;
  uploadedFiles: UploadedFile[];
  maxFileSize?: number; // in bytes
  acceptedTypes?: string[];
  disabled?: boolean;
}

export default function FileUpload({
  onFileUpload,
  onFileRemove,
  uploadedFiles,
  maxFileSize = 5 * 1024 * 1024, // 5MB default
  acceptedTypes = ['.txt', '.md', '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs', '.sql', '.json', '.xml', '.yaml', '.yml', '.html', '.css'],
  disabled = false
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateFile = (file: File): string | null => {
    // Check file size
    if (file.size > maxFileSize) {
      return `File size must be less than ${Math.round(maxFileSize / (1024 * 1024))}MB`;
    }

    // Check file type
    const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!acceptedTypes.includes(fileExtension || '')) {
      return `File type not supported. Accepted types: ${acceptedTypes.join(', ')}`;
    }

    return null;
  };

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        resolve(content);
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  };

  const handleFileSelect = async (file: File) => {
    setError(null);

    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      return;
    }

    try {
      const content = await readFileContent(file);
      const uploadedFile: UploadedFile = {
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        name: file.name,
        size: file.size,
        type: file.type,
        content,
        lastModified: file.lastModified
      };

      onFileUpload(uploadedFile);
    } catch {
      setError('Failed to read file content');
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    if (disabled) return;

    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      await handleFileSelect(files[0]); // Handle only the first file for now
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      await handleFileSelect(files[0]);
    }
    // Reset input value to allow selecting the same file again
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-2">
      {/* Upload Area */}
      <div
        className={`
          border-2 border-dashed rounded-lg p-3 transition-colors cursor-pointer
          ${isDragging 
            ? 'border-purple-400 bg-purple-50 dark:bg-purple-900/20' 
            : 'border-gray-300 dark:border-gray-600 hover:border-purple-400 dark:hover:border-purple-400'
          }
          ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
        `}
        onDrop={handleDrop}
        onDragOver={(e) => {
          e.preventDefault();
          if (!disabled) setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onClick={() => !disabled && fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept={acceptedTypes.join(',')}
          onChange={handleFileInputChange}
          className="hidden"
          disabled={disabled}
        />

        <div className="flex items-center justify-center space-x-2 text-sm">
          <Upload size={16} className="text-gray-500 dark:text-gray-400" />
          <span className="text-gray-600 dark:text-gray-300">
            {isDragging ? 'Drop file here' : 'Click to upload or drag & drop'}
          </span>
        </div>
        <p className="text-xs text-gray-500 dark:text-gray-400 text-center mt-1">
          Max {Math.round(maxFileSize / (1024 * 1024))}MB • {acceptedTypes.slice(0, 5).join(', ')}
          {acceptedTypes.length > 5 && ` + ${acceptedTypes.length - 5} more`}
        </p>
      </div>

      {/* Error Message */}
      {error && (
        <div className="flex items-center space-x-2 text-red-600 dark:text-red-400 text-sm">
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Uploaded Files */}
      {uploadedFiles.length > 0 && (
        <div className="space-y-1">
          {uploadedFiles.map((file) => (
            <div
              key={file.id}
              className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded-lg"
            >
              <div className="flex items-center space-x-2 min-w-0 flex-1">
                <FileIcon size={16} className="text-purple-600 dark:text-purple-400 flex-shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                    {file.name}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {formatFileSize(file.size)}
                  </p>
                </div>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onFileRemove(file.id);
                }}
                className="p-1 text-gray-400 hover:text-red-500 dark:hover:text-red-400 transition-colors flex-shrink-0"
                title="Remove file"
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}