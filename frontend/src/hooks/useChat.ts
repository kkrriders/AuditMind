import { useMutation } from '@tanstack/react-query';
import { sendChatMessage, ChatRequest, analyzeFileWithChat, FileAnalysisRequest } from '@/utils/api';

export const useChatMessage = () => {
  return useMutation({
    mutationFn: (request: ChatRequest) => sendChatMessage(request),
    onError: (error) => {
      console.error('Chat failed:', error);
    },
  });
};

export const useFileAnalysis = () => {
  return useMutation({
    mutationFn: (request: FileAnalysisRequest) => analyzeFileWithChat(request),
    onError: (error) => {
      console.error('File analysis failed:', error);
    },
  });
};