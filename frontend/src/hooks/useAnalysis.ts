import { useMutation, useQuery } from '@tanstack/react-query';
import { analyzeCode, getHealth, AnalysisRequest } from '@/utils/api';

export const useAnalyzeCode = () => {
  return useMutation({
    mutationFn: (request: AnalysisRequest) => analyzeCode(request),
    onError: (error) => {
      console.error('Analysis failed:', error);
    },
  });
};

export const useHealth = () => {
  return useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 30000, // Check health every 30 seconds
    retry: 3,
  });
};