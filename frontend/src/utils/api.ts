import axios from 'axios';
import { Message } from '@/components/Chatbot/ChatMessage';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface RiskAnalysis {
  id: string;
  category: 'security' | 'privacy' | 'compliance' | 'operational' | 'ethical/fairness';
  severity: 'low' | 'medium' | 'high' | 'critical';
  issue: string;
  explanation: string;
  suggested_mitigation: string;
  confidence: number;
  line_number?: number;
}

export interface AnalysisResult {
  timestamp: string;
  document_type: string;
  analysis_method: string;
  summary: string;
  risks: RiskAnalysis[];
   llm_insights: Record<string, unknown> | string | null;
  uncertain: boolean;
  // Computed properties for the dashboard
  total_risks?: number;
  risk_breakdown?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  ai_insights?: string;
  analysis_time?: number;
}

export interface AnalysisRequest {
  code: string;
  language?: string;
  model?: string;
}

export const analyzeCode = async (request: AnalysisRequest): Promise<AnalysisResult> => {
  // Transform frontend request to match backend format
  const backendRequest = {
    document: request.code,
    document_type: request.language || 'code',
    enable_llm: true
  };
  
  console.log('Sending request:', backendRequest);
  
  try {
    const startTime = Date.now();
    const response = await api.post('/analyze', backendRequest);
    const endTime = Date.now();
    
    console.log('Received response:', response.data);
    
    const data = response.data;
    
    // Calculate risk breakdown
    const riskBreakdown = {
      critical: data.risks.filter((r: RiskAnalysis) => r.severity === 'critical').length,
      high: data.risks.filter((r: RiskAnalysis) => r.severity === 'high').length,
      medium: data.risks.filter((r: RiskAnalysis) => r.severity === 'medium').length,
      low: data.risks.filter((r: RiskAnalysis) => r.severity === 'low').length,
    };
    
    // Transform the response to include computed properties for our dashboard
    return {
      ...data,
      total_risks: data.risks.length,
      risk_breakdown: riskBreakdown,
      ai_insights: typeof data.llm_insights === 'object' 
        ? JSON.stringify(data.llm_insights, null, 2) 
        : data.llm_insights || data.summary,
      analysis_time: (endTime - startTime) / 1000
    };
  } catch (error: unknown) {
    const apiError = error as { response?: { data?: unknown; status?: number }; message?: string; config?: unknown };
    console.error('API Error:', apiError.response?.data || apiError.message);
    throw error;
  }
};

export const getHealth = async () => {
  const response = await api.get('/health');
  return response.data;
};

export interface ChatRequest {
  message: string;
  context?: string;
  history?: Message[];
}

export interface ChatResponse {
  response: string;
  timestamp: string;
  model_used?: string;
}

export interface FileAnalysisRequest {
  filename: string;
  content: string;
  message?: string;
  context?: string;
  history?: Message[];
}

export interface FileAnalysisResponse extends ChatResponse {
  analysis_result: AnalysisResult;
  file_info: {
    filename: string;
    size: number;
    risks_found: number;
  };
}

export const sendChatMessage = async (request: ChatRequest): Promise<ChatResponse> => {
  try {
    console.log('Sending chat request:', request);
    const response = await api.post('/chat', request);
    console.log('Chat response received:', response.data);
    return response.data;
  } catch (error: unknown) {
    const apiError = error as { response?: { data?: unknown; status?: number }; message?: string; config?: unknown };
    console.error('API Error:', apiError.response?.data || apiError.message);
    throw error;
  }
  
  }


export const analyzeFileWithChat = async (request: FileAnalysisRequest): Promise<FileAnalysisResponse> => {
  try {
    console.log('Sending file analysis request:', {
      filename: request.filename,
      size: request.content.length,
      message: request.message
    });
    const response = await api.post('/chat/analyze-file', request);
    console.log('File analysis response received:', response.data);
    return response.data;
  } catch (error: unknown) {
    const apiError = error as { response?: { data?: unknown; status?: number }; message?: string; config?: unknown };
    console.error('API Error:', apiError.response?.data || apiError.message);
    throw error;
  }
  }
