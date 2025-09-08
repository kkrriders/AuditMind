'use client';

import { Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { AlertTriangle, Shield, Eye, FileText } from 'lucide-react';
import { AnalysisResult } from '@/utils/api';

interface RiskDashboardProps {
  result: AnalysisResult | null;
  isLoading: boolean;
}

const RISK_COLORS = {
  critical: '#dc2626',
  high: '#ea580c', 
  medium: '#d97706',
  low: '#65a30d'
};

const CATEGORY_ICONS = {
  security: Shield,
  privacy: Eye,
  compliance: FileText,
  operational: AlertTriangle,
  'ethical/fairness': AlertTriangle
};

export default function RiskDashboard({ result, isLoading }: RiskDashboardProps) {
  if (isLoading) {
    return (
      <div className="p-6 bg-white dark:bg-gray-800 rounded-lg border">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-4"></div>
          <div className="space-y-3">
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded"></div>
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-5/6"></div>
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-4/6"></div>
          </div>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="p-6 bg-white dark:bg-gray-800 rounded-lg border text-center text-gray-500">
        <AlertTriangle className="mx-auto mb-2 w-12 h-12 text-gray-400" />
         <p>No analysis results yet. Enter code and click &ldquo;Analyze&rdquo; to get started.</p>
      </div>
    );
  }

  const riskBreakdownData = [
    { name: 'Critical', value: result.risk_breakdown?.critical || 0, color: RISK_COLORS.critical },
    { name: 'High', value: result.risk_breakdown?.high || 0, color: RISK_COLORS.high },
    { name: 'Medium', value: result.risk_breakdown?.medium || 0, color: RISK_COLORS.medium },
    { name: 'Low', value: result.risk_breakdown?.low || 0, color: RISK_COLORS.low },
  ];

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">
          <div className="text-red-600 dark:text-red-400 text-sm font-medium">Critical</div>
          <div className="text-2xl font-bold text-red-700 dark:text-red-300">{result.risk_breakdown?.critical || 0}</div>
        </div>
        <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg border border-orange-200 dark:border-orange-800">
          <div className="text-orange-600 dark:text-orange-400 text-sm font-medium">High</div>
          <div className="text-2xl font-bold text-orange-700 dark:text-orange-300">{result.risk_breakdown?.high || 0}</div>
        </div>
        <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
          <div className="text-yellow-600 dark:text-yellow-400 text-sm font-medium">Medium</div>
          <div className="text-2xl font-bold text-yellow-700 dark:text-yellow-300">{result.risk_breakdown?.medium || 0}</div>
        </div>
        <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
          <div className="text-green-600 dark:text-green-400 text-sm font-medium">Low</div>
          <div className="text-2xl font-bold text-green-700 dark:text-green-300">{result.risk_breakdown?.low || 0}</div>
        </div>
      </div>

      {/* Risk Breakdown Chart */}
      <div className="p-6 bg-white dark:bg-gray-800 rounded-lg border">
        <h3 className="text-lg font-semibold mb-4">Risk Distribution</h3>
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie
              data={riskBreakdownData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={80}
              label={({ name, value }) => (value && value > 0) ? `${name}: ${value}` : ''}
            >
              {riskBreakdownData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* AI Insights */}
      {result.ai_insights && (
        <div className="p-6 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
          <h3 className="text-lg font-semibold mb-3 text-blue-800 dark:text-blue-200">AI Insights</h3>
          <p className="text-blue-700 dark:text-blue-300 whitespace-pre-wrap">{result.ai_insights}</p>
        </div>
      )}

      {/* Detailed Risk List */}
      {result.risks.length > 0 && (
        <div className="p-6 bg-white dark:bg-gray-800 rounded-lg border">
          <h3 className="text-lg font-semibold mb-4">Detailed Findings</h3>
          <div className="space-y-3">
            {result.risks.map((risk, index) => {
              const Icon = CATEGORY_ICONS[risk.category];
              return (
                <div 
                  key={index}
                  className="flex items-start gap-3 p-4 rounded-lg border border-gray-200 dark:border-gray-700"
                >
                  <div className={`p-2 rounded-full ${
                    risk.severity === 'critical' ? 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400' :
                    risk.severity === 'high' ? 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400' :
                    risk.severity === 'medium' ? 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-400' :
                    'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400'
                  }`}>
                    <Icon size={16} />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                        risk.severity === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                        risk.severity === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400' :
                        risk.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                        'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                      }`}>
                        {risk.severity.toUpperCase()}
                      </span>
                      <span className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                        {risk.category}
                      </span>
                      {risk.line_number && (
                        <span className="text-sm text-gray-500 dark:text-gray-400">
                          Line {risk.line_number}
                        </span>
                      )}
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {Math.round(risk.confidence * 100)}% confidence
                      </span>
                    </div>
                    <p className="text-gray-700 dark:text-gray-300 mb-2">{risk.explanation}</p>
                    {risk.suggested_mitigation && (
                      <p className="text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 p-2 rounded">
                        💡 {risk.suggested_mitigation}
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Analysis Stats */}
      <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg border text-sm text-gray-600 dark:text-gray-400">
        <div className="flex justify-between items-center">
          <span>Total Risks Found: {result.total_risks}</span>
          <span>Analysis Time: {result.analysis_time?.toFixed(2) || 0}s</span>
        </div>
      </div>
    </div>
  );
}