import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { FileText, AlertTriangle, CheckCircle, Layers } from 'lucide-react';

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#84cc16'];

export default function ProjectOverview({ report }) {
  const langData = report.languages?.map(l => ({
    name: l.language,
    value: l.file_count,
    lines: l.line_count
  })) || [];

  return (
    <div className="space-y-6">
      {/* Executive Summary */}
      <div className="card">
        <div className="flex items-center gap-2 mb-4">
          <FileText size={20} className="text-blue-600" />
          <h3 className="text-lg font-semibold text-slate-900">Executive Summary</h3>
        </div>
        <div className="prose prose-slate max-w-none">
          <p className="text-slate-700 leading-relaxed whitespace-pre-wrap">{report.overall_assessment}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Language Breakdown */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Layers size={20} className="text-blue-600" />
            <h3 className="text-lg font-semibold text-slate-900">Language Breakdown</h3>
          </div>
          {langData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={langData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {langData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    formatter={(value, name, props) => [`${value} files (${props.payload.lines} lines)`, name]}
                    contentStyle={{ borderRadius: '8px', border: '1px solid #e2e8f0' }}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-slate-500 text-center py-8">No language data available</p>
          )}
        </div>

        {/* Project Level Issues */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle size={20} className="text-orange-600" />
            <h3 className="text-lg font-semibold text-slate-900">Project-Level Issues</h3>
          </div>
          {report.project_level_issues?.length > 0 ? (
            <div className="space-y-3">
              {report.project_level_issues.map((issue, idx) => (
                <div key={idx} className="border-l-4 border-orange-400 bg-orange-50 rounded-r-lg p-3">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold uppercase text-orange-700">{issue.severity}</span>
                    <span className="text-xs text-slate-500 capitalize">{issue.category}</span>
                  </div>
                  <p className="text-sm text-slate-800">{issue.description}</p>
                  <p className="text-xs text-slate-600 mt-1">{issue.recommendation}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-green-600 py-8 justify-center">
              <CheckCircle size={20} />
              <span className="font-medium">No project-level issues identified</span>
            </div>
          )}
        </div>
      </div>

      {/* Metadata */}
      <div className="card">
        <h3 className="text-sm font-semibold text-slate-900 mb-3 uppercase tracking-wider">Analysis Metadata</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-slate-500">LLM Provider</p>
            <p className="font-medium text-slate-900 capitalize">{report.metadata?.llm_provider}</p>
          </div>
          <div>
            <p className="text-slate-500">Model</p>
            <p className="font-medium text-slate-900">{report.metadata?.llm_model}</p>
          </div>
          <div>
            <p className="text-slate-500">Generated</p>
            <p className="font-medium text-slate-900">{new Date(report.generated_at).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-slate-500">Source</p>
            <p className="font-medium text-slate-900 capitalize">{report.source_type}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
