import React, { useState } from 'react';
import { FileCode, AlertCircle, CheckCircle, ChevronRight, ChevronDown } from 'lucide-react';

const SEVERITY_COLORS = {
  critical: 'text-red-600',
  high: 'text-orange-600',
  medium: 'text-yellow-600',
  low: 'text-blue-600',
  info: 'text-slate-400',
};

export default function FileExplorer({ fileAnalyses }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [expandedDirs, setExpandedDirs] = useState(new Set(['']));

  if (!fileAnalyses?.length) {
    return (
      <div className="card text-center py-12">
        <FileCode size={48} className="text-slate-300 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-slate-900">No Files</h3>
      </div>
    );
  }

  const analyzed = fileAnalyses.filter(f => f.analyzed);
  const skipped = fileAnalyses.filter(f => !f.analyzed);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* File Tree */}
      <div className="lg:col-span-1 card max-h-[600px] overflow-y-auto">
        <h3 className="text-sm font-semibold text-slate-900 mb-4 uppercase tracking-wider">Files</h3>
        <div className="space-y-1">
          {analyzed.map((fa, idx) => (
            <FileTreeItem
              key={idx}
              file={fa}
              isSelected={selectedFile === idx}
              onClick={() => setSelectedFile(idx)}
            />
          ))}
          {skipped.length > 0 && (
            <div className="mt-4 pt-4 border-t border-slate-100">
              <p className="text-xs font-medium text-slate-500 mb-2">Skipped ({skipped.length})</p>
              {skipped.map((fa, idx) => (
                <div key={`skip-${idx}`} className="flex items-center gap-2 px-3 py-2 text-xs text-slate-400">
                  <FileCode size={14} />
                  <span className="truncate">{fa.file_path}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* File Detail */}
      <div className="lg:col-span-2">
        {selectedFile !== null ? (
          <FileDetail file={analyzed[selectedFile]} />
        ) : (
          <div className="card h-full flex items-center justify-center text-slate-400">
            <p>Select a file to view details</p>
          </div>
        )}
      </div>
    </div>
  );
}

function FileTreeItem({ file, isSelected, onClick }) {
  const issueCount = file.issues?.length || 0;
  const hasCritical = file.issues?.some(i => i.severity === 'critical');
  const hasHigh = file.issues?.some(i => i.severity === 'high');

  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-sm transition-colors ${
        isSelected ? 'bg-blue-50 text-blue-700' : 'hover:bg-slate-50 text-slate-700'
      }`}
    >
      <FileCode size={16} className={isSelected ? 'text-blue-600' : 'text-slate-400'} />
      <span className="truncate flex-1">{file.file_path}</span>
      {issueCount > 0 && (
        <span className={`text-xs font-medium ${hasCritical ? 'text-red-600' : hasHigh ? 'text-orange-600' : 'text-slate-500'}`}>
          {issueCount}
        </span>
      )}
      {issueCount === 0 && <CheckCircle size={14} className="text-green-500" />}
    </button>
  );
}

function FileDetail({ file }) {
  const [activeFilter, setActiveFilter] = useState('all');
  const issues = file.issues || [];
  const filteredIssues = activeFilter === 'all' ? issues : issues.filter(i => i.category === activeFilter);

  const categories = [...new Set(issues.map(i => i.category))];

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-slate-900 font-mono">{file.file_path}</h3>
          <p className="text-sm text-slate-500">{file.language} · {file.size_bytes} bytes · {file.token_count} tokens</p>
        </div>
        <span className={`badge ${issues.length === 0 ? 'bg-green-100 text-green-700' : 'bg-orange-100 text-orange-700'}`}>
          {issues.length} issues
        </span>
      </div>

      <div className="bg-slate-50 rounded-lg p-4 mb-4">
        <p className="text-sm text-slate-700">{file.summary}</p>
      </div>

      {issues.length > 0 && (
        <>
          <div className="flex gap-2 mb-3">
            <button
              onClick={() => setActiveFilter('all')}
              className={`px-3 py-1 rounded-md text-xs font-medium ${activeFilter === 'all' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-600'}`}
            >
              All ({issues.length})
            </button>
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setActiveFilter(cat)}
                className={`px-3 py-1 rounded-md text-xs font-medium capitalize ${activeFilter === cat ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-600'}`}
              >
                {cat} ({issues.filter(i => i.category === cat).length})
              </button>
            ))}
          </div>

          <div className="space-y-2">
            {filteredIssues.map((issue, idx) => (
              <div key={idx} className="border border-slate-200 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-xs font-bold uppercase ${SEVERITY_COLORS[issue.severity]}`}>
                    {issue.severity}
                  </span>
                  <span className="text-xs text-slate-500">Line {issue.line || 'N/A'}</span>
                </div>
                <p className="text-sm text-slate-800 mb-1">{issue.description}</p>
                <p className="text-xs text-slate-600">{issue.recommendation}</p>
              </div>
            ))}
          </div>
        </>
      )}

      {issues.length === 0 && (
        <div className="flex items-center gap-2 text-green-600">
          <CheckCircle size={18} />
          <span className="text-sm font-medium">No issues found in this file</span>
        </div>
      )}
    </div>
  );
}
