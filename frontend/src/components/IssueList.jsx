import { useState, useMemo } from 'react';
import { Filter, Search, ChevronDown, ChevronUp, FileWarning } from 'lucide-react';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-slate-100 text-slate-600 border-slate-200',
};

const CATEGORY_COLORS = {
  bug: 'bg-purple-100 text-purple-700',
  security: 'bg-red-100 text-red-700',
  performance: 'bg-cyan-100 text-cyan-700',
  refactoring: 'bg-emerald-100 text-emerald-700',
  deployment: 'bg-indigo-100 text-indigo-700',
};

function ComplianceBadge({ complianceRef }) {
  if (!complianceRef) return null;
  const upper = complianceRef.toUpperCase();
  let cls, label;
  if (upper.includes('HIPAA')) {
    cls = 'bg-teal-100 text-teal-700 border-teal-200';
    label = 'HIPAA ' + complianceRef.split('—')[0].replace(/.*§/, '§').trim();
  } else if (upper.includes('PCI')) {
    cls = 'bg-blue-100 text-blue-700 border-blue-200';
    label = complianceRef.split('—')[0].trim();
  } else if (upper.includes('GDPR')) {
    cls = 'bg-purple-100 text-purple-700 border-purple-200';
    label = complianceRef.split('—')[0].trim();
  } else if (upper.includes('SOC')) {
    cls = 'bg-indigo-100 text-indigo-700 border-indigo-200';
    label = complianceRef.split('—')[0].trim();
  } else {
    cls = 'bg-slate-100 text-slate-600 border-slate-200';
    label = complianceRef.split('—')[0].trim();
  }
  return <span className={`badge font-mono text-xs ${cls}`}>{label}</span>;
}

export default function IssueList({ issues, title }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState(['critical', 'high', 'medium', 'low']);
  const [expandedIssue, setExpandedIssue] = useState(null);

  const filtered = useMemo(() => {
    let result = issues.filter(i => severityFilter.includes(i.severity));
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(i => 
        i.description?.toLowerCase().includes(q) ||
        i.file?.toLowerCase().includes(q) ||
        i.category?.toLowerCase().includes(q)
      );
    }
    return result.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [issues, severityFilter, search]);

  if (!issues.length) {
    return (
      <div className="card text-center py-12">
        <FileWarning size={48} className="text-slate-300 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-slate-900">No {title} Found</h3>
        <p className="text-slate-500 mt-1">Great news — no issues in this category.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="card py-4">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder={`Search ${title.toLowerCase()}...`}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input-field pl-9"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter size={16} className="text-slate-500" />
            {Object.keys(SEVERITY_ORDER).map(sev => (
              <button
                key={sev}
                onClick={() => {
                  setSeverityFilter(prev => 
                    prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
                  );
                }}
                className={`px-2.5 py-1 rounded-md text-xs font-medium capitalize transition-colors ${
                  severityFilter.includes(sev)
                    ? SEVERITY_COLORS[sev]
                    : 'bg-slate-100 text-slate-400 border border-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
        <p className="text-xs text-slate-500 mt-3">
          Showing {filtered.length} of {issues.length} issues
        </p>
      </div>

      {/* Issues */}
      <div className="space-y-3">
        {filtered.map((issue, idx) => (
          <div 
            key={idx} 
            className="card card-hover cursor-pointer"
            onClick={() => setExpandedIssue(expandedIssue === idx ? null : idx)}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <span className={`badge ${SEVERITY_COLORS[issue.severity]} capitalize`}>
                    {issue.severity}
                  </span>
                  <span className={`badge ${CATEGORY_COLORS[issue.category]} capitalize`}>
                    {issue.category}
                  </span>
                  {(issue.compliance_ref || issue.hipaa_reference) && (
                    <ComplianceBadge complianceRef={issue.compliance_ref || issue.hipaa_reference} />
                  )}
                  <span className="text-xs text-slate-500 font-mono">
                    {issue.file}{issue.line ? `:${issue.line}` : ''}
                  </span>
                </div>
                <p className="text-sm text-slate-900 leading-relaxed">
                  {issue.description}
                </p>
              </div>
              <div className="shrink-0 text-slate-400">
                {expandedIssue === idx ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
              </div>
            </div>

            {expandedIssue === idx && (
              <div className="mt-4 pt-4 border-t border-slate-100">
                <div className="bg-slate-50 rounded-lg p-4">
                  <h4 className="text-sm font-medium text-slate-900 mb-1">Recommendation</h4>
                  <p className="text-sm text-slate-700">{issue.recommendation}</p>
                </div>
                {issue.code_snippet && (
                  <div className="mt-3">
                    <h4 className="text-xs font-medium text-slate-500 mb-1.5 uppercase tracking-wider">Code Snippet</h4>
                    <pre className="bg-slate-900 text-slate-100 p-3 rounded-lg text-xs overflow-x-auto">
                      <code>{issue.code_snippet}</code>
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
