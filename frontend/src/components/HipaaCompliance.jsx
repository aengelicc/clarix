import React from 'react';
import { CheckCircle, XCircle, AlertTriangle, ShieldCheck } from 'lucide-react';

const SEV_COLORS = {
  critical: 'text-red-600',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-500',
};

const SEV_BORDER = {
  critical: 'border-red-300 bg-red-50',
  high: 'border-orange-300 bg-orange-50',
  medium: 'border-yellow-300 bg-yellow-50',
  low: 'border-blue-300 bg-blue-50',
};

export default function HipaaCompliance({ checklist }) {
  if (!checklist?.length) {
    return (
      <div className="card text-center py-12">
        <ShieldCheck size={48} className="text-slate-300 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-slate-900">No HIPAA Checklist Available</h3>
        <p className="text-slate-500 mt-1">HIPAA compliance data was not generated for this scan.</p>
      </div>
    );
  }

  const failing = checklist.filter(i => i.status === 'fail');
  const passing = checklist.filter(i => i.status === 'pass');
  const totalFindings = checklist.reduce((sum, i) => sum + i.findings_count, 0);

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className={`card text-center ${failing.length > 0 ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
          <p className="text-sm text-slate-600 mb-1">Compliance Status</p>
          <p className={`text-2xl font-bold ${failing.length > 0 ? 'text-red-600' : 'text-green-600'}`}>
            {failing.length > 0 ? 'At Risk' : 'Compliant'}
          </p>
        </div>
        <div className="card text-center">
          <p className="text-sm text-slate-600 mb-1">Sections Failing</p>
          <p className="text-2xl font-bold text-slate-900">{failing.length} / {checklist.length}</p>
        </div>
        <div className="card text-center">
          <p className="text-sm text-slate-600 mb-1">HIPAA Findings</p>
          <p className={`text-2xl font-bold ${totalFindings > 0 ? 'text-orange-600' : 'text-green-600'}`}>
            {totalFindings}
          </p>
        </div>
      </div>

      {/* Checklist */}
      <div className="card">
        <h3 className="text-lg font-semibold text-slate-900 mb-4">HIPAA Security Rule — Technical Safeguards</h3>
        <div className="space-y-3">
          {checklist.map((item) => (
            <div
              key={item.section}
              className={`rounded-lg border p-4 ${
                item.status === 'fail'
                  ? (SEV_BORDER[item.worst_severity] || 'border-orange-300 bg-orange-50')
                  : 'border-green-200 bg-green-50'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className="shrink-0 mt-0.5">
                  {item.status === 'pass' ? (
                    <CheckCircle size={20} className="text-green-600" />
                  ) : item.worst_severity === 'critical' ? (
                    <XCircle size={20} className="text-red-600" />
                  ) : (
                    <AlertTriangle size={20} className={SEV_COLORS[item.worst_severity] || 'text-orange-500'} />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-xs font-mono font-bold text-slate-600">{item.section}</span>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                      item.status === 'pass'
                        ? 'bg-green-100 text-green-700'
                        : 'bg-red-100 text-red-700'
                    }`}>
                      {item.status === 'pass' ? 'PASS' : `FAIL — ${item.findings_count} finding${item.findings_count !== 1 ? 's' : ''}`}
                    </span>
                    {item.worst_severity && item.status === 'fail' && (
                      <span className={`text-xs font-medium capitalize ${SEV_COLORS[item.worst_severity]}`}>
                        {item.worst_severity} severity
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-medium text-slate-900">{item.title}</p>
                  <p className="text-xs text-slate-600 mt-0.5">{item.description}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card bg-teal-50 border-teal-200">
        <p className="text-xs text-teal-700 leading-relaxed">
          <strong>Disclaimer:</strong> This assessment identifies technical indicators of potential HIPAA Security Rule
          compliance gaps in source code. It is not a substitute for a formal HIPAA risk analysis conducted by a
          qualified professional. Covered entities and business associates should consult legal and compliance counsel.
        </p>
      </div>
    </div>
  );
}
