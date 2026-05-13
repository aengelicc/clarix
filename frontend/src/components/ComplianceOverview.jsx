import { useState } from 'react';
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

const FRAMEWORKS = [
  { key: 'hipaa', label: 'HIPAA', color: 'teal', disclaimer: 'This assessment identifies technical indicators of potential HIPAA Security Rule gaps. It is not a substitute for a formal risk analysis by a qualified professional.' },
  { key: 'pci', label: 'PCI-DSS v4.0', color: 'blue', disclaimer: 'This assessment identifies technical indicators of PCI-DSS compliance gaps. A formal QSA assessment is required for official PCI-DSS certification.' },
  { key: 'gdpr', label: 'GDPR', color: 'purple', disclaimer: 'This assessment flags common GDPR technical implementation issues. Consult a DPO or legal counsel for full GDPR compliance review.' },
  { key: 'soc2', label: 'SOC 2', color: 'indigo', disclaimer: 'This assessment identifies technical gaps against SOC 2 Trust Service Criteria. A formal SOC 2 audit requires a licensed CPA firm.' },
];

const COLOR_MAP = {
  teal:   { tab: 'border-teal-500 text-teal-700',   inactive: 'text-slate-500 hover:text-teal-600',   badge: 'bg-teal-100 text-teal-700',   disc: 'bg-teal-50 border-teal-200 text-teal-700' },
  blue:   { tab: 'border-blue-500 text-blue-700',   inactive: 'text-slate-500 hover:text-blue-600',   badge: 'bg-blue-100 text-blue-700',   disc: 'bg-blue-50 border-blue-200 text-blue-700' },
  purple: { tab: 'border-purple-500 text-purple-700', inactive: 'text-slate-500 hover:text-purple-600', badge: 'bg-purple-100 text-purple-700', disc: 'bg-purple-50 border-purple-200 text-purple-700' },
  indigo: { tab: 'border-indigo-500 text-indigo-700', inactive: 'text-slate-500 hover:text-indigo-600', badge: 'bg-indigo-100 text-indigo-700', disc: 'bg-indigo-50 border-indigo-200 text-indigo-700' },
};

function ChecklistPanel({ checklist, framework }) {
  if (!checklist?.length) {
    return (
      <div className="card text-center py-10">
        <ShieldCheck size={40} className="text-slate-300 mx-auto mb-3" />
        <p className="text-slate-500">No {framework} checklist data available for this scan.</p>
      </div>
    );
  }

  const failing = checklist.filter(i => i.status === 'fail');
  const totalFindings = checklist.reduce((sum, i) => sum + i.findings_count, 0);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className={`card text-center ${failing.length > 0 ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
          <p className="text-sm text-slate-600 mb-1">Compliance Status</p>
          <p className={`text-2xl font-bold ${failing.length > 0 ? 'text-red-600' : 'text-green-600'}`}>
            {failing.length > 0 ? 'At Risk' : 'No Issues Found'}
          </p>
        </div>
        <div className="card text-center">
          <p className="text-sm text-slate-600 mb-1">Sections Failing</p>
          <p className="text-2xl font-bold text-slate-900">{failing.length} / {checklist.length}</p>
        </div>
        <div className="card text-center">
          <p className="text-sm text-slate-600 mb-1">Findings</p>
          <p className={`text-2xl font-bold ${totalFindings > 0 ? 'text-orange-600' : 'text-green-600'}`}>
            {totalFindings}
          </p>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold text-slate-900 mb-4">{framework} — Control Sections</h3>
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
    </div>
  );
}

export default function ComplianceOverview({ report }) {
  const [activeFramework, setActiveFramework] = useState('hipaa');

  const checklistMap = {
    hipaa: report?.hipaa_checklist,
    pci: report?.pci_checklist,
    gdpr: report?.gdpr_checklist,
    soc2: report?.soc2_checklist,
  };

  const summaryBadge = (key) => {
    const list = checklistMap[key] || [];
    const failing = list.filter(i => i.status === 'fail').length;
    if (!list.length) return null;
    return failing > 0
      ? <span className="ml-1.5 text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded-full font-semibold">{failing}</span>
      : <span className="ml-1.5 text-xs bg-green-100 text-green-700 px-1.5 py-0.5 rounded-full">✓</span>;
  };

  const fw = FRAMEWORKS.find(f => f.key === activeFramework);
  const c = COLOR_MAP[fw.color];

  return (
    <div className="space-y-6">
      {/* Framework selector */}
      <div className="border-b border-slate-200">
        <div className="flex gap-6 overflow-x-auto">
          {FRAMEWORKS.map((f) => (
            <button
              key={f.key}
              onClick={() => setActiveFramework(f.key)}
              className={`flex items-center pb-3 text-sm font-medium whitespace-nowrap transition-colors border-b-2 ${
                activeFramework === f.key
                  ? `${c.tab} border-b-2`
                  : `border-transparent ${COLOR_MAP[f.color].inactive}`
              }`}
            >
              {f.label}
              {summaryBadge(f.key)}
            </button>
          ))}
        </div>
      </div>

      <ChecklistPanel
        checklist={checklistMap[activeFramework]}
        framework={fw.label}
      />

      <div className={`card border text-xs leading-relaxed ${c.disc}`}>
        <strong>Disclaimer:</strong> {fw.disclaimer}
      </div>
    </div>
  );
}
