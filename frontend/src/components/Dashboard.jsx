import { useState, Component } from 'react';
import { ArrowLeft, Download, FileText, Code2, Shield, Bug, Zap, Hammer, HeartPulse, AlertOctagon, Settings2 } from 'lucide-react';

class TabErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div className="card p-8 border-red-200 bg-red-50">
          <div className="flex items-center gap-3 mb-3 text-red-700">
            <AlertOctagon size={24} />
            <h3 className="font-semibold text-lg">Render error in this tab</h3>
          </div>
          <p className="text-red-600 text-sm mb-3">{this.state.error.message}</p>
          <pre className="text-xs bg-slate-900 text-slate-200 p-4 rounded-lg overflow-auto max-h-48 whitespace-pre-wrap">
            {this.state.error.stack}
          </pre>
        </div>
      );
    }
    return this.props.children;
  }
}
import RiskScore from './RiskScore';
import IssueList from './IssueList';
import FileExplorer from './FileExplorer';
import ProjectOverview from './ProjectOverview';
import ComplianceOverview from './ComplianceOverview';
import RulesManager from './RulesManager';

const TABS = [
  { id: 'overview', label: 'Overview', icon: FileText },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'bugs', label: 'Bugs', icon: Bug },
  { id: 'performance', label: 'Performance', icon: Zap },
  { id: 'refactoring', label: 'Refactoring', icon: Hammer },
  { id: 'compliance', label: 'Compliance', icon: HeartPulse },
  { id: 'files', label: 'Files', icon: Code2 },
  { id: 'rules', label: 'Rules', icon: Settings2 },
];

export default function Dashboard({ report, onReset }) {
  const [activeTab, setActiveTab] = useState('overview');

  const exportMarkdown = () => {
    const md = generateMarkdown(report);
    downloadFile(md, `codegate_${report.repo_name.replace('/', '_')}.md`, 'text/markdown');
  };

  const exportJSON = () => {
    const json = JSON.stringify(report, null, 2);
    downloadFile(json, `codegate_${report.repo_name.replace('/', '_')}.json`, 'application/json');
  };

  return (
    <div className="space-y-6">
      {/* Top Bar */}
      <div className="flex items-center justify-between">
        <button onClick={onReset} className="btn-secondary">
          <ArrowLeft size={18} />
          New Analysis
        </button>
        <div className="flex gap-2">
          <button onClick={exportMarkdown} className="btn-secondary text-sm">
            <Download size={16} />
            Markdown
          </button>
          <button onClick={exportJSON} className="btn-secondary text-sm">
            <Download size={16} />
            JSON
          </button>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <RiskScore score={report.overall_risk_score} />
        <MetricCard 
          label="Files Analyzed" 
          value={report.metadata?.total_files_analyzed || 0} 
          sub={report.metadata?.total_files_skipped ? `${report.metadata.total_files_skipped} skipped` : ''}
        />
        <MetricCard 
          label="Total Issues" 
          value={report.metadata?.total_issues_found || 0} 
        />
        <MetricCard 
          label="Security Findings" 
          value={report.security_findings?.length || 0}
          highlight={report.security_findings?.length > 0}
        />
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-200">
        <div className="flex gap-6 overflow-x-auto">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 pb-3 text-sm whitespace-nowrap transition-colors ${
                  activeTab === tab.id ? 'tab-active' : 'tab-inactive'
                }`}
              >
                <Icon size={16} />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
        <TabErrorBoundary key={activeTab}>
          {activeTab === 'overview' && <ProjectOverview report={report} />}
          {activeTab === 'security' && <IssueList issues={getIssuesByCategory(report, 'security')} title="Security Findings" />}
          {activeTab === 'bugs' && <IssueList issues={getIssuesByCategory(report, 'bug')} title="Bugs" />}
          {activeTab === 'performance' && <IssueList issues={getIssuesByCategory(report, 'performance')} title="Performance Issues" />}
          {activeTab === 'refactoring' && <IssueList issues={getIssuesByCategory(report, 'refactoring')} title="Refactoring Opportunities" />}
          {activeTab === 'compliance' && <ComplianceOverview report={report} />}
          {activeTab === 'files' && <FileExplorer fileAnalyses={report.file_analyses} />}
          {activeTab === 'rules' && <RulesManager />}
        </TabErrorBoundary>
      </div>
    </div>
  );
}

function MetricCard({ label, value, sub, highlight }) {
  return (
    <div className={`card ${highlight ? 'border-red-300 bg-red-50' : ''}`}>
      <p className="text-sm text-slate-600 mb-1">{label}</p>
      <p className="text-3xl font-bold text-slate-900">{value}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
    </div>
  );
}

function getIssuesByCategory(report, category) {
  const issues = [];
  report.file_analyses?.forEach(fa => {
    fa.issues?.forEach(issue => {
      if (issue.category === category) issues.push(issue);
    });
  });
  report.project_level_issues?.forEach(issue => {
    if (issue.category === category) issues.push(issue);
  });
  return issues;
}

function downloadFile(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function generateMarkdown(report) {
  let md = `# Clarix Assessment Report\n\n`;
  md += `**Repository:** \`${report.repo_name}\`  \n`;
  md += `**Risk Score:** ${report.overall_risk_score}/100  \n`;
  md += `**Generated:** ${report.generated_at}\n\n`;
  md += `## Executive Summary\n\n${report.overall_assessment}\n\n`;
  md += `## Language Breakdown\n\n| Language | Files | Lines |\n|----------|-------|-------|\n`;
  report.languages?.forEach(l => {
    md += `| ${l.language} | ${l.file_count} | ${l.line_count} |\n`;
  });
  md += `\n## Issues\n\n`;
  const allIssues = [];
  report.file_analyses?.forEach(fa => allIssues.push(...(fa.issues || [])));
  allIssues.push(...(report.project_level_issues || []));
  allIssues.sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return sevOrder[a.severity] - sevOrder[b.severity];
  });
  allIssues.forEach(issue => {
    const line = issue.line ? `:${issue.line}` : '';
    md += `### [${issue.severity.toUpperCase()}] ${issue.file}${line}\n\n`;
    md += `- **Category:** ${issue.category}\n`;
    md += `- **Description:** ${issue.description}\n`;
    md += `- **Recommendation:** ${issue.recommendation}\n\n`;
  });
  return md;
}
