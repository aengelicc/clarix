import { useState, useEffect } from 'react';
import { Plus, Pencil, Trash2, X, Check, ChevronDown, ChevronUp } from 'lucide-react';
import { useRules } from '../hooks/useRules';

const SCANNERS = ['security', 'hipaa', 'pci', 'gdpr', 'soc2'];
const SCANNER_LABELS = { security: 'Security', hipaa: 'HIPAA', pci: 'PCI-DSS', gdpr: 'GDPR', soc2: 'SOC 2' };
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-blue-100 text-blue-700',
  info: 'bg-slate-100 text-slate-600',
};

const BLANK_FORM = {
  name: '', pattern: '', severity: 'high', description: '', recommendation: '',
  language: '*', scanner: 'security', rule_type: 'dangerous', compliance_ref: '',
};

export default function RulesManager() {
  const { rules, loading, error, createRule, updateRule, deleteRule, bulkUpdate } = useRules();
  const [activeScanner, setActiveScanner] = useState('all');
  const [search, setSearch] = useState('');
  const [modal, setModal] = useState(null); // null | { mode: 'add' } | { mode: 'edit', rule }
  const [form, setForm] = useState(BLANK_FORM);
  const [formError, setFormError] = useState('');
  const [saving, setSaving] = useState(false);
  const [expandedId, setExpandedId] = useState(null);

  const visible = rules.filter(r => {
    if (activeScanner !== 'all' && r.scanner !== activeScanner) return false;
    if (search && !r.name.toLowerCase().includes(search.toLowerCase()) &&
        !r.description.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const openAdd = () => {
    setForm(BLANK_FORM);
    setFormError('');
    setModal({ mode: 'add' });
  };

  const openEdit = (rule) => {
    setForm({
      name: rule.name, pattern: rule.pattern, severity: rule.severity,
      description: rule.description, recommendation: rule.recommendation,
      language: rule.language, scanner: rule.scanner, rule_type: rule.rule_type,
      compliance_ref: rule.compliance_ref || '',
    });
    setFormError('');
    setModal({ mode: 'edit', rule });
  };

  const closeModal = () => setModal(null);

  const handleSave = async () => {
    if (!form.name.trim() || !form.pattern.trim()) {
      setFormError('Name and pattern are required.');
      return;
    }
    setSaving(true);
    setFormError('');
    try {
      const payload = { ...form, compliance_ref: form.compliance_ref || null };
      if (modal.mode === 'add') {
        await createRule(payload);
      } else {
        await updateRule(modal.rule.id, payload);
      }
      closeModal();
    } catch (e) {
      setFormError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (rule) => {
    try {
      await updateRule(rule.id, { enabled: !rule.enabled });
    } catch {
      // ignore — UI will re-sync on next fetch
    }
  };

  const handleBulkToggle = async (enabled) => {
    try {
      await bulkUpdate(enabled);
    } catch (e) {
      alert(e.message);
    }
  };

  const handleDelete = async (rule) => {
    const label = rule.builtin ? 'This is a built-in rule. Delete it permanently?' : `Delete "${rule.name}"?`;
    if (!window.confirm(label)) return;
    try {
      await deleteRule(rule.id);
    } catch (e) {
      alert(e.message);
    }
  };

  if (loading) return <div className="text-slate-500 text-sm">Loading rules...</div>;
  if (error) return <div className="text-red-600 text-sm">Error: {error}</div>;

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          className="border border-slate-200 rounded-lg px-3 py-1.5 text-sm w-52 focus:outline-none focus:ring-2 focus:ring-blue-300"
          placeholder="Search rules..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="flex gap-1 flex-wrap">
          {['all', ...SCANNERS].map(s => (
            <button
              key={s}
              onClick={() => setActiveScanner(s)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                activeScanner === s
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {s === 'all' ? 'All' : SCANNER_LABELS[s]}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1.5 ml-auto">
          <button
            onClick={() => handleBulkToggle(true)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 text-slate-600 hover:bg-green-100 hover:text-green-700 transition-colors"
          >
            Enable all
          </button>
          <button
            onClick={() => handleBulkToggle(false)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 text-slate-600 hover:bg-red-100 hover:text-red-700 transition-colors"
          >
            Disable all
          </button>
          <button onClick={openAdd} className="btn-primary text-sm flex items-center gap-1.5">
            <Plus size={15} /> Add Rule
          </button>
        </div>
      </div>

      {/* Stats line */}
      <p className="text-xs text-slate-500">
        {visible.length} rule{visible.length !== 1 ? 's' : ''} shown
        {' · '}{rules.filter(r => !r.enabled).length} disabled
        {' · '}{rules.filter(r => !r.builtin).length} custom
      </p>

      {/* Rule rows */}
      <div className="space-y-1">
        {visible.map(rule => (
          <RuleRow
            key={rule.id}
            rule={rule}
            expanded={expandedId === rule.id}
            onToggleExpand={() => setExpandedId(expandedId === rule.id ? null : rule.id)}
            onToggleEnabled={() => handleToggle(rule)}
            onEdit={() => openEdit(rule)}
            onDelete={() => handleDelete(rule)}
          />
        ))}
        {visible.length === 0 && (
          <p className="text-sm text-slate-400 py-6 text-center">No rules match your filters.</p>
        )}
      </div>

      {/* Modal */}
      {modal && (
        <RuleModal
          mode={modal.mode}
          form={form}
          onChange={patch => setForm(f => ({ ...f, ...patch }))}
          onSave={handleSave}
          onClose={closeModal}
          error={formError}
          saving={saving}
        />
      )}
    </div>
  );
}

function RuleRow({ rule, expanded, onToggleExpand, onToggleEnabled, onEdit, onDelete }) {
  return (
    <div className={`border rounded-lg transition-colors ${rule.enabled ? 'border-slate-200 bg-white' : 'border-slate-100 bg-slate-50'}`}>
      <div className="flex items-center gap-3 px-3 py-2.5">
        {/* Toggle */}
        <button
          onClick={onToggleEnabled}
          title={rule.enabled ? 'Disable' : 'Enable'}
          className={`w-9 h-5 rounded-full transition-colors flex-shrink-0 inline-flex items-center p-0.5 ${rule.enabled ? 'bg-green-500' : 'bg-slate-300'}`}
        >
          <span className={`w-4 h-4 bg-white rounded-full shadow transition-transform ${rule.enabled ? 'translate-x-4' : 'translate-x-0'}`} />
        </button>

        {/* Name + badges */}
        <button onClick={onToggleExpand} className="flex-1 text-left flex items-center gap-2 min-w-0">
          <span className={`text-sm font-medium truncate ${rule.enabled ? 'text-slate-800' : 'text-slate-400'}`}>
            {rule.name}
          </span>
          <span className="text-xs text-slate-400 shrink-0">{SCANNER_LABELS[rule.scanner] || rule.scanner}</span>
          {rule.language !== '*' && (
            <span className="text-xs bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded shrink-0">{rule.language}</span>
          )}
          {!rule.builtin && (
            <span className="text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded shrink-0">custom</span>
          )}
        </button>

        <span className={`text-xs px-2 py-0.5 rounded-full font-medium shrink-0 ${SEV_COLORS[rule.severity] || ''}`}>
          {rule.severity}
        </span>

        <div className="flex items-center gap-1 shrink-0">
          <button onClick={onEdit} className="p-1 text-slate-400 hover:text-blue-600 transition-colors" title="Edit">
            <Pencil size={14} />
          </button>
          <button onClick={onDelete} className="p-1 text-slate-400 hover:text-red-600 transition-colors" title="Delete">
            <Trash2 size={14} />
          </button>
          <button onClick={onToggleExpand} className="p-1 text-slate-400">
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="px-3 pb-3 border-t border-slate-100 pt-2 space-y-1.5 text-xs text-slate-600">
          <div>
            <span className="font-medium text-slate-500">Pattern:</span>{' '}
            <code className="bg-slate-100 px-1 py-0.5 rounded font-mono break-all">{rule.pattern}</code>
          </div>
          <div><span className="font-medium text-slate-500">Description:</span> {rule.description}</div>
          <div><span className="font-medium text-slate-500">Recommendation:</span> {rule.recommendation}</div>
          {rule.compliance_ref && (
            <div><span className="font-medium text-slate-500">Ref:</span> {rule.compliance_ref}</div>
          )}
        </div>
      )}
    </div>
  );
}

function RuleModal({ mode, form, onChange, onSave, onClose, error, saving }) {
  const isCompliance = form.scanner !== 'security';

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100">
          <h3 className="font-semibold text-slate-800">{mode === 'add' ? 'Add Rule' : 'Edit Rule'}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600"><X size={18} /></button>
        </div>

        <div className="px-5 py-4 space-y-3">
          <Field label="Name *">
            <input className="form-input" value={form.name} onChange={e => onChange({ name: e.target.value })} placeholder="AWS Access Key" />
          </Field>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Scanner">
              <select className="form-input" value={form.scanner} onChange={e => onChange({ scanner: e.target.value })}>
                {SCANNERS.map(s => <option key={s} value={s}>{SCANNER_LABELS[s]}</option>)}
              </select>
            </Field>
            <Field label="Type">
              <select className="form-input" value={form.rule_type} onChange={e => onChange({ rule_type: e.target.value })}>
                <option value="secret">Secret</option>
                <option value="dangerous">Dangerous pattern</option>
                <option value="compliance">Compliance</option>
              </select>
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Severity">
              <select className="form-input" value={form.severity} onChange={e => onChange({ severity: e.target.value })}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="Language">
              <input className="form-input" value={form.language} onChange={e => onChange({ language: e.target.value })} placeholder="* or Python, JavaScript…" />
            </Field>
          </div>

          <Field label="Regex pattern *">
            <input className="form-input font-mono text-xs" value={form.pattern} onChange={e => onChange({ pattern: e.target.value })} placeholder="e.g. (?i)api_key\s*=\s*.+" />
          </Field>

          <Field label="Description">
            <textarea className="form-input resize-none" rows={2} value={form.description} onChange={e => onChange({ description: e.target.value })} />
          </Field>

          <Field label="Recommendation">
            <textarea className="form-input resize-none" rows={2} value={form.recommendation} onChange={e => onChange({ recommendation: e.target.value })} />
          </Field>

          {isCompliance && (
            <Field label="Compliance reference">
              <input className="form-input" value={form.compliance_ref} onChange={e => onChange({ compliance_ref: e.target.value })} placeholder="GDPR Art. 32 — Security of Processing" />
            </Field>
          )}

          {error && <p className="text-red-600 text-xs">{error}</p>}
        </div>

        <div className="flex justify-end gap-2 px-5 py-4 border-t border-slate-100">
          <button onClick={onClose} className="btn-secondary text-sm">Cancel</button>
          <button onClick={onSave} disabled={saving} className="btn-primary text-sm flex items-center gap-1.5">
            {saving ? 'Saving…' : <><Check size={14} /> Save</>}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-600 mb-1">{label}</label>
      {children}
    </div>
  );
}
