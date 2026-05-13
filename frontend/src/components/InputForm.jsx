import { useState } from 'react';
import { Search, Folder, Loader2, Settings2, KeyRound, FolderOpen } from 'lucide-react';

export default function InputForm({ onAnalyze, loading, progress }) {
  const [sourceType, setSourceType] = useState('github');
  const [source, setSource] = useState('');
  const [showSettings, setShowSettings] = useState(false);
  const [config, setConfig] = useState({
    max_files: 100,
    max_file_size_kb: 500,
    llm_provider: 'anthropic',
    api_key: '',
    github_pat: '',
    static_only: false,
  });

  const [browsing, setBrowsing] = useState(false);

  const handleBrowse = async () => {
    setBrowsing(true);
    try {
      const res = await fetch('/api/browse-folder', { method: 'POST' });
      if (res.status === 204 || res.status === 400) return;
      if (!res.ok) return;
      const { path } = await res.json();
      if (path) setSource(path);
    } finally {
      setBrowsing(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!source.trim()) return;
    onAnalyze(source, sourceType, config);
  };

  return (
    <div className="card">
      <form onSubmit={handleSubmit}>
        {/* Source Type Toggle */}
        <div className="flex p-1 bg-slate-100 rounded-lg mb-6 w-fit">
          <button
            type="button"
            onClick={() => setSourceType('github')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
              sourceType === 'github'
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            GitHub Repository
          </button>
          <button
            type="button"
            onClick={() => setSourceType('local')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
              sourceType === 'local'
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Local Folder
          </button>
        </div>

        {/* Input Field */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-slate-700 mb-1.5">
            {sourceType === 'github' ? 'Repository URL' : 'Absolute Path'}
          </label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                {sourceType === 'github' ? <Search size={18} /> : <Folder size={18} />}
              </div>
              <input
                type="text"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                placeholder={
                  sourceType === 'github'
                    ? 'https://github.com/owner/repo'
                    : '/path/to/your/project'
                }
                className="input-field pl-10"
                disabled={loading}
              />
            </div>
            {sourceType === 'local' && (
              <button
                type="button"
                onClick={handleBrowse}
                disabled={loading || browsing}
                className="btn-secondary flex items-center gap-1.5 shrink-0"
                title="Browse for folder"
              >
                <FolderOpen size={16} />
                {browsing ? 'Opening…' : 'Browse'}
              </button>
            )}
          </div>
          <p className="mt-1.5 text-xs text-slate-500">
            {sourceType === 'github'
              ? 'Public repos work immediately. For private repos, add a GitHub PAT in Analysis Settings.'
              : 'Must be an absolute path to a directory on this machine.'}
          </p>
        </div>

        {/* Settings Toggle */}
        <div className="mb-4">
          <button
            type="button"
            onClick={() => setShowSettings(!showSettings)}
            className="text-sm text-slate-600 hover:text-blue-600 flex items-center gap-1.5 transition-colors"
          >
            <Settings2 size={16} />
            {showSettings ? 'Hide Settings' : 'Analysis Settings'}
          </button>
        </div>

        {/* Settings Panel */}
        {showSettings && (
          <div className="mb-6 p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-4">
            {/* Static-only toggle */}
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.static_only}
                onChange={(e) => setConfig({ ...config, static_only: e.target.checked })}
                className="mt-0.5 w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <div>
                <span className="text-xs font-semibold text-slate-700">Static analysis only (no LLM)</span>
                <p className="text-xs text-slate-500 mt-0.5">
                  Run regex and pattern-matching scanners only. No API key required. Faster, but no AI code review.
                </p>
              </div>
            </label>

            {/* API Configuration */}
            <div className={config.static_only ? 'opacity-40 pointer-events-none select-none' : ''}>
              <div className="flex items-center gap-1.5 mb-3">
                <KeyRound size={14} className="text-slate-500" />
                <span className="text-xs font-semibold text-slate-700 uppercase tracking-wider">API Configuration</span>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">LLM Provider</label>
                  <div className="flex p-0.5 bg-slate-200 rounded-md w-fit">
                    {['anthropic', 'openai'].map((p) => (
                      <button
                        key={p}
                        type="button"
                        onClick={() => setConfig({ ...config, llm_provider: p, api_key: '' })}
                        className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                          config.llm_provider === p
                            ? 'bg-white text-blue-600 shadow-sm'
                            : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {p === 'anthropic' ? 'Anthropic' : 'OpenAI'}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    {config.llm_provider === 'anthropic' ? 'Anthropic API Key' : 'OpenAI API Key'}
                    <span className="ml-1 text-slate-400 font-normal">(session only, not stored)</span>
                  </label>
                  <input
                    type="password"
                    value={config.api_key}
                    onChange={(e) => setConfig({ ...config, api_key: e.target.value })}
                    placeholder={config.llm_provider === 'anthropic' ? 'sk-ant-...' : 'sk-...'}
                    className="input-field font-mono text-sm"
                    autoComplete="off"
                  />
                </div>
                {sourceType === 'github' && (
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      GitHub PAT
                      <span className="ml-1 text-slate-400 font-normal">(required for private repos)</span>
                    </label>
                    <input
                      type="password"
                      value={config.github_pat}
                      onChange={(e) => setConfig({ ...config, github_pat: e.target.value })}
                      placeholder="ghp_..."
                      className="input-field font-mono text-sm"
                      autoComplete="off"
                    />
                  </div>
                )}
              </div>
            </div>

            {/* Analysis Limits */}
            <div>
              <span className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-3">Analysis Limits</span>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">Max Files</label>
                  <input
                    type="number"
                    value={config.max_files}
                    onChange={(e) => setConfig({ ...config, max_files: parseInt(e.target.value) })}
                    className="input-field"
                    min={10}
                    max={200}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">Max File Size (KB)</label>
                  <input
                    type="number"
                    value={config.max_file_size_kb}
                    onChange={(e) => setConfig({ ...config, max_file_size_kb: parseInt(e.target.value) })}
                    className="input-field"
                    min={50}
                    max={2000}
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={loading || !source.trim()}
          className="btn-primary w-full justify-center"
        >
          {loading ? (
            <>
              <Loader2 className="animate-spin" size={20} />
              {progress || 'Analyzing...'}
            </>
          ) : (
            <>
              <Search size={20} />
              Start Analysis
            </>
          )}
        </button>
      </form>
    </div>
  );
}
