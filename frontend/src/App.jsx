import { useState } from 'react';
import { Shield, AlertCircle } from 'lucide-react';
import { useAnalysis } from './hooks/useAnalysis';
import Header from './components/Header';
import InputForm from './components/InputForm';
import Dashboard from './components/Dashboard';
import RulesManager from './components/RulesManager';

function App() {
  const { report, loading, error, progress, analyze, clear } = useAnalysis();
  const [showRules, setShowRules] = useState(false);

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {showRules ? (
          <div>
            <button onClick={() => setShowRules(false)} className="btn-secondary mb-6 text-sm">← Back</button>
            <RulesManager />
          </div>
        ) : !report ? (
          <div className="max-w-2xl mx-auto">
            <div className="text-center mb-10">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-100 text-blue-600 mb-4">
                <Shield size={32} />
              </div>
              <h1 className="text-3xl font-bold text-slate-900 mb-2">
                Clarix
              </h1>
              <p className="text-slate-600 text-lg">
                Pre-deployment code assessment for security, bugs, performance, and architecture.
              </p>
            </div>

            <InputForm onAnalyze={analyze} loading={loading} progress={progress} />

            <div className="mt-4 text-center">
              <button onClick={() => setShowRules(true)} className="text-xs text-slate-400 hover:text-slate-600 underline">
                Manage security rules
              </button>
            </div>

            {error && (
              <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
                <AlertCircle className="text-red-600 shrink-0 mt-0.5" size={20} />
                <div>
                  <h3 className="font-medium text-red-800">Analysis Failed</h3>
                  <p className="text-red-700 text-sm mt-1">{error}</p>
                </div>
              </div>
            )}
          </div>
        ) : (
          <Dashboard report={report} onReset={clear} />
        )}
      </main>
    </div>
  );
}

export default App;
