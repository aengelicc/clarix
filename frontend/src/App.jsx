import { useState, Component } from 'react';
import { Shield, AlertCircle } from 'lucide-react';
import { useAnalysis } from './hooks/useAnalysis';
import Header from './components/Header';
import InputForm from './components/InputForm';
import Dashboard from './components/Dashboard';
import RulesManager from './components/RulesManager';

class AppErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div className="max-w-2xl mx-auto mt-16 p-6 bg-red-50 border border-red-200 rounded-xl">
          <h2 className="text-red-800 font-semibold text-lg mb-2">Something went wrong rendering the report</h2>
          <p className="text-red-700 text-sm mb-4">{this.state.error.message}</p>
          <pre className="text-xs bg-slate-900 text-slate-200 p-4 rounded-lg overflow-auto max-h-48 whitespace-pre-wrap mb-4">
            {this.state.error.stack}
          </pre>
          <button onClick={() => this.setState({ error: null })} className="btn-secondary text-sm">
            ← Start over
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  const { report, loading, error, progress, analyze, cancel, clear } = useAnalysis();
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

            <InputForm onAnalyze={analyze} onCancel={cancel} loading={loading} progress={progress} />

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
          <AppErrorBoundary>
            <Dashboard report={report} onReset={clear} />
          </AppErrorBoundary>
        )}
      </main>
    </div>
  );
}

export default App;
