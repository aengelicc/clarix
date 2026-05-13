import { useState, useCallback } from 'react';

const API_URL = '/api';

export function useAnalysis() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState('');

  const analyze = useCallback(async (source, sourceType, config = {}) => {
    setLoading(true);
    setError(null);
    setProgress('Initializing analysis...');

    try {
      const response = await fetch(`${API_URL}/analyze/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, source_type: sourceType, ...config }),
        signal: AbortSignal.timeout(300000),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || `Server error ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let completed = false;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (!raw) continue;
          try {
            const event = JSON.parse(raw);
            if (event.type === 'progress') {
              const msg = event.total > 0
                ? `${event.message} (${event.current}/${event.total})`
                : event.message;
              setProgress(msg);
            } else if (event.type === 'complete') {
              setReport(event.report);
              setProgress('Complete');
              completed = true;
            } else if (event.type === 'error') {
              setError(event.message);
              completed = true;
            }
          } catch (e) {
            console.error('SSE parse error:', e, 'raw:', raw.slice(0, 200));
          }
        }
        if (completed) break;
      }

      if (!completed) {
        setError('Analysis stream ended without a result. Check the browser console for details.');
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setError(err.message || 'Unknown error');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const clear = useCallback(() => {
    setReport(null);
    setError(null);
    setProgress('');
  }, []);

  return { report, loading, error, progress, analyze, clear };
}
