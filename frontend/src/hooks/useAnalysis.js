import { useState, useCallback, useRef } from 'react';

const API_URL = '/api';

export function useAnalysis() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState('');
  const abortControllerRef = useRef(null);
  const userCancelledRef = useRef(false);
  const timeoutRef = useRef(null);
  const jobIdRef = useRef(null);

  const cancel = useCallback(async () => {
    userCancelledRef.current = true;
    clearTimeout(timeoutRef.current);
    try {
      await fetch(`${API_URL}/analyze/cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ job_id: jobIdRef.current }),
      });
    } catch {}
    abortControllerRef.current?.abort();
  }, []);

  const analyze = useCallback(async (source, sourceType, config = {}) => {
    userCancelledRef.current = false;
    jobIdRef.current = null;
    abortControllerRef.current = new AbortController();
    timeoutRef.current = setTimeout(() => abortControllerRef.current?.abort(), 900000);
    setLoading(true);
    setError(null);
    setProgress('Initializing analysis...');

    try {
      const response = await fetch(`${API_URL}/analyze/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, source_type: sourceType, ...config }),
        signal: abortControllerRef.current.signal,
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
            if (event.type === 'started') {
              jobIdRef.current = event.job_id;
            } else if (event.type === 'progress') {
              const msg = event.total > 0
                ? `${event.message} (${event.current}/${event.total})`
                : event.message;
              setProgress(msg);
            } else if (event.type === 'complete') {
              if (event.report) {
                setReport(event.report);
                setProgress('Complete');
              } else {
                setError('Analysis completed but the report was empty. Please try again.');
              }
              completed = true;
            } else if (event.type === 'cancelled') {
              completed = true;
            } else if (event.type === 'error') {
              setError(event.message || 'An unknown error occurred.');
              completed = true;
            }
          } catch (e) {
            console.error('SSE parse error:', e, 'raw:', raw.slice(0, 200));
            setError(`Failed to parse analysis result: ${e.message}`);
            completed = true;
          }
        }
        if (completed) break;
      }

      if (!completed) {
        setError('Analysis stream ended without a result. Check the browser console for details.');
      }
    } catch (err) {
      if (err.name === 'AbortError' && !userCancelledRef.current) {
        setError('Analysis timed out (15 min limit). Try enabling Static analysis only, or reduce Max Files in settings.');
      } else if (err.name !== 'AbortError') {
        setError(err.message || 'Unknown error');
      }
    } finally {
      clearTimeout(timeoutRef.current);
      setLoading(false);
    }
  }, []);

  const clear = useCallback(() => {
    setReport(null);
    setError(null);
    setProgress('');
  }, []);

  return { report, loading, error, progress, analyze, cancel, clear };
}
