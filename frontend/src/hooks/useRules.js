import { useState, useEffect, useCallback } from 'react';

const API = '/api';

export function useRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/rules`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setRules(await res.json());
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  const createRule = async (data) => {
    const res = await fetch(`${API}/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.detail || 'Failed to create rule');
    await fetchRules();
    return json;
  };

  const updateRule = async (id, data) => {
    const res = await fetch(`${API}/rules/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.detail || 'Failed to update rule');
    await fetchRules();
    return json;
  };

  const deleteRule = async (id) => {
    const res = await fetch(`${API}/rules/${id}`, { method: 'DELETE' });
    if (!res.ok) {
      const json = await res.json().catch(() => ({}));
      throw new Error(json.detail || 'Failed to delete rule');
    }
    await fetchRules();
  };

  const bulkUpdate = async (enabled) => {
    const res = await fetch(`${API}/rules`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) {
      const json = await res.json().catch(() => ({}));
      throw new Error(json.detail || 'Failed to update rules');
    }
    await fetchRules();
  };

  return { rules, loading, error, createRule, updateRule, deleteRule, bulkUpdate, refetch: fetchRules };
}
