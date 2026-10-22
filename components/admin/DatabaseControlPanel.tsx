'use client';

import React, { useState, useEffect } from 'react';
import {
  Database,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  TableProperties,
  Sparkles,
  Server,
  Layers,
  Download,
} from 'lucide-react';
import { toast } from 'sonner';

interface DatabaseStatsResponse {
  ok: boolean;
  engine: string;
  supabaseConnected: boolean;
  databaseName: string;
  schemaVersion: string;
  tableStats: Record<string, { count: number; status: 'online' | 'fallback' }>;
  timestamp: string;
}

export function DatabaseControlPanel() {
  const [data, setData] = useState<DatabaseStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);

  const fetchStatus = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/admin/database', { credentials: 'include' });
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch {
      toast.error('Failed to query database status.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleSeed = async () => {
    try {
      setSeeding(true);
      const toastId = toast.loading('Initializing database & seeding initial records...');
      const res = await fetch('/api/admin/database', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      const json = await res.json();
      if (res.ok && json.ok) {
        toast.success('Database initialized & seeded successfully! 🎉', { id: toastId });
        await fetchStatus();
      } else {
        toast.error(json.error || 'Database seeding failed.', { id: toastId });
      }
    } catch {
      toast.error('Network error during database seeding.');
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-5">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary/10 text-primary">
            <Database className="h-6 w-6" aria-hidden="true" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold">Full Database Engine &amp; Schemas</h2>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                  data?.supabaseConnected
                    ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                    : 'bg-primary/15 text-primary'
                }`}
              >
                <CheckCircle2 className="h-3 w-3" />
                {data?.supabaseConnected ? 'PostgreSQL Connected' : 'Persistent Fallback Online'}
              </span>
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Complete multi-role database for Students, Quizzes, Exams, Certificates, Teachers &amp; Payments.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={fetchStatus}
            disabled={loading}
            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-border bg-muted/30 px-3.5 text-xs font-semibold transition hover:bg-accent disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          <button
            type="button"
            onClick={handleSeed}
            disabled={seeding}
            className="inline-flex h-9 items-center gap-1.5 rounded-full bg-gradient-hero px-4 text-xs font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.02] disabled:opacity-50"
          >
            <Sparkles className="h-3.5 w-3.5" /> {seeding ? 'Seeding...' : 'Seed & Initialize Data'}
          </button>
        </div>
      </div>

      {/* Engine and Schema Metadata */}
      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <div className="rounded-2xl border border-border bg-muted/20 p-3.5">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
            <Server className="h-3.5 w-3.5 text-primary" /> Active Engine
          </div>
          <div className="mt-1 font-mono text-sm font-bold text-foreground">
            {data?.engine || 'Detecting...'}
          </div>
        </div>
        <div className="rounded-2xl border border-border bg-muted/20 p-3.5">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
            <Layers className="h-3.5 w-3.5 text-secondary" /> Schema Definition
          </div>
          <div className="mt-1 font-mono text-sm font-bold text-foreground">
            lib/supabase-schema.sql (1,300+ Lines)
          </div>
        </div>
        <div className="rounded-2xl border border-border bg-muted/20 p-3.5">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
            <TableProperties className="h-3.5 w-3.5 text-amber-500" /> Total Monitored Tables
          </div>
          <div className="mt-1 font-mono text-sm font-bold text-foreground">
            {data?.tableStats ? Object.keys(data.tableStats).length : 16} Authoritative Tables
          </div>
        </div>
      </div>

      {/* Tables Grid */}
      <div className="mt-6">
        <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
          Authoritative Database Tables &amp; Records Status
        </h3>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4 lg:grid-cols-4">
          {data?.tableStats &&
            Object.entries(data.tableStats).map(([table, stat]) => (
              <div
                key={table}
                className="flex items-center justify-between rounded-xl border border-border bg-card p-3 shadow-sm hover:border-primary/40 transition-colors"
              >
                <div>
                  <div className="font-mono text-xs font-semibold text-foreground">
                    {table}
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    {stat.count} {stat.count === 1 ? 'record' : 'records'}
                  </div>
                </div>
                <span className="inline-flex h-2 w-2 rounded-full bg-emerald-500" title="Active & Healthy" />
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}
