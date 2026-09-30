'use client';

import React from 'react';
import Link from 'next/link';
import {
  FileText,
  Users,
  IndianRupee,
  GraduationCap,
  Gift,
  Download,
  FileSpreadsheet,
} from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { BulkImport } from '@/components/admin/BulkImport';
import { ChaptersManager } from '@/components/admin/ChaptersManager';
import { StudentVerifications } from '@/components/admin/StudentVerifications';
import { TeachersPanel } from '@/components/admin/TeachersPanel';
import { BrandPanel } from '@/components/admin/BrandPanel';
import { AdminExtendedPanels } from '@/components/admin/AdminExtendedPanels';
import { GoogleSheetsHub } from '@/components/sheets/GoogleSheetsHub';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export default function AdminDashboardPage() {
  const { leaderboard, markPrizePaid } = useUyanixStore();

  const handleExportCsv = () => {
    const headers = ['Rank,Name,Class,City,Score,PrizePaid'];
    const rows = leaderboard.map(
      (s) =>
        `${s.rank},"${s.name}",Class ${s.classNum},"${s.city}",${s.score}/${s.total},${
          s.prizePaid ? 'Paid' : 'Pending'
        }`
    );
    const csv = [...headers, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'uyanix-top-students-2026.csv';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Top Students CSV exported successfully! 📊');
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
        <h1 className="text-3xl font-bold sm:text-4xl">Admin Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Manage registrations, revenue and prizes.
        </p>

        <div className="mt-6 flex flex-wrap gap-3">
          <Link
            href="/admin/exams"
            className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-5 text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.02]"
          >
            <FileText className="h-4 w-4" aria-hidden="true" /> Manage Exams &amp;
            Questions
          </Link>
          <Link
            href="/sheets"
            className="inline-flex h-11 items-center gap-2 rounded-full bg-secondary px-5 text-sm font-semibold text-secondary-foreground shadow-soft transition hover:scale-[1.02]"
          >
            <FileSpreadsheet className="h-4 w-4" aria-hidden="true" /> Google Sheets Sync Hub
          </Link>
        </div>

        {/* 4 Top KPI Cards */}
        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <Users className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Total Registrations
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">12,847</div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <IndianRupee className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Total Revenue
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              ₹12,71,853
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <GraduationCap className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Exams Completed
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">9,432</div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <Gift className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Prizes to Distribute
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              {leaderboard.slice(0, 3).filter((s) => !s.prizePaid).length}
            </div>
          </div>
        </div>

        {/* Top Students Table */}
        <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold">Top Students</h2>
            <button
              type="button"
              onClick={handleExportCsv}
              className="inline-flex h-10 items-center gap-2 rounded-full bg-secondary px-4 text-sm font-semibold text-secondary-foreground transition hover:opacity-95"
            >
              <Download className="h-4 w-4" aria-hidden="true" /> Export CSV
            </button>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Rank</th>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Class</th>
                  <th className="px-3 py-2">City</th>
                  <th className="px-3 py-2">Score</th>
                  <th className="px-3 py-2 text-right">Prize</th>
                </tr>
              </thead>
              <tbody>
                {leaderboard.slice(0, 10).map((s) => (
                  <tr key={s.id} className="border-t border-border">
                    <td className="px-3 py-3 font-bold tabular-nums">#{s.rank}</td>
                    <td className="px-3 py-3 font-medium">{s.name}</td>
                    <td className="px-3 py-3">Class {s.classNum}</td>
                    <td className="px-3 py-3 text-muted-foreground">{s.city}</td>
                    <td className="px-3 py-3 font-semibold tabular-nums">
                      {s.score}/{s.total}
                    </td>
                    <td className="px-3 py-3 text-right">
                      {s.rank <= 3 ? (
                        <button
                          type="button"
                          onClick={() => {
                            markPrizePaid(s.id);
                            toast.success(
                              `Updated prize status for #${s.rank} ${s.name}`
                            );
                          }}
                          className={`rounded-full px-3 py-1 text-xs font-semibold transition ${
                            s.prizePaid
                              ? 'bg-secondary/15 text-secondary border border-secondary/30'
                              : 'border border-border hover:bg-accent'
                          }`}
                        >
                          {s.prizePaid ? 'Paid ✓' : 'Mark Paid'}
                        </button>
                      ) : (
                        <span className="text-xs text-muted-foreground">Gift</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Google Sheets & Drive Live Sync Hub */}
        <div className="mt-8">
          <GoogleSheetsHub />
        </div>

        {/* Exact Admin Sections from HTML */}
        <BulkImport />
        <ChaptersManager />
        <StudentVerifications />
        <TeachersPanel />
        <BrandPanel />

        {/* Extended Pro Admin Suite */}
        <AdminExtendedPanels />
      </section>

      <Footer />
    </div>
  );
}
