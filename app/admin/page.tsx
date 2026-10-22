'use client';

import React, { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  FileText,
  Users,
  IndianRupee,
  GraduationCap,
  Gift,
  Download,
  FileSpreadsheet,
  Loader2,
} from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

const BulkImport = dynamic(() =>
  import('@/components/admin/BulkImport').then((mod) => mod.BulkImport)
);
const ChaptersManager = dynamic(() =>
  import('@/components/admin/ChaptersManager').then((mod) => mod.ChaptersManager)
);
const StudentVerifications = dynamic(() =>
  import('@/components/admin/StudentVerifications').then(
    (mod) => mod.StudentVerifications
  )
);
const TeachersPanel = dynamic(() =>
  import('@/components/admin/TeachersPanel').then((mod) => mod.TeachersPanel)
);
const BrandPanel = dynamic(() =>
  import('@/components/admin/BrandPanel').then((mod) => mod.BrandPanel)
);
const AdminExtendedPanels = dynamic(() =>
  import('@/components/admin/AdminExtendedPanels').then(
    (mod) => mod.AdminExtendedPanels
  )
);
const GoogleSheetsHub = dynamic(() =>
  import('@/components/sheets/GoogleSheetsHub').then(
    (mod) => mod.GoogleSheetsHub
  )
);
const DatabaseControlPanel = dynamic(() =>
  import('@/components/admin/DatabaseControlPanel').then(
    (mod) => mod.DatabaseControlPanel
  )
);

interface AdminMetricsState {
  totalRegistrations: number;
  activeStudents: number;
  verifiedStudents: number;
  pendingVerifications: number;
  suspendedStudents: number;
  totalCapturedPayments: number;
  totalRefundedPayments: number;
  netRevenue: number;
  completedExams: number;
  pendingWithdrawals: number;
  paidWithdrawals: number;
  pendingPrizes: number;
  activeTeachers: number;
  pendingTeacherApprovals: number;
}

export default function AdminDashboardPage() {
  const router = useRouter();
  const {
    leaderboard,
    payments,
    examAttempts,
    markPrizePaid,
    syncAdminVerifications,
    syncServerSession,
  } = useUyanixStore();

  const [metrics, setMetrics] = useState<AdminMetricsState | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [processingPrizeId, setProcessingPrizeId] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const fetchMetrics = () => {
      const token = typeof window !== 'undefined' ? localStorage.getItem('uyanix_token') : null;
      fetch('/api/admin/metrics', {
        credentials: 'include',
        headers: token ? { 'x-uyanix-session': token, Authorization: `Bearer ${token}` } : {},
      })
        .then((res) => res.json())
        .then((data) => {
          if (!active) return;
          if (data.ok && data.metrics) {
            setMetrics(data.metrics);
          }
        })
        .catch(() => {});
    };

    syncServerSession().then((serverUser) => {
      if (!active) return;
      const isTrustedAdmin =
        serverUser?.role === 'admin' ||
        serverUser?.email?.toLowerCase() === 'dollysingh1268@gmail.com' ||
        serverUser?.email?.toLowerCase() === 'admin@uyanix.in';

      if (!serverUser) {
        router.replace('/login?redirect=/admin');
      } else if (!isTrustedAdmin) {
        router.replace('/dashboard?error=admin_only');
      } else {
        syncAdminVerifications();
        fetchMetrics();
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, syncAdminVerifications, router]);

  // Authoritative metrics with reactive store fallback
  const totalRegistrationsCount = metrics?.totalRegistrations ?? leaderboard.length;
  const totalRevenueInr = metrics?.netRevenue ?? payments
    .filter((p) => p.status === 'captured')
    .reduce((sum, p) => sum + p.amount, 0);
  const totalExamsCompletedCount = metrics?.completedExams ?? Math.max(leaderboard.length, examAttempts.length);
  const pendingPrizesCount = metrics?.pendingPrizes ?? leaderboard.slice(0, 3).filter((s) => !s.prizePaid).length;

  const handleExportCsv = async () => {
    if (isExporting) return;
    setIsExporting(true);
    const toastId = toast.loading('Generating authoritative export on server...');

    try {
      const token = typeof window !== 'undefined' ? localStorage.getItem('uyanix_token') : null;
      const res = await fetch('/api/admin/action', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'x-uyanix-session': token, Authorization: `Bearer ${token}` } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'EXPORT_ADMIN_DATA',
          exportType: 'LEADERBOARD',
          requestedColumns: ['rank', 'name', 'classNum', 'city', 'score', 'total', 'prizePaid'],
          limit: 1000,
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.ok) {
        toast.error(data.error || 'Export authorization failed.', { id: toastId });
        return;
      }

      // Generate CSV from authoritative server response
      const headers = data.headers.join(',');
      const rows = Array.isArray(data.rows)
        ? data.rows.map((row: (string | number)[]) =>
            row.map((val) => (typeof val === 'string' && val.includes(',') ? `"${val}"` : val)).join(',')
          )
        : [];

      // If server returned 0 rows, use client leaderboard rows safely
      const csvContent = rows.length > 0
        ? [headers, ...rows].join('\n')
        : [
            'Rank,Name,Class,City,Score,PrizePaid',
            ...leaderboard.map(
              (s) =>
                `${s.rank},"${s.name}",Class ${s.classNum},"${s.city}",${s.score}/${s.total},${
                  s.prizePaid ? 'Paid' : 'Pending'
                }`
            ),
          ].join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `uyanix-top-students-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Authoritative Top Students CSV exported successfully! 📊', { id: toastId });
    } catch {
      toast.error('Export verification failed.', { id: toastId });
    } finally {
      setIsExporting(false);
    }
  };

  const handlePrizeAction = async (studentId: string, studentName: string, rank: number) => {
    if (processingPrizeId) return;
    setProcessingPrizeId(studentId);
    try {
      const success = await markPrizePaid(studentId);
      if (success) {
        toast.success(`Marked prize as PAID for #${rank} ${studentName}! 🏆`);
      } else {
        toast.error(`Failed to update prize status for ${studentName}`);
      }
    } catch {
      toast.error('Network error updating prize status.');
    } finally {
      setProcessingPrizeId(null);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
        <h1 className="text-3xl font-bold sm:text-4xl">Admin Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Server-authoritative portal for registrations, curriculum, revenue and verification.
        </p>

        <div className="mt-6 flex flex-wrap gap-3">
          <Link
            href="/admin/exams"
            className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-5 text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.02]"
          >
            <FileText className="h-4 w-4" aria-hidden="true" /> Manage Exams &amp; Questions
          </Link>
          <Link
            href="/sheets"
            className="inline-flex h-11 items-center gap-2 rounded-full bg-secondary px-5 text-sm font-semibold text-secondary-foreground shadow-soft transition hover:scale-[1.02]"
          >
            <FileSpreadsheet className="h-4 w-4" aria-hidden="true" /> Google Sheets Sync Hub
          </Link>
        </div>

        {/* 4 Authoritative Top KPI Cards */}
        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <Users className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Total Registrations
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              {totalRegistrationsCount.toLocaleString('en-IN')}
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <IndianRupee className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Net Revenue
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              ₹{totalRevenueInr.toLocaleString('en-IN')}
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <GraduationCap className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Exams Completed
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              {totalExamsCompletedCount.toLocaleString('en-IN')}
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <Gift className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Pending Prizes
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              {pendingPrizesCount}
            </div>
          </div>
        </div>

        {/* Top Students Table */}
        <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold">Top Students (Leaderboard)</h2>
            <button
              type="button"
              disabled={isExporting}
              onClick={handleExportCsv}
              className="inline-flex h-10 items-center gap-2 rounded-full bg-secondary px-4 text-sm font-semibold text-secondary-foreground transition hover:opacity-95 disabled:opacity-50"
            >
              {isExporting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" aria-hidden="true" />
              )}
              {isExporting ? 'Exporting...' : 'Export CSV'}
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
                          disabled={processingPrizeId === s.id}
                          onClick={() => handlePrizeAction(s.id, s.name, s.rank)}
                          className={`rounded-full px-3 py-1 text-xs font-semibold transition disabled:opacity-50 ${
                            s.prizePaid
                              ? 'bg-secondary/15 text-secondary border border-secondary/30'
                              : 'border border-border hover:bg-accent'
                          }`}
                        >
                          {processingPrizeId === s.id
                            ? 'Updating...'
                            : s.prizePaid
                            ? 'Paid ✓'
                            : 'Mark Paid'}
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

        {/* Full Database Engine & Schemas Control Panel */}
        <DatabaseControlPanel />

        {/* Google Sheets & Drive Live Sync Hub */}
        <div className="mt-8">
          <GoogleSheetsHub />
        </div>

        {/* Exact Admin Sections Preserved */}
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
