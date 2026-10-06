'use client';

import React from 'react';
import { Users, UserCheck, Banknote, ShieldAlert } from 'lucide-react';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export function TeachersPanel() {
  const {
    teachers,
    withdrawals,
    fraudLogs,
    updateTeacherStatus,
    processWithdrawal,
  } = useUyanixStore();

  const [processingTeacherId, setProcessingTeacherId] = React.useState<string | null>(null);
  const [processingWithdrawalId, setProcessingWithdrawalId] = React.useState<string | null>(null);

  const handleStatusChange = async (teacherId: string, status: 'approved' | 'rejected', teacherName: string) => {
    if (processingTeacherId) return;
    setProcessingTeacherId(teacherId);
    try {
      const success = await updateTeacherStatus(teacherId, status);
      if (success) {
        if (status === 'approved') {
          toast.success(`Teacher ${teacherName} approved! ✅`);
        } else {
          toast.info(`Teacher ${teacherName} status set to rejected.`);
        }
      } else {
        toast.error(`Failed to update status for ${teacherName}.`);
      }
    } catch {
      toast.error('Network error updating teacher status.');
    } finally {
      setProcessingTeacherId(null);
    }
  };

  const handleWithdrawalAction = async (withdrawalId: string, status: 'paid' | 'rejected') => {
    if (processingWithdrawalId) return;
    setProcessingWithdrawalId(withdrawalId);
    try {
      const success = await processWithdrawal(withdrawalId, status);
      if (success) {
        if (status === 'paid') {
          toast.success('Withdrawal marked as PAID in database! 💸');
        } else {
          toast.info('Withdrawal rejected & refunded to teacher wallet.');
        }
      } else {
        toast.error('Failed to process withdrawal transition.');
      }
    } catch {
      toast.error('Network error processing withdrawal.');
    } finally {
      setProcessingWithdrawalId(null);
    }
  };

  const approvedCount = teachers.filter((t) => t.status === 'approved').length;
  const pendingCount = teachers.filter((t) => t.status === 'pending').length;
  const totalCommissionsPaid = withdrawals
    .filter((w) => w.status === 'paid')
    .reduce((sum, w) => sum + w.amount, 0);

  return (
    <div className="mt-10 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Teacher Referral System</h2>
          <p className="text-sm text-muted-foreground">
            Approvals, withdrawals aur fraud alerts manage karein.
          </p>
        </div>
      </div>

      {/* 4 KPI Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <Users className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Total Teachers
          </div>
          <div className="mt-1 text-2xl font-extrabold tabular-nums">
            {teachers.length}
          </div>
        </div>

        <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <UserCheck className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Approved
          </div>
          <div className="mt-1 text-2xl font-extrabold tabular-nums">
            {approvedCount}
          </div>
          <div className="text-xs text-muted-foreground tabular-nums">
            {pendingCount} pending
          </div>
        </div>

        <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <Banknote className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Commissions Paid
          </div>
          <div className="mt-1 text-2xl font-extrabold tabular-nums">
            ₹{totalCommissionsPaid}
          </div>
        </div>

        <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Fraud Alerts
          </div>
          <div className="mt-1 text-2xl font-extrabold tabular-nums">
            {fraudLogs.length}
          </div>
        </div>
      </div>

      {/* Teachers Table */}
      <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
        <h3 className="mb-3 text-lg font-bold">Teachers</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-2 py-2">Name</th>
                <th className="px-2 py-2">Code</th>
                <th className="px-2 py-2">Status</th>
                <th className="px-2 py-2">Balance</th>
                <th className="px-2 py-2">Risk</th>
                <th className="px-2 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {teachers.map((t) => (
                <tr key={t.id} className="border-t border-border">
                  <td className="px-2 py-2">
                    <div className="font-medium">{t.name}</div>
                    <div className="text-xs text-muted-foreground">{t.email}</div>
                  </td>
                  <td className="px-2 py-2 font-mono text-xs">{t.code}</td>
                  <td className="px-2 py-2">
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-semibold ${
                        t.status === 'approved'
                          ? 'bg-secondary/15 text-secondary'
                          : t.status === 'pending'
                          ? 'bg-amber-500/15 text-amber-600'
                          : 'bg-destructive/15 text-destructive'
                      }`}
                    >
                      {t.status}
                    </span>
                  </td>
                  <td className="px-2 py-2 tabular-nums">
                    ₹{t.balance}{' '}
                    <span className="text-xs text-muted-foreground">
                      / ₹{t.totalEarned}
                    </span>
                  </td>
                  <td className="px-2 py-2 tabular-nums">{t.riskScore}</td>
                  <td className="px-2 py-2 text-right">
                    <div className="inline-flex gap-1">
                      {t.status !== 'approved' ? (
                        <button
                          type="button"
                          onClick={() => {
                            updateTeacherStatus(t.id, 'approved');
                            toast.success(`Teacher ${t.name} approved!`);
                          }}
                          className="rounded-md border border-border px-2 py-1 text-xs font-semibold hover:bg-accent"
                        >
                          Approve
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => {
                            updateTeacherStatus(t.id, 'rejected');
                            toast.info(`Teacher ${t.name} status set to rejected.`);
                          }}
                          className="rounded-md border border-border px-2 py-1 text-xs font-semibold hover:bg-accent"
                        >
                          Reject
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Withdrawal Requests Table */}
      <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
        <h3 className="mb-3 text-lg font-bold">Withdrawal Requests</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-2 py-2">Date</th>
                <th className="px-2 py-2">Teacher</th>
                <th className="px-2 py-2">Method</th>
                <th className="px-2 py-2">Destination</th>
                <th className="px-2 py-2">Amount</th>
                <th className="px-2 py-2">Status</th>
                <th className="px-2 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {withdrawals.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-2 py-6 text-center text-xs text-muted-foreground"
                  >
                    Koi withdrawal request nahi.
                  </td>
                </tr>
              ) : (
                withdrawals.map((w) => (
                  <tr key={w.id} className="border-t border-border">
                    <td className="px-2 py-2 text-xs">{w.date}</td>
                    <td className="px-2 py-2 font-medium">{w.teacherName}</td>
                    <td className="px-2 py-2">{w.method}</td>
                    <td className="px-2 py-2 font-mono text-xs">{w.destination}</td>
                    <td className="px-2 py-2 font-semibold tabular-nums">₹{w.amount}</td>
                    <td className="px-2 py-2 text-xs font-semibold uppercase">
                      {w.status}
                    </td>
                    <td className="px-2 py-2 text-right">
                      {w.status === 'pending' && (
                        <div className="inline-flex gap-1">
                          <button
                            type="button"
                            onClick={() => {
                              processWithdrawal(w.id, 'paid');
                              toast.success('Withdrawal marked as PAID!');
                            }}
                            className="rounded-md bg-secondary px-2 py-1 text-xs font-semibold text-secondary-foreground"
                          >
                            Mark Paid
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              processWithdrawal(w.id, 'rejected');
                              toast.error('Withdrawal rejected & refunded to wallet.');
                            }}
                            className="rounded-md border border-destructive px-2 py-1 text-xs font-semibold text-destructive"
                          >
                            Reject
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Fraud Log */}
      <div className="rounded-3xl border border-destructive/30 bg-destructive/5 p-6">
        <h3 className="mb-3 flex items-center gap-2 text-lg font-bold text-destructive">
          <ShieldAlert className="h-5 w-5" aria-hidden="true" /> Fraud Log
        </h3>
        {fraudLogs.length === 0 ? (
          <p className="text-xs text-muted-foreground">All clear ✅</p>
        ) : (
          <ul className="space-y-1 text-xs text-destructive">
            {fraudLogs.map((log, i) => (
              <li key={i}>{log}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
