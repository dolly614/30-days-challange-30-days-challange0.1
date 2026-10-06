'use client';

import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  CreditCard,
  Megaphone,
  History,
  ShieldBan,
  Send,
  Loader2,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

interface AnalyticsPoint {
  day: string;
  date: string;
  registrations: number;
  revenue: number;
  refunds: number;
  netRevenue: number;
  examAttempts: number;
}

export function AdminExtendedPanels() {
  const {
    leaderboard,
    payments,
    auditLogs,
    toggleBanStudent,
    refundPayment,
    broadcastNotification,
  } = useUyanixStore();

  const [bTitle, setBTitle] = useState('');
  const [bBody, setBBody] = useState('');
  const [userSearch, setUserSearch] = useState('');
  const [isBroadcasting, setIsBroadcasting] = useState(false);
  const [processingRefundId, setProcessingRefundId] = useState<string | null>(null);
  const [processingBanId, setProcessingBanId] = useState<string | null>(null);

  // Authoritative Analytics Data from Server
  const [analyticsData, setAnalyticsData] = useState<AnalyticsPoint[]>([]);
  const [isLoadingAnalytics, setIsLoadingAnalytics] = useState(true);

  useEffect(() => {
    let active = true;
    fetch('/api/admin/metrics', { credentials: 'include' })
      .then((res) => res.json())
      .then((data) => {
        if (!active) return;
        if (data.ok && Array.isArray(data.analytics)) {
          setAnalyticsData(data.analytics);
        }
      })
      .catch(() => {})
      .finally(() => {
        if (active) setIsLoadingAnalytics(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleBroadcast = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bTitle.trim() || !bBody.trim() || isBroadcasting) return;

    setIsBroadcasting(true);
    const toastId = toast.loading('Broadcasting notification via server...');

    try {
      const result = await broadcastNotification(bTitle.trim(), bBody.trim());
      if (result.ok) {
        toast.success(
          `Notification broadcasted to ${result.recipientCount ?? 1} registered students! 📢`,
          { id: toastId }
        );
        setBTitle('');
        setBBody('');
      } else {
        toast.error('Failed to broadcast notification.', { id: toastId });
      }
    } catch {
      toast.error('Network error during broadcast.', { id: toastId });
    } finally {
      setIsBroadcasting(false);
    }
  };

  const handleRefund = async (paymentId: string, razorpayId: string) => {
    if (processingRefundId) return;
    setProcessingRefundId(paymentId);
    const toastId = toast.loading(`Processing refund for ${razorpayId}...`);

    try {
      const success = await refundPayment(paymentId);
      if (success) {
        toast.success(`Refund completed for ${razorpayId}! ✅`, { id: toastId });
      } else {
        toast.error('Failed to process refund. Ensure payment is captured.', { id: toastId });
      }
    } catch {
      toast.error('Network error during refund.', { id: toastId });
    } finally {
      setProcessingRefundId(null);
    }
  };

  const handleToggleBan = async (studentId: string, studentName: string) => {
    if (processingBanId) return;
    setProcessingBanId(studentId);
    try {
      const success = await toggleBanStudent(studentId);
      if (success) {
        toast.info(`Updated access status for ${studentName}`);
      } else {
        toast.error(`Failed to update status for ${studentName}`);
      }
    } catch {
      toast.error('Network error updating student status.');
    } finally {
      setProcessingBanId(null);
    }
  };

  const filteredUsers = leaderboard.filter(
    (u) =>
      u.name.toLowerCase().includes(userSearch.toLowerCase()) ||
      u.city.toLowerCase().includes(userSearch.toLowerCase())
  );

  return (
    <div className="mt-10 space-y-8">
      {/* Recharts Revenue & Registration Analytics (Server-Authoritative) */}
      <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-primary" />
          <h2 className="text-xl font-bold">Analytics Overview (Authoritative 7-Day Trend)</h2>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Authoritative student registrations aur exam fee revenue (INR) queried from database
        </p>

        <div className="mt-5 h-64 w-full">
          {isLoadingAnalytics ? (
            <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin text-primary" /> Loading analytics metrics...
            </div>
          ) : analyticsData.length === 0 ? (
            <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
              No revenue events recorded in the last 7 days.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analyticsData}>
                <defs>
                  <linearGradient id="colorRev" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#7c3aed" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                <XAxis dataKey="day" fontSize={12} />
                <YAxis fontSize={12} />
                <Tooltip />
                <Area
                  type="monotone"
                  dataKey="revenue"
                  stroke="#7c3aed"
                  strokeWidth={2.5}
                  fillOpacity={1}
                  fill="url(#colorRev)"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* User Management & Payments Grid */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* User & Role Management */}
        <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldBan className="h-5 w-5 text-primary" />
              <h3 className="text-lg font-bold">User &amp; Access Management</h3>
            </div>
            <input
              value={userSearch}
              onChange={(e) => setUserSearch(e.target.value)}
              placeholder="Search student..."
              className="h-8 rounded-full border border-input bg-background px-3 text-xs outline-none focus:border-primary"
            />
          </div>

          <div className="mt-4 max-h-64 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="text-left uppercase text-muted-foreground">
                <tr>
                  <th className="py-2">Student</th>
                  <th className="py-2">School</th>
                  <th className="py-2">Status</th>
                  <th className="py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => (
                  <tr key={u.id} className="border-t border-border">
                    <td className="py-2.5 font-semibold">
                      {u.name} (C{u.classNum})
                    </td>
                    <td className="py-2.5 text-muted-foreground">
                      {u.school || u.city}
                    </td>
                    <td className="py-2.5">
                      <span
                        className={`font-semibold uppercase ${
                          u.status === 'banned' ? 'text-destructive' : 'text-secondary'
                        }`}
                      >
                        {u.status || 'active'}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        type="button"
                        disabled={processingBanId === u.id}
                        onClick={() => handleToggleBan(u.id, u.name)}
                        className="rounded-lg border border-border px-2.5 py-1 font-semibold hover:bg-accent disabled:opacity-50"
                      >
                        {processingBanId === u.id
                          ? 'Updating...'
                          : u.status === 'banned'
                          ? 'Unban'
                          : 'Suspend'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Payment & Refund Management */}
        <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex items-center gap-2">
            <CreditCard className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-bold">Razorpay Payments &amp; Refunds</h3>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Authoritative ₹199 exam fee transactions aur server-governed refund controls
          </p>

          <div className="mt-4 max-h-64 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="text-left uppercase text-muted-foreground">
                <tr>
                  <th className="py-2">Student</th>
                  <th className="py-2">Razorpay ID</th>
                  <th className="py-2">Status</th>
                  <th className="py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {payments.map((p) => (
                  <tr key={p.id} className="border-t border-border">
                    <td className="py-2.5 font-semibold">
                      {p.userName} (₹{p.amount})
                    </td>
                    <td className="py-2.5 font-mono text-[11px] text-muted-foreground">
                      {p.razorpayId}
                    </td>
                    <td className="py-2.5">
                      <span
                        className={`font-semibold uppercase ${
                          p.status === 'refunded' ? 'text-amber-600' : 'text-secondary'
                        }`}
                      >
                        {p.status}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      {p.status === 'captured' && (
                        <button
                          type="button"
                          disabled={processingRefundId === p.id}
                          onClick={() => handleRefund(p.id, p.razorpayId)}
                          className="rounded-lg border border-destructive/40 px-2.5 py-1 font-semibold text-destructive hover:bg-destructive/10 disabled:opacity-50"
                        >
                          {processingRefundId === p.id ? 'Refunding...' : 'Refund'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Broadcast Notifications & Audit Logs */}
      <div className="grid gap-6 lg:grid-cols-2">
        <form
          onSubmit={handleBroadcast}
          className="rounded-3xl border border-border bg-card p-6 shadow-card space-y-3"
        >
          <div className="flex items-center gap-2">
            <Megaphone className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-bold">Broadcast Push Notification</h3>
          </div>
          <p className="text-xs text-muted-foreground">
            Saare registered students ke Notification Bell mein authoritative message bhejein.
          </p>
          <input
            required
            placeholder="Notification Title (e.g. Final Exam Date Announced!)"
            value={bTitle}
            onChange={(e) => setBTitle(e.target.value)}
            className="h-10 w-full rounded-xl border border-input bg-background px-3 text-xs outline-none focus:border-primary"
          />
          <textarea
            required
            rows={3}
            placeholder="Hinglish message body..."
            value={bBody}
            onChange={(e) => setBBody(e.target.value)}
            className="w-full rounded-xl border border-input bg-background p-3 text-xs outline-none focus:border-primary"
          />
          <button
            type="submit"
            disabled={isBroadcasting}
            className="inline-flex h-10 items-center gap-2 rounded-full bg-primary px-5 text-xs font-semibold text-primary-foreground shadow-soft hover:opacity-90 disabled:opacity-50"
          >
            {isBroadcasting ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Send className="h-3.5 w-3.5" />
            )}
            {isBroadcasting ? 'Broadcasting...' : 'Broadcast to All Students'}
          </button>
        </form>

        {/* Real Audit Trail */}
        <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex items-center gap-2">
            <History className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-bold">Immutable Audit Logs</h3>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Recent administrative operations recorded in server append-only ledger
          </p>

          <div className="mt-4 max-h-56 overflow-y-auto space-y-2 text-xs">
            {auditLogs.length === 0 ? (
              <p className="text-xs text-muted-foreground">No recent audit logs.</p>
            ) : (
              auditLogs.slice(0, 15).map((log) => (
                <div
                  key={log.id}
                  className="rounded-xl border border-border/80 bg-muted/20 p-2.5"
                >
                  <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                    <span className="font-mono font-semibold text-primary">
                      {log.action}
                    </span>
                    <span>{log.timestamp}</span>
                  </div>
                  <div className="mt-1 text-xs">
                    Target: <span className="font-semibold">{log.target}</span> • Actor:{' '}
                    <span className="font-mono text-muted-foreground">{log.actor}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
