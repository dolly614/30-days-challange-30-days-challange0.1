'use client';

import React, { useState } from 'react';
import {
  BarChart3,
  CreditCard,
  Megaphone,
  History,
  ShieldBan,
  Send,
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

const REVENUE_DATA = [
  { day: 'Sep 21', registrations: 1240, revenue: 145000 },
  { day: 'Sep 22', registrations: 1580, revenue: 178000 },
  { day: 'Sep 23', registrations: 1890, revenue: 204000 },
  { day: 'Sep 24', registrations: 2110, revenue: 192000 },
  { day: 'Sep 25', registrations: 2450, revenue: 238000 },
  { day: 'Sep 26', registrations: 1920, revenue: 164853 },
  { day: 'Sep 27', registrations: 1657, revenue: 150000 },
];

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

  const handleBroadcast = (e: React.FormEvent) => {
    e.preventDefault();
    if (!bTitle.trim() || !bBody.trim()) return;
    broadcastNotification(bTitle.trim(), bBody.trim());
    setBTitle('');
    setBBody('');
    toast.success('Notification broadcasted to all 12,847 students! 📢');
  };

  const filteredUsers = leaderboard.filter(
    (u) =>
      u.name.toLowerCase().includes(userSearch.toLowerCase()) ||
      u.city.toLowerCase().includes(userSearch.toLowerCase())
  );

  return (
    <div className="mt-10 space-y-8">
      {/* Recharts Revenue & Registration Analytics */}
      <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-primary" />
          <h2 className="text-xl font-bold">Analytics Overview (7-Day Trend)</h2>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Daily student registrations aur exam fee revenue (INR)
        </p>

        <div className="mt-5 h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={REVENUE_DATA}>
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
                        onClick={() => {
                          toggleBanStudent(u.id);
                          toast.info(`Updated access status for ${u.name}`);
                        }}
                        className="rounded-lg border border-border px-2.5 py-1 font-semibold hover:bg-accent"
                      >
                        {u.status === 'banned' ? 'Unban' : 'Suspend'}
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
            Recent ₹199 exam fee transactions aur instant refund controls
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
                          onClick={() => {
                            refundPayment(p.id);
                            toast.success(`Refund initiated for ${p.razorpayId}`);
                          }}
                          className="rounded-lg border border-destructive/40 px-2.5 py-1 font-semibold text-destructive hover:bg-destructive/10"
                        >
                          Refund
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
            Saare registered students ke Notification Bell mein message bhejein.
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
            className="inline-flex h-10 items-center gap-2 rounded-full bg-gradient-hero px-5 text-xs font-semibold text-primary-foreground shadow-soft"
          >
            <Send className="h-3.5 w-3.5" /> Broadcast Now
          </button>
        </form>

        <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex items-center gap-2">
            <History className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-bold">System Audit Logs</h3>
          </div>
          <div className="mt-3 max-h-52 space-y-2 overflow-y-auto text-xs">
            {auditLogs.map((log) => (
              <div
                key={log.id}
                className="flex items-center justify-between rounded-xl border border-border bg-background px-3 py-2"
              >
                <div>
                  <span className="font-mono font-bold text-primary">
                    {log.action}
                  </span>{' '}
                  <span className="text-foreground">→ {log.target}</span>
                  <div className="text-[10px] text-muted-foreground">
                    Actor: {log.actor}
                  </div>
                </div>
                <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                  {log.timestamp}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
