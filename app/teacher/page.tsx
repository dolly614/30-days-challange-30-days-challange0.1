'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Award,
  LogOut,
  Users,
  UserCheck,
  Wallet,
  TrendingUp,
  QrCode,
  Copy,
  Share2,
  IndianRupee,
  GraduationCap,
  Banknote,
  ShieldAlert,
  FileCheck2,
  PlusCircle,
  Download,
} from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { buildCanonicalTeacherReferralUrl } from '@/lib/seo-canonical-url-governance';
import { toast } from 'sonner';

export default function TeacherPortalPage() {
  const router = useRouter();
  const {
    teachers,
    referrals,
    withdrawals,
    logout,
    syncTeacherData,
    requestWithdrawal,
    submitTeacherKyc,
    simulateTeacherReferral,
    syncServerSession,
  } = useUyanixStore();

  useEffect(() => {
    let active = true;
    syncServerSession().then((serverUser) => {
      if (!active) return;
      if (!serverUser) {
        router.replace('/login?redirect=/teacher');
      } else if (serverUser.role !== 'teacher' && serverUser.role !== 'admin') {
        router.replace('/dashboard?error=teacher_only');
      } else {
        syncTeacherData();
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, syncTeacherData, router]);

  const teacher = teachers[0];
  const [payoutMethod, setPayoutMethod] = useState<'UPI' | 'Bank'>('UPI');
  const [destination, setDestination] = useState(
    teacher?.upiId || 'shiv9897320579@gmail.com'
  );
  const [amount, setAmount] = useState(500);
  const [showKycModal, setShowKycModal] = useState(false);
  const [panInput, setPanInput] = useState(teacher?.kycPan || 'ABCDE1234F');

  const referralUrl = buildCanonicalTeacherReferralUrl(
    teacher?.code || 'DOLLOXW0'
  );

  const conversionRate =
    teacher && teacher.referredCount > 0
      ? Math.round((teacher.paidActiveCount / teacher.referredCount) * 100)
      : 0;

  const tierProgress = teacher
    ? Math.min(100, Math.round((teacher.paidActiveCount / 50) * 100))
    : 0;

  const handleCopyLink = () => {
    navigator.clipboard.writeText(referralUrl);
    toast.success('Referral link copied to clipboard! 📋');
  };

  const handleWithdrawSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!teacher || teacher.balance < amount) {
      toast.error('Minimum ₹500 available balance chahiye payout request ke liye!');
      return;
    }
    const ok = await requestWithdrawal(payoutMethod, destination, amount);
    if (ok) {
      toast.success(`₹${amount} payout request submitted via ${payoutMethod}! 💸`);
    } else {
      toast.error('Withdrawal request failed. Please check available balance.');
    }
  };

  const handleKycSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    submitTeacherKyc(panInput, destination);
    setShowKycModal(false);
    toast.success('Teacher KYC submitted for Admin verification!');
  };

  const handleDownloadInvoice = (invoiceId: string, amt: number, date: string) => {
    const text = `UYANIX EDUCATOR PAYOUT INVOICE\nInvoice ID: ${invoiceId}\nTeacher: ${teacher?.name} (${teacher?.code})\nDate: ${date}\nMethod: ${payoutMethod} (${destination})\nAmount: INR ${amt}\nStatus: Verified`;
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${invoiceId}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Invoice ${invoiceId} downloaded!`);
  };

  const maxSignup = Math.max(
    1,
    ...(teacher?.dailySignups.map((d) => d.count) || [1])
  );

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-accent/60 px-3 py-1 text-xs font-semibold">
              <Award className="h-3.5 w-3.5 text-primary" aria-hidden="true" />{' '}
              {teacher?.tier || 'Beginner Teacher'}
              <span
                className={`ml-2 rounded-full px-2 py-0.5 ${
                  teacher?.status === 'approved'
                    ? 'bg-secondary/15 text-secondary'
                    : 'bg-amber-500/15 text-amber-600'
                }`}
              >
                Status: {teacher?.status || 'rejected'}
              </span>
            </div>

            <h1 className="mt-2 text-3xl font-extrabold sm:text-4xl">
              Hi, {teacher?.name || 'dolly'} 👋
            </h1>
            <p className="text-sm text-muted-foreground">
              Aapka referral code:{' '}
              <span className="font-mono font-semibold text-foreground">
                {teacher?.code || 'DOLLOXW0'}
              </span>
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => {
                simulateTeacherReferral();
                toast.error(
                  'Demo referral simulation is disabled in production. Referrals are credited from verified student registrations.'
                );
              }}
              className="inline-flex h-10 items-center gap-1.5 rounded-full bg-secondary/15 px-4 text-xs font-semibold text-secondary transition hover:bg-secondary/25"
            >
              <PlusCircle className="h-4 w-4" /> Simulate Referral (+₹250)
            </button>

            <button
              type="button"
              onClick={() => setShowKycModal(true)}
              className="inline-flex h-10 items-center gap-1.5 rounded-full border border-border bg-card px-4 text-xs font-semibold transition hover:bg-accent"
            >
              <FileCheck2 className="h-4 w-4 text-primary" />{' '}
              {teacher?.kycVerified ? 'KYC Verified' : 'Complete KYC'}
            </button>

            <button
              type="button"
              onClick={() => {
                logout();
                toast.success('Logged out from Teacher Portal');
                router.push('/login');
              }}
              className="inline-flex h-10 items-center gap-2 rounded-full border border-border bg-card px-4 text-sm font-semibold transition hover:bg-accent"
            >
              <LogOut className="h-4 w-4" aria-hidden="true" /> Logout
            </button>
          </div>
        </div>

        {/* 4 KPI Stat Cards */}
        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-3xl border border-border bg-card/80 p-5 shadow-card backdrop-blur">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <Users className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Referred Students
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              {teacher?.referredCount || 0}
            </div>
            <div className="mt-1 text-xs text-muted-foreground tabular-nums">
              {teacher?.pendingReferrals || 0} pending
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card/80 p-5 shadow-card backdrop-blur">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <UserCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Paid &amp; Active
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              {teacher?.paidActiveCount || 0}
            </div>
            <div className="mt-1 text-xs text-muted-foreground tabular-nums">
              {conversionRate}% conversion
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card/80 p-5 shadow-card backdrop-blur">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <Wallet className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Available Balance
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              ₹{teacher?.balance || 0}
            </div>
            <div className="mt-1 text-xs text-muted-foreground tabular-nums">
              Total earned ₹{teacher?.totalEarned || 0}
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card/80 p-5 shadow-card backdrop-blur">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <TrendingUp className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              This Month
            </div>
            <div className="mt-1 text-2xl font-extrabold tabular-nums">
              ₹{teacher?.thisMonthEarned || 0}
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              From verified payouts
            </div>
          </div>
        </div>

        {/* 3 Middle Cards: QR Referral, Current Rank, Withdraw Earnings */}
        <div className="mt-8 grid gap-6 lg:grid-cols-3">
          {/* Card 1: Your Referral */}
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card lg:col-span-1">
            <div className="mb-3 flex items-center gap-2 text-sm font-bold">
              <QrCode className="h-4 w-4" aria-hidden="true" /> Your Referral
            </div>

            <div className="mx-auto flex h-40 w-40 items-center justify-center rounded-xl border border-border bg-white p-2">
              <QRCodeSVG value={referralUrl} size={136} />
            </div>

            <div className="mt-4 flex items-center gap-2 rounded-xl border border-border bg-background p-2 text-xs">
              <span className="truncate font-mono">{referralUrl}</span>
              <button
                type="button"
                onClick={handleCopyLink}
                className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-primary/10 px-2 py-1 text-primary hover:bg-primary/20"
              >
                <Copy className="h-3 w-3" aria-hidden="true" />
                Copy
              </button>
            </div>

            <div className="mt-3 grid grid-cols-4 gap-2 text-xs">
              <a
                target="_blank"
                rel="noreferrer"
                href={`https://wa.me/?text=${encodeURIComponent(
                  `Join Uyanix 30 Days Challenge with my code ${teacher?.code || 'DOLLOXW0'} → ${referralUrl}`
                )}`}
                className="rounded-lg border border-border py-2 text-center hover:bg-accent"
              >
                WhatsApp
              </a>
              <a
                target="_blank"
                rel="noreferrer"
                href={`https://t.me/share/url?url=${encodeURIComponent(
                  referralUrl
                )}&text=${encodeURIComponent(
                  `Join Uyanix 30 Days Challenge with my code ${teacher?.code || 'DOLLOXW0'} → ${referralUrl}`
                )}`}
                className="rounded-lg border border-border py-2 text-center hover:bg-accent"
              >
                Telegram
              </a>
              <a
                target="_blank"
                rel="noreferrer"
                href={`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(
                  referralUrl
                )}`}
                className="rounded-lg border border-border py-2 text-center hover:bg-accent"
              >
                Facebook
              </a>
              <button
                type="button"
                onClick={handleCopyLink}
                className="inline-flex items-center justify-center gap-1 rounded-lg border border-border py-2 hover:bg-accent"
              >
                <Share2 className="h-3 w-3" aria-hidden="true" />
                More
              </button>
            </div>
          </div>

          {/* Card 2: Current Rank */}
          <div className="rounded-3xl border border-border bg-gradient-hero p-6 text-primary-foreground shadow-soft">
            <div className="text-xs font-semibold uppercase opacity-80">
              Current Rank
            </div>
            <div className="mt-1 text-2xl font-extrabold">
              {teacher?.tier || 'Beginner Teacher'}
            </div>
            <div className="mt-1 text-xs opacity-80 tabular-nums">
              {teacher?.paidActiveCount || 0} active paid students
            </div>

            <div className="mt-5 text-xs opacity-80">
              Next: <b>Active Mentor</b>
            </div>
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-white/20">
              <div
                className="h-full bg-white transition-all"
                style={{ width: `${tierProgress}%` }}
              />
            </div>

            <div className="mt-5 grid grid-cols-3 gap-2 text-[10px] opacity-90">
              <div>
                1–50
                <br />
                <b>₹10/student</b>
              </div>
              <div>
                51–200
                <br />
                <b>₹15/student</b>
              </div>
              <div>
                200+
                <br />
                <b>₹20/student</b>
              </div>
            </div>
          </div>

          {/* Card 3: Withdraw Earnings */}
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <div className="flex items-center gap-2 text-sm font-bold">
              <Wallet className="h-4 w-4" aria-hidden="true" /> Withdraw Earnings
            </div>
            <div className="mt-2 text-xs text-muted-foreground">
              Available: <b className="text-foreground tabular-nums">₹{teacher?.balance || 0}</b> · Min ₹500
            </div>

            <form onSubmit={handleWithdrawSubmit} className="mt-4 space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setPayoutMethod('UPI')}
                  className={`rounded-xl border px-3 py-2 text-xs font-semibold transition ${
                    payoutMethod === 'UPI'
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border'
                  }`}
                >
                  UPI
                </button>
                <button
                  type="button"
                  onClick={() => setPayoutMethod('Bank')}
                  className={`rounded-xl border px-3 py-2 text-xs font-semibold transition ${
                    payoutMethod === 'Bank'
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border'
                  }`}
                >
                  Bank
                </button>
              </div>

              <input
                required
                placeholder={payoutMethod === 'UPI' ? 'name@upi' : 'A/C No & IFSC Code'}
                value={destination}
                onChange={(e) => setDestination(e.target.value)}
                className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
              />

              <input
                required
                type="number"
                min={500}
                step={50}
                value={amount}
                onChange={(e) => setAmount(Number(e.target.value))}
                className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2 tabular-nums"
              />

              <button
                type="submit"
                disabled={(teacher?.balance || 0) < 500}
                className="inline-flex h-11 w-full items-center justify-center rounded-full bg-gradient-hero text-sm font-semibold text-primary-foreground shadow-soft disabled:opacity-50"
              >
                Request Payout
              </button>
            </form>
          </div>
        </div>

        {/* Daily Signups Bar Chart */}
        <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold">Daily Signups (last 14 days)</h2>
              <p className="text-xs text-muted-foreground">
                Track kab aapke students join karte hain
              </p>
            </div>
            <IndianRupee className="h-5 w-5 text-primary" aria-hidden="true" />
          </div>

          <div className="mt-6 flex h-40 items-end gap-1.5">
            {(teacher?.dailySignups || []).map((d) => {
              const heightPct = d.count > 0 ? Math.round((d.count / maxSignup) * 100) : 0;
              return (
                <div
                  key={d.dayLabel}
                  className="flex flex-1 flex-col items-center gap-1"
                >
                  <div
                    className="w-full rounded-t-md bg-gradient-hero transition-all"
                    title={`${d.count} signups`}
                    style={{ height: `${heightPct}%`, minHeight: '4px' }}
                  />
                  <div className="text-[10px] text-muted-foreground tabular-nums">
                    {d.dayLabel}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Referrals & Withdrawal History */}
        <div className="mt-8 grid gap-6 lg:grid-cols-2">
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <div className="mb-3 flex items-center gap-2 text-sm font-bold">
              <GraduationCap className="h-4 w-4" aria-hidden="true" />
              Recent Referrals
            </div>

            {referrals.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
                Abhi tak koi referral nahi. Apna link share karein.
              </div>
            ) : (
              <div className="space-y-2">
                {referrals.map((r) => (
                  <div
                    key={r.id}
                    className="flex items-center justify-between rounded-xl border border-border p-3 text-xs"
                  >
                    <div>
                      <div className="font-semibold text-foreground">
                        {r.studentName} (Class {r.studentClass})
                      </div>
                      <div className="text-[11px] text-muted-foreground">{r.date}</div>
                    </div>
                    <div className="text-right">
                      <div className="font-bold text-secondary tabular-nums">
                        +₹{r.commission}
                      </div>
                      <div className="text-[10px] uppercase text-muted-foreground">
                        {r.status}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <div className="mb-3 flex items-center gap-2 text-sm font-bold">
              <Banknote className="h-4 w-4" aria-hidden="true" />
              Withdrawal History
            </div>

            {withdrawals.length === 0 ? (
              <div className="rounded-xl border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
                Koi withdrawal request nahi.
              </div>
            ) : (
              <div className="space-y-2">
                {withdrawals.map((w) => (
                  <div
                    key={w.id}
                    className="flex items-center justify-between rounded-xl border border-border p-3 text-xs"
                  >
                    <div>
                      <div className="font-semibold text-foreground tabular-nums">
                        ₹{w.amount} via {w.method}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        {w.destination} • {w.date}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="rounded-full bg-accent px-2.5 py-0.5 text-[10px] font-bold uppercase text-primary">
                        {w.status}
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          handleDownloadInvoice(w.invoiceId, w.amount, w.date)
                        }
                        title="Download Payout Invoice"
                        className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-border hover:bg-accent"
                      >
                        <Download className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Compliance Notice */}
        <div className="mt-8 rounded-2xl border border-border bg-accent/40 p-5 text-xs text-muted-foreground">
          <div className="flex items-start gap-2">
            <ShieldAlert
              className="mt-0.5 h-4 w-4 shrink-0 text-primary"
              aria-hidden="true"
            />
            <p>
              <b className="text-foreground">Compliance:</b> Self-referral, duplicate device/email/phone, refunded payments aur fake accounts pe commission cancel ho jaata hai. Chain / sub-affiliate referral allowed nahi hai.{' '}
              <Link href="/admin" className="underline">
                Admin
              </Link>{' '}
              manual review bhi karta hai.
            </p>
          </div>
        </div>
      </section>

      {/* Teacher KYC Modal */}
      {showKycModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
          <form
            onSubmit={handleKycSubmit}
            className="w-full max-w-md rounded-3xl border border-border bg-card p-6 shadow-soft space-y-4"
          >
            <h3 className="text-lg font-bold">Teacher KYC Verification 🪪</h3>
            <p className="text-xs text-muted-foreground">
              Instant UPI / Bank withdrawals enable karne ke liye apna PAN aur UPI ID verify karein.
            </p>
            <label className="block">
              <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                PAN Card Number
              </span>
              <input
                required
                value={panInput}
                onChange={(e) => setPanInput(e.target.value.toUpperCase())}
                placeholder="ABCDE1234F"
                className="h-11 w-full rounded-xl border border-input bg-background px-3 font-mono text-sm uppercase outline-none focus:border-primary"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                Verified UPI ID
              </span>
              <input
                required
                value={destination}
                onChange={(e) => setDestination(e.target.value)}
                className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
              />
            </label>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowKycModal(false)}
                className="h-10 rounded-full border border-border px-4 text-xs font-semibold hover:bg-accent"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="h-10 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
              >
                Verify KYC &amp; Approve
              </button>
            </div>
          </form>
        </div>
      )}

      <Footer />
    </div>
  );
}
