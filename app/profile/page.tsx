'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { User, Save, CheckCircle2, CreditCard, Flame } from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export default function ProfilePage() {
  const router = useRouter();
  const { currentUser, updateProfile, completedDays, payments, examAttempts, syncServerSession } =
    useUyanixStore();

  useEffect(() => {
    let active = true;
    syncServerSession().then((serverUser) => {
      if (active && !serverUser) {
        router.replace('/login?redirect=/profile');
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, router]);

  const [name, setName] = useState(currentUser?.name || 'Student');
  const [classNum, setClassNum] = useState(String(currentUser?.classNum || 10));
  const [school, setSchool] = useState(currentUser?.school || '');
  const [city, setCity] = useState(currentUser?.city || '');
  const [phone, setPhone] = useState(currentUser?.phone || '');
  const [email, setEmail] = useState(currentUser?.email || '');
  const [streakReminders, setStreakReminders] = useState(
    currentUser?.streakReminders ?? true
  );

  useEffect(() => {
    if (currentUser) {
      setName(currentUser.name || 'Student');
      setClassNum(String(currentUser.classNum || 10));
      setSchool(currentUser.school || '');
      setCity(currentUser.city || '');
      setPhone(currentUser.phone || '');
      setEmail(currentUser.email || '');
      setStreakReminders(currentUser.streakReminders ?? true);
    }
  }, [currentUser]);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    updateProfile({
      name: name.trim(),
      classNum: Number(classNum),
      school: school.trim(),
      city: city.trim(),
      phone: phone.trim(),
      email: email.trim(),
      streakReminders,
    });
    toast.success('Profile details updated successfully! ✅');
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-4xl px-4 py-10 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold sm:text-4xl">My Profile &amp; Settings</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Apna naam, class, school aur daily streak reminders manage karein.
            </p>
          </div>
          <div className="inline-flex items-center gap-2 rounded-full bg-secondary/15 px-4 py-2 text-xs font-bold text-secondary">
            <CheckCircle2 className="h-4 w-4" /> {currentUser?.idVerified ? 'Student ID Verified' : 'Verification: Pending'}
          </div>
        </div>

        <div className="mt-8 grid gap-6 md:grid-cols-3">
          <form
            onSubmit={handleSave}
            className="space-y-4 rounded-3xl border border-border bg-card p-6 shadow-card md:col-span-2"
          >
            <div className="flex items-center gap-2 text-base font-bold">
              <User className="h-4 w-4 text-primary" /> Personal &amp; Academic Details
            </div>

            {currentUser?.registrationId && (
              <div className="rounded-2xl border border-primary/20 bg-primary/5 p-3 flex items-center justify-between">
                <div>
                  <span className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground block">Official Registration ID</span>
                  <span className="font-mono text-sm font-bold text-primary">{currentUser.registrationId}</span>
                </div>
                <span className="text-[10px] font-semibold text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-full flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" /> Registered
                </span>
              </div>
            )}

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                  Full Name
                </span>
                <input
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
                />
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                  Class (1–12)
                </span>
                <select
                  value={classNum}
                  onChange={(e) => setClassNum(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
                >
                  {Array.from({ length: 12 }, (_, i) => i + 1).map((c) => (
                    <option key={c} value={String(c)}>
                      Class {c}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                  School Name
                </span>
                <input
                  required
                  value={school}
                  onChange={(e) => setSchool(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
                />
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                  City
                </span>
                <input
                  required
                  value={city}
                  onChange={(e) => setCity(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
                />
              </label>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                  Mobile Number
                </span>
                <input
                  required
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
                />
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                  Email Address
                </span>
                <input
                  required
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
                />
              </label>
            </div>

            <label className="flex items-center gap-2.5 pt-2 text-xs font-medium text-foreground">
              <input
                type="checkbox"
                checked={streakReminders}
                onChange={(e) => setStreakReminders(e.target.checked)}
                className="h-4 w-4 rounded accent-primary"
              />
              Send daily 7:00 PM WhatsApp &amp; Email Streak Reminders
            </label>

            <button
              type="submit"
              className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
            >
              <Save className="h-4 w-4" /> Save Profile Changes
            </button>
          </form>

          {/* Activity Summary Sidebar */}
          <div className="space-y-4">
            <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
              <div className="flex items-center gap-2 text-sm font-bold">
                <Flame className="h-4 w-4 text-saffron" /> Learning Summary
              </div>
              <div className="mt-3 space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Completed Days</span>
                  <b className="tabular-nums">{completedDays.length} / 30</b>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Exams Taken</span>
                  <b className="tabular-nums">{examAttempts.length}</b>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Account Role</span>
                  <b className="uppercase text-primary">{currentUser?.role || 'student'}</b>
                </div>
              </div>
            </div>

            <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
              <div className="flex items-center gap-2 text-sm font-bold">
                <CreditCard className="h-4 w-4 text-primary" /> Exam Fee Receipts
              </div>
              <div className="mt-3 space-y-2 text-xs text-muted-foreground">
                {payments.slice(0, 3).map((p) => (
                  <div key={p.id} className="rounded-xl border border-border p-2.5">
                    <div className="flex justify-between font-semibold text-foreground">
                      <span>{p.type === 'final_exam' ? 'Final Exam' : 'Mid Exam'}</span>
                      <span className="tabular-nums">₹{p.amount}</span>
                    </div>
                    <div className="mt-0.5 font-mono text-[10px]">{p.razorpayId}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}
