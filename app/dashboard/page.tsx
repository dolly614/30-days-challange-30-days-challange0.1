'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Flame,
  CircleCheck,
  Trophy,
  Lock,
  Award,
  Share2,
  Search,
  BellRing,
} from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { getTopicsForClass } from '@/lib/curriculum';
import { buildCanonicalWhatsAppShareUrl } from '@/lib/seo-canonical-url-governance';
import { toast } from 'sonner';

export default function DashboardPage() {
  const router = useRouter();
  const {
    currentUser,
    completedDays,
    leaderboard,
    updateProfile,
    syncServerSession,
    syncStudentProgress,
    syncLeaderboard,
  } = useUyanixStore();
  const [chapterSearch, setChapterSearch] = useState('');

  useEffect(() => {
    let active = true;
    syncServerSession().then((serverUser) => {
      if (active && !serverUser) {
        router.replace('/login?redirect=/dashboard');
      } else if (active && serverUser) {
        syncStudentProgress();
        syncLeaderboard();
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, syncStudentProgress, syncLeaderboard, router]);

  const userClass = currentUser?.classNum || 12;
  const userName = currentUser?.name || 'dollysingh';
  const topics = getTopicsForClass(userClass);

  const completedCount = completedDays.length;
  const progressPercent = Math.round((completedCount / 30) * 100);
  const nextDay = Math.min(30, completedCount + 1);
  const nextTopicTitle = topics[nextDay - 1] || 'Globalization';

  const matchingDays = topics
    .map((title, idx) => ({ day: idx + 1, title }))
    .filter((item) =>
      chapterSearch.trim() === ''
        ? true
        : item.title.toLowerCase().includes(chapterSearch.toLowerCase()) ||
          String(item.day) === chapterSearch.trim()
    );

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-sm text-muted-foreground">Welcome back,</p>
            <h1 className="text-3xl font-bold sm:text-4xl">Hi {userName} 👋</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Class {userClass} • Apna progress dekho aur aaj ka task complete karo.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => {
                const next = !currentUser?.streakReminders;
                updateProfile({ streakReminders: next });
                toast.success(
                  next
                    ? 'Daily Streak Reminders ON (WhatsApp & Email) 🔔'
                    : 'Daily Streak Reminders paused'
                );
              }}
              className="inline-flex items-center gap-1.5 rounded-full border border-border bg-card px-3.5 py-2 text-xs font-semibold hover:bg-accent"
              title="Toggle Daily Streak Reminders"
            >
              <BellRing className="h-3.5 w-3.5 text-primary" />
              {currentUser?.streakReminders ? 'Reminders Active' : 'Enable Reminders'}
            </button>

            <div className="flex items-center gap-2 rounded-full bg-gradient-to-r from-saffron/20 to-india-green/20 px-4 py-2 text-sm font-semibold tabular-nums card-interactive">
              <Flame className="h-4 w-4 text-saffron animate-streak-fire" aria-hidden="true" /> {completedCount} day streak!
            </div>
          </div>
        </div>

        {/* 3 KPI Stat Cards */}
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          <div className="card-interactive rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <span className="h-2 w-2 rounded-full bg-secondary" /> Days Completed
            </div>
            <div className="mt-2 text-3xl font-extrabold tabular-nums">
              {completedCount}/30
            </div>
          </div>

          <div className="card-interactive rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <span className="h-2 w-2 rounded-full bg-primary" /> Progress
            </div>
            <div className="mt-2 text-3xl font-extrabold tabular-nums">
              {progressPercent}%
            </div>
          </div>

          <div className="card-interactive rounded-3xl border border-border bg-card p-5 shadow-card">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <span className="h-2 w-2 rounded-full bg-saffron" /> Current Rank
            </div>
            <div className="mt-2 text-3xl font-extrabold tabular-nums">#7</div>
          </div>
        </div>

        {/* Progress Bar with glossy continuous shimmer sweep */}
        <div className="shimmer-container relative mt-3 h-3.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="relative h-full overflow-hidden rounded-full bg-gradient-hero transition-all duration-500 ease-out"
            style={{ width: `${progressPercent}%` }}
          >
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/35 to-transparent animate-[shimmerSweep_2s_infinite]" />
          </div>
        </div>

        {/* Tracker + Sidebar */}
        <div className="mt-10 grid gap-6 lg:grid-cols-3">
          <div className="card-interactive rounded-3xl border border-border bg-card p-6 shadow-card lg:col-span-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-xl font-bold">30-Day Challenge Tracker</h2>
                <span className="text-xs text-muted-foreground">
                  Class {userClass} curriculum
                </span>
              </div>

              {/* Search Chapters input */}
              <div className="relative w-full sm:w-56">
                <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                <input
                  value={chapterSearch}
                  onChange={(e) => setChapterSearch(e.target.value)}
                  placeholder="Search chapter or day..."
                  className="h-8 w-full rounded-full border border-border bg-background pl-8 pr-3 text-xs outline-none focus:border-primary"
                />
              </div>
            </div>

            <div className="mt-5 grid grid-cols-5 gap-2 sm:grid-cols-6 md:grid-cols-10">
              {matchingDays.map(({ day, title }) => {
                const isDone = completedDays.includes(day);
                const isToday = day === nextDay && !isDone;

                return (
                  <Link
                    key={day}
                    title={`Day ${day}: ${title}`}
                    href={`/daily/${day}`}
                    className={`relative flex aspect-square flex-col items-center justify-center rounded-xl text-xs font-semibold transition-all duration-150 hover:scale-110 active:scale-95 ${
                      isDone
                        ? 'bg-secondary text-secondary-foreground shadow-sm'
                        : isToday
                        ? 'bg-primary text-primary-foreground ring-2 ring-primary/40 animate-pulse-glow'
                        : 'bg-muted text-muted-foreground hover:bg-muted-foreground/20'
                    }`}
                  >
                    {isDone && (
                      <CircleCheck
                        className="animate-pop-in absolute right-1 top-1 h-3 w-3"
                        aria-hidden="true"
                      />
                    )}
                    <span className="text-[10px] opacity-80">Day</span>
                    <span className="text-base tabular-nums">{day}</span>
                  </Link>
                );
              })}
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5">
                <span className="h-3 w-3 rounded bg-secondary" /> Completed
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-3 w-3 rounded bg-primary" /> Today
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-3 w-3 rounded bg-muted" /> Upcoming
              </div>
            </div>
          </div>

          {/* Right Action Cards */}
          <div className="space-y-6">
            <div className="card-interactive animate-aura rounded-3xl border border-border bg-gradient-hero p-6 text-primary-foreground shadow-soft">
              <div className="text-xs font-semibold uppercase tracking-widest opacity-80">
                Aaj ka task
              </div>
              <div className="mt-2 text-xl font-bold">
                Day {nextDay}: {nextTopicTitle}
              </div>
              <p className="mt-1 text-sm opacity-90">5 MCQs • ~10 mins</p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Link
                  href="/exam?type=mid"
                  className="inline-flex h-10 items-center rounded-full bg-card px-5 text-sm font-semibold text-primary shadow-soft transition hover:scale-[1.03]"
                >
                  Take Mid Exam →
                </Link>
                <Link
                  href={`/daily/${nextDay}`}
                  className="inline-flex h-10 items-center rounded-full border border-white/40 bg-white/15 px-4 text-xs font-semibold text-white transition hover:bg-white/25"
                >
                  Open Day {nextDay} Notes
                </Link>
              </div>
            </div>

            <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
              <div className="flex items-center gap-2 text-sm font-bold">
                <Trophy className="h-4 w-4 text-saffron" aria-hidden="true" />
                Exams
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                Registration FREE hai. Exam fee sirf exam dene ke time pe.
              </p>
              <div className="mt-3 space-y-2">
                <Link
                  href="/exam?type=mid"
                  className="flex h-10 w-full items-center justify-center rounded-full bg-secondary text-xs font-semibold text-secondary-foreground transition hover:opacity-95"
                >
                  Mid Exam (15 Days) · ₹199
                </Link>

                {completedCount >= 30 ? (
                  <Link
                    href="/exam?type=final"
                    className="flex h-10 w-full items-center justify-center gap-2 rounded-full bg-gradient-hero text-xs font-semibold text-primary-foreground shadow-soft"
                  >
                    Final Exam (30 Days) · ₹199
                  </Link>
                ) : (
                  <button
                    type="button"
                    onClick={() => router.push('/exam?type=final')}
                    className="flex h-10 w-full items-center justify-center gap-2 rounded-full bg-muted text-xs font-semibold text-muted-foreground transition hover:bg-accent"
                  >
                    <Lock className="h-3 w-3" aria-hidden="true" /> Final Exam — Day 30 pe unlock
                  </button>
                )}
              </div>
            </div>

            <button
              type="button"
              onClick={() => router.push('/certificate')}
              className="flex w-full items-center justify-center gap-2 rounded-2xl border border-border bg-card p-4 text-sm font-semibold shadow-card transition hover:bg-accent"
            >
              <Award className="h-4 w-4 text-primary" aria-hidden="true" />
              Download Certificate
            </button>

            <a
              href={buildCanonicalWhatsAppShareUrl(completedCount)}
              target="_blank"
              rel="noreferrer"
              className="flex w-full items-center justify-center gap-2 rounded-2xl bg-secondary p-4 text-sm font-semibold text-secondary-foreground transition hover:opacity-90"
            >
              <Share2 className="h-4 w-4" aria-hidden="true" /> Share on WhatsApp
            </a>
          </div>
        </div>

        {/* Top 10 Leaderboard Section */}
        <div className="mt-10 rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold">🏆 Top 10 Leaderboard</h2>
            <Link
              href="/leaderboard"
              className="text-sm font-semibold text-primary hover:underline"
            >
              View full →
            </Link>
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Rank</th>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Class</th>
                  <th className="px-3 py-2">City</th>
                  <th className="px-3 py-2 text-right">Score</th>
                </tr>
              </thead>
              <tbody>
                {leaderboard.slice(0, 10).map((s) => {
                  const isTop3 = s.rank <= 3;
                  const medal =
                    s.rank === 1 ? '🥇' : s.rank === 2 ? '🥈' : s.rank === 3 ? '🥉' : '⭐';
                  return (
                    <tr
                      key={s.id}
                      className={`border-t border-border ${isTop3 ? 'bg-accent/40' : ''}`}
                    >
                      <td className="px-3 py-3 font-bold tabular-nums">
                        {medal} {s.rank}
                      </td>
                      <td className="px-3 py-3 font-medium">{s.name}</td>
                      <td className="px-3 py-3">Class {s.classNum}</td>
                      <td className="px-3 py-3 text-muted-foreground">{s.city}</td>
                      <td className="px-3 py-3 text-right font-semibold tabular-nums">
                        {s.score}/{s.total}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}
