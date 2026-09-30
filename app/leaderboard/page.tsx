'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { RefreshCw, Search, Award, FileSpreadsheet } from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

type ClassFilter = 'all' | '1-5' | '6-8' | '9-12';

const TEACHER_LEADERBOARD = [
  { rank: 1, name: 'Rajeshwari Devi', school: 'KV No. 1, Jaipur', city: 'Jaipur', students: 245, tier: 'Super Educator', earned: '₹4,900' },
  { rank: 2, name: 'Anil Kumar Verma', school: 'DPS Indirapuram', city: 'Ghaziabad', cityState: 'UP', students: 168, tier: 'Active Mentor', earned: '₹2,520' },
  { rank: 3, name: 'Sunita Deshmukh', school: 'Fergusson Junior College', city: 'Pune', students: 112, tier: 'Active Mentor', earned: '₹1,680' },
  { rank: 4, name: 'Prakash Rao', school: 'Narayana Concept School', city: 'Hyderabad', students: 84, tier: 'Active Mentor', earned: '₹1,260' },
  { rank: 5, name: 'Meenakshi Iyer', school: 'DAV Public School', city: 'Chennai', students: 49, tier: 'Beginner Teacher', earned: '₹490' },
];

export default function LeaderboardPage() {
  const { leaderboard, refreshLeaderboard } = useUyanixStore();
  const [filter, setFilter] = useState<ClassFilter>('all');
  const [boardType, setBoardType] = useState<'students' | 'teachers'>('students');
  const [searchQuery, setSearchQuery] = useState('');

  const handleRefresh = () => {
    refreshLeaderboard();
    toast.success('Leaderboard refreshed with latest live scores! 🏆');
  };

  const filteredStudents = leaderboard.filter((student) => {
    const matchesSearch =
      student.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      student.city.toLowerCase().includes(searchQuery.toLowerCase());
    if (!matchesSearch) return false;
    if (filter === '1-5') return student.classNum >= 1 && student.classNum <= 5;
    if (filter === '6-8') return student.classNum >= 6 && student.classNum <= 8;
    if (filter === '9-12') return student.classNum >= 9 && student.classNum <= 12;
    return true;
  });

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-3xl font-bold sm:text-4xl">🏆 Live Leaderboard</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Apna rank dekho aur top par pahunchne ki tayari karo!
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="inline-flex rounded-full border border-border bg-card p-1 text-xs font-semibold">
              <button
                type="button"
                onClick={() => setBoardType('students')}
                className={`rounded-full px-3 py-1.5 transition ${
                  boardType === 'students' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'
                }`}
              >
                Students
              </button>
              <button
                type="button"
                onClick={() => setBoardType('teachers')}
                className={`rounded-full px-3 py-1.5 transition ${
                  boardType === 'teachers' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'
                }`}
              >
                Teachers
              </button>
            </div>

            <Link
              href="/sheets"
              className="inline-flex h-10 items-center gap-2 rounded-full bg-secondary px-4 text-sm font-semibold text-secondary-foreground transition hover:opacity-95"
            >
              <FileSpreadsheet className="h-4 w-4" aria-hidden="true" /> Sync Sheets
            </Link>

            <button
              type="button"
              onClick={handleRefresh}
              className="inline-flex h-10 items-center gap-2 rounded-full border border-border bg-card px-4 text-sm font-semibold transition hover:bg-accent"
            >
              <RefreshCw className="h-4 w-4" aria-hidden="true" /> Refresh
            </button>
          </div>
        </div>

        {boardType === 'students' ? (
          <>
            <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap gap-2">
                {[
                  { id: 'all', label: 'All Classes' },
                  { id: '1-5', label: 'Class 1–5' },
                  { id: '6-8', label: 'Class 6–8' },
                  { id: '9-12', label: 'Class 9–12' },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setFilter(tab.id as ClassFilter)}
                    className={`rounded-full px-4 py-1.5 text-sm font-medium transition ${
                      filter === tab.id
                        ? 'bg-primary text-primary-foreground'
                        : 'border border-border bg-card hover:bg-accent'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="relative w-full sm:w-64">
                <Search className="absolute left-3.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search student or city..."
                  className="h-9 w-full rounded-full border border-border bg-card pl-9 pr-4 text-xs outline-none focus:border-primary"
                />
              </div>
            </div>

            <div className="mt-6 overflow-hidden rounded-3xl border border-border bg-card shadow-card">
              <table className="w-full text-sm">
                <thead className="bg-accent/50 text-left text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="px-4 py-3">Rank</th>
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3">Class</th>
                    <th className="px-4 py-3">City</th>
                    <th className="px-4 py-3 text-right">Score</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredStudents.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-sm text-muted-foreground">
                        Is filter mein koi student nahi mila.
                      </td>
                    </tr>
                  ) : (
                    filteredStudents.map((s) => {
                      const rowBg =
                        s.rank === 1
                          ? 'bg-gradient-gold/40'
                          : s.rank === 2
                          ? 'bg-gradient-silver/60'
                          : s.rank === 3
                          ? 'bg-gradient-bronze/30'
                          : '';
                      const medal =
                        s.rank === 1
                          ? '🥇'
                          : s.rank === 2
                          ? '🥈'
                          : s.rank === 3
                          ? '🥉'
                          : '⭐';

                      return (
                        <tr key={s.id} className={`border-t border-border ${rowBg}`}>
                          <td className="px-4 py-4 text-base font-bold tabular-nums">
                            {medal} #{s.rank}
                          </td>
                          <td className="px-4 py-4 font-semibold">{s.name}</td>
                          <td className="px-4 py-4">Class {s.classNum}</td>
                          <td className="px-4 py-4 text-muted-foreground">{s.city}</td>
                          <td className="px-4 py-4 text-right font-bold tabular-nums">
                            {s.score}/{s.total}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="mt-6 overflow-hidden rounded-3xl border border-border bg-card shadow-card">
            <div className="flex items-center gap-2 border-b border-border bg-accent/30 px-5 py-3 text-xs font-semibold text-primary">
              <Award className="h-4 w-4" /> Top Referring Mentors &amp; Educators Across India
            </div>
            <table className="w-full text-sm">
              <thead className="bg-accent/50 text-left text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">Rank</th>
                  <th className="px-4 py-3">Teacher Name</th>
                  <th className="px-4 py-3">School / Institute</th>
                  <th className="px-4 py-3">Tier</th>
                  <th className="px-4 py-3 text-right">Verified Students</th>
                </tr>
              </thead>
              <tbody>
                {TEACHER_LEADERBOARD.map((t) => (
                  <tr key={t.rank} className="border-t border-border">
                    <td className="px-4 py-4 font-bold tabular-nums">
                      {t.rank === 1 ? '🥇 #1' : t.rank === 2 ? '🥈 #2' : t.rank === 3 ? '🥉 #3' : `⭐ #${t.rank}`}
                    </td>
                    <td className="px-4 py-4 font-semibold">{t.name}</td>
                    <td className="px-4 py-4 text-muted-foreground">
                      {t.school}, {t.city}
                    </td>
                    <td className="px-4 py-4 text-xs font-semibold text-primary">{t.tier}</td>
                    <td className="px-4 py-4 text-right font-bold tabular-nums">{t.students}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Footer />
    </div>
  );
}
