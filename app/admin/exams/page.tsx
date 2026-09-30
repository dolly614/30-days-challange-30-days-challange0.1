'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Plus, Trash2, HelpCircle } from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export default function AdminExamsManagerPage() {
  const {
    customExamQuestions,
    examAttempts,
    addCustomExamQuestion,
    deleteCustomExamQuestion,
  } = useUyanixStore();

  const [question, setQuestion] = useState('');
  const [optA, setOptA] = useState('');
  const [optB, setOptB] = useState('');
  const [optC, setOptC] = useState('');
  const [optD, setOptD] = useState('');
  const [correctIndex, setCorrectIndex] = useState(0);
  const [explanation, setExplanation] = useState('');
  const [topic, setTopic] = useState('General Aptitude');

  const handleAddQuestion = (e: React.FormEvent) => {
    e.preventDefault();
    addCustomExamQuestion({
      id: `custom-${Date.now()}`,
      question: question.trim(),
      options: [optA.trim(), optB.trim(), optC.trim(), optD.trim()],
      correctIndex,
      explanation: explanation.trim() || 'Standard NCERT explanation.',
      topic: topic.trim(),
    });
    setQuestion('');
    setOptA('');
    setOptB('');
    setOptC('');
    setOptD('');
    setExplanation('');
    toast.success('New Exam Question added to Mid & Final Exam pool! ✅');
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
        <Link
          href="/admin"
          className="inline-flex items-center gap-1.5 text-sm font-semibold text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" /> Back to Admin Dashboard
        </Link>

        <h1 className="mt-4 text-3xl font-bold sm:text-4xl">
          Manage Exams &amp; Questions
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          15-Day Mid Exam aur 30-Day Final Exam ke MCQs aur student submissions manage karein.
        </p>

        {/* Add New MCQ Form */}
        <form
          onSubmit={handleAddQuestion}
          className="mt-6 space-y-4 rounded-3xl border border-border bg-card p-6 shadow-card"
        >
          <h2 className="text-lg font-bold">Add New Exam Question</h2>

          <div className="grid gap-4 sm:grid-cols-3">
            <label className="block sm:col-span-2">
              <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                Question Text (Hinglish / English)
              </span>
              <input
                required
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Enter MCQ question..."
                className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
              />
            </label>

            <label className="block">
              <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                Topic / Subject
              </span>
              <input
                required
                value={topic}
                onChange={(e) => setTopic(e.target.value)}
                className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
              />
            </label>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <input
              required
              placeholder="Option A"
              value={optA}
              onChange={(e) => setOptA(e.target.value)}
              className="h-10 rounded-xl border border-input bg-background px-3 text-sm"
            />
            <input
              required
              placeholder="Option B"
              value={optB}
              onChange={(e) => setOptB(e.target.value)}
              className="h-10 rounded-xl border border-input bg-background px-3 text-sm"
            />
            <input
              required
              placeholder="Option C"
              value={optC}
              onChange={(e) => setOptC(e.target.value)}
              className="h-10 rounded-xl border border-input bg-background px-3 text-sm"
            />
            <input
              required
              placeholder="Option D"
              value={optD}
              onChange={(e) => setOptD(e.target.value)}
              className="h-10 rounded-xl border border-input bg-background px-3 text-sm"
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <label className="block">
              <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                Correct Option
              </span>
              <select
                value={correctIndex}
                onChange={(e) => setCorrectIndex(Number(e.target.value))}
                className="h-10 w-full rounded-xl border border-input bg-background px-3 text-sm"
              >
                <option value={0}>Option A</option>
                <option value={1}>Option B</option>
                <option value={2}>Option C</option>
                <option value={3}>Option D</option>
              </select>
            </label>

            <label className="block sm:col-span-2">
              <span className="mb-1 block text-xs font-semibold text-muted-foreground">
                Answer Explanation
              </span>
              <input
                value={explanation}
                onChange={(e) => setExplanation(e.target.value)}
                placeholder="Why is this option correct?"
                className="h-10 w-full rounded-xl border border-input bg-background px-3 text-sm"
              />
            </label>
          </div>

          <button
            type="submit"
            className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
          >
            <Plus className="h-4 w-4" /> Add Question to Pool
          </button>
        </form>

        {/* Question Bank List */}
        <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-bold">
              Active Question Pool ({customExamQuestions.length} Questions)
            </h2>
            <Link
              href="/sheets"
              className="inline-flex h-9 items-center gap-1.5 rounded-full bg-secondary px-4 text-xs font-semibold text-secondary-foreground transition hover:opacity-95"
            >
              Sync MCQs with Google Sheets
            </Link>
          </div>

          <div className="mt-4 space-y-3">
            {customExamQuestions.map((q, idx) => (
              <div
                key={q.id}
                className="flex items-start justify-between gap-4 rounded-2xl border border-border bg-background p-4 text-sm"
              >
                <div>
                  <div className="font-semibold">
                    <HelpCircle className="mr-1.5 inline h-4 w-4 text-primary" />
                    Q{idx + 1}. {q.question}
                  </div>
                  <div className="mt-1.5 text-xs text-muted-foreground">
                    Options: {q.options.join(' | ')} •{' '}
                    <b className="text-secondary">
                      Correct: {q.options[q.correctIndex]}
                    </b>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    deleteCustomExamQuestion(q.id);
                    toast.info('Question removed from pool.');
                  }}
                  className="rounded-lg border border-destructive/40 p-2 text-destructive hover:bg-destructive/10"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Exam Attempts */}
        <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
          <h2 className="text-lg font-bold">Recent Student Exam Submissions</h2>
          {examAttempts.length === 0 ? (
            <p className="mt-3 text-xs text-muted-foreground">
              Abhi is session mein koi live exam submit nahi hua hai.
            </p>
          ) : (
            <div className="mt-3 space-y-2">
              {examAttempts.map((att) => (
                <div
                  key={att.id}
                  className="flex items-center justify-between rounded-xl border border-border p-3 text-xs"
                >
                  <div>
                    <b className="uppercase text-primary">{att.type} Exam</b> •{' '}
                    {att.completedAt}
                  </div>
                  <div className="font-bold tabular-nums">
                    Score: {att.score}/{att.total} (Rank #{att.rank})
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      <Footer />
    </div>
  );
}
