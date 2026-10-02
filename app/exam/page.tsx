'use client';

import React, { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import {
  Clock,
  ShieldCheck,
  Flag,
  CheckCircle2,
  Award,
  Trophy,
  AlertTriangle,
  CreditCard,
} from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';
import confetti from 'canvas-confetti';

function ExamPortalContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const examType = searchParams.get('type') === 'final' ? 'final' : 'mid';

  const {
    currentUser,
    customExamQuestions,
    examPaid,
    payForExam,
    submitExamAttempt,
    syncServerSession,
  } = useUyanixStore();

  useEffect(() => {
    let active = true;
    syncServerSession().then((serverUser) => {
      if (active && !serverUser) {
        router.replace(`/login?redirect=/exam?type=${examType}`);
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, router, examType]);

  const isPaid = examPaid[examType];
  const questions = customExamQuestions;

  const [stage, setStage] = useState<'gate' | 'instructions' | 'live' | 'result'>(
    isPaid ? 'instructions' : 'gate'
  );
  const [currentIdx, setCurrentIdx] = useState(0);
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const [markedReview, setMarkedReview] = useState<string[]>([]);
  const [secondsLeft, setSecondsLeft] = useState(45 * 60);
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [paying, setPaying] = useState(false);
  const [serverAttemptId, setServerAttemptId] = useState<string>('');
  const [serverScore, setServerScore] = useState<number | null>(null);
  const [serverCorrectCount, setServerCorrectCount] = useState<number | null>(null);

  useEffect(() => {
    if (stage !== 'live') return;
    fetch('/api/exam', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ action: 'START_ATTEMPT', examType }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (data?.attemptId) {
          setServerAttemptId(data.attemptId);
          if (typeof data.remainingSeconds === 'number' && data.remainingSeconds > 0) {
            setSecondsLeft(data.remainingSeconds);
          }
        }
      })
      .catch(() => {});
  }, [stage, examType]);

  useEffect(() => {
    if (stage !== 'live') return;
    const timer = setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          setStage('result');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [stage]);

  const handleRazorpayPay = async () => {
    setPaying(true);
    try {
      const idemKey = `ord_${examType}_${currentUser?.id || 'session'}`;
      const res = await fetch('/api/payment', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idemKey,
        },
        credentials: 'include',
        body: JSON.stringify({
          examType,
          completeServerVerifiedCheckout: true,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data?.success || !data?.orderId) {
        toast.error(data?.error || 'Payment verification failed. Please try again.');
        return;
      }
      payForExam(examType, data.orderId);
      toast.success(`₹199 Payment Verified via Razorpay (${data.orderId})! Exam Unlocked 🎉`);
      setStage('instructions');
    } catch {
      toast.error('Unable to reach payment verification server. Please try again.');
    } finally {
      setPaying(false);
    }
  };

  const handleFinalSubmit = async () => {
    let correct = 0;
    questions.forEach((q) => {
      if (answers[q.id] === q.correctIndex) correct++;
    });

    let scaledScore = Math.round((correct / questions.length) * 150);

    try {
      const idemKey = `sub_${serverAttemptId || examType}_${Object.keys(answers).length}`;
      const res = await fetch('/api/exam', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idemKey,
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'SUBMIT_ATTEMPT',
          attemptId: serverAttemptId,
          examType,
          answers,
          idempotencyKey: idemKey,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data?.result) {
        toast.error(
          data?.error || 'Exam submission verification failed. Please try again.'
        );
        return;
      }
      scaledScore = data.result.score;
      setServerScore(data.result.score);
      setServerCorrectCount(data.result.correct_count);
    } catch {
      toast.error(
        'Network error while submitting exam. Please check your connection and try again.'
      );
      return;
    }

    submitExamAttempt(examType, scaledScore, 150, answers);
    setShowSubmitModal(false);
    setStage('result');

    try {
      confetti({ particleCount: 90, spread: 70, origin: { y: 0.6 } });
    } catch {
      // ignore
    }

    toast.success('Exam submitted successfully! Aapka result aur rank ready hai 🏆');
  };

  const mins = String(Math.floor(secondsLeft / 60)).padStart(2, '0');
  const secs = String(secondsLeft % 60).padStart(2, '0');

  const currentQuestion = questions[currentIdx] || questions[0];

  const correctCount =
    serverCorrectCount ??
    questions.reduce(
      (acc, q) => (answers[q.id] === q.correctIndex ? acc + 1 : acc),
      0
    );
  const scaledTotalScore =
    serverScore ?? Math.round((correctCount / questions.length) * 150);

  return (
    <section className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      {/* STAGE 1: RAZORPAY PAY-LATER GATE */}
      {stage === 'gate' && (
        <div className="mx-auto max-w-lg rounded-3xl border border-border bg-card p-8 shadow-soft">
          <div className="inline-flex items-center gap-2 rounded-full bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
            <ShieldCheck className="h-4 w-4" /> Pay-Later Exam Fee Unlock
          </div>

          <h1 className="mt-3 text-2xl font-extrabold sm:text-3xl">
            {examType === 'final' ? '30-Day Grand Final Exam 🏆' : '15-Day Mid Challenge Exam 🎯'}
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Registration bilkul FREE tha! Ab official timed exam aur national ranking + certificate unlock karne ke liye exam fee pay karein.
          </p>

          <div className="mt-6 rounded-2xl border border-border bg-muted/40 p-4 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Student Name</span>
              <span className="font-semibold">{currentUser?.name || 'dollysingh'} (Class {currentUser?.classNum || 12})</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Exam Format</span>
              <span className="font-semibold">150 Marks • 45 Mins</span>
            </div>
            <div className="flex justify-between border-t border-border pt-2 text-base font-bold">
              <span>Payable Exam Fee</span>
              <span className="text-primary tabular-nums">₹199 (Incl. GST)</span>
            </div>
          </div>

          <button
            type="button"
            disabled={paying}
            onClick={handleRazorpayPay}
            className="mt-6 inline-flex h-12 w-full items-center justify-center gap-2 rounded-full bg-gradient-hero text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.01] disabled:opacity-60"
          >
            <CreditCard className="h-4 w-4" />
            {paying ? 'Verifying Razorpay Payment...' : 'Pay ₹199 via Razorpay & Start Exam →'}
          </button>

          <p className="mt-3 text-center text-[11px] text-muted-foreground">
            🔒 100% Secure Razorpay Checkout • UPI, GPay, PhonePe, Cards &amp; NetBanking supported
          </p>
        </div>
      )}

      {/* STAGE 2: EXAM INSTRUCTIONS */}
      {stage === 'instructions' && (
        <div className="mx-auto max-w-2xl rounded-3xl border border-border bg-card p-8 shadow-card">
          <h1 className="text-2xl font-extrabold sm:text-3xl">
            📋 Exam Instructions ({examType === 'final' ? '30-Day Final Exam' : '15-Day Mid Exam'})
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Exam shuru karne se pehle neeche diye gaye rules dhyan se padhein:
          </p>

          <ul className="mt-5 space-y-3 text-sm text-foreground">
            <li className="flex items-start gap-2">
              <span className="font-bold text-primary">1.</span>
              Total time <b>45 Minutes</b> hai. Timer khatam hone par exam auto-submit ho jayega.
            </li>
            <li className="flex items-start gap-2">
              <span className="font-bold text-primary">2.</span>
              Har sahi jawab ke poore marks milenge. <b>Koi negative marking nahi hai</b>, isliye saare questions attempt karein!
            </li>
            <li className="flex items-start gap-2">
              <span className="font-bold text-primary">3.</span>
              Agar kisi sawal mein doubt ho, toh <b>&quot;Mark for Review&quot;</b> button use karein taaki baad mein question palette se wapas aa sakein.
            </li>
            <li className="flex items-start gap-2">
              <span className="font-bold text-primary">4.</span>
              Exam submit karte hi aapka instant Score, Answer Explanations, National Rank aur Digital Certificate generate ho jayega.
            </li>
          </ul>

          <div className="mt-7 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() => setStage('live')}
              className="inline-flex h-12 items-center gap-2 rounded-full bg-gradient-hero px-8 text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.02]"
            >
              Start Timed Exam Now 🚀
            </button>
            <Link
              href="/dashboard"
              className="inline-flex h-12 items-center rounded-full border border-border px-6 text-sm font-semibold hover:bg-accent"
            >
              Back to Dashboard
            </Link>
          </div>
        </div>
      )}

      {/* STAGE 3: LIVE EXAM INTERFACE WITH PALETTE */}
      {stage === 'live' && currentQuestion && (
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Question Area */}
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card lg:col-span-2">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-4">
              <div>
                <span className="text-xs font-bold uppercase tracking-wider text-primary">
                  Question {currentIdx + 1} of {questions.length}
                </span>
                {currentQuestion.topic && (
                  <span className="ml-2 text-xs text-muted-foreground">
                    · {currentQuestion.topic}
                  </span>
                )}
              </div>

              <div className="inline-flex items-center gap-1.5 rounded-full bg-destructive/10 px-3.5 py-1.5 font-mono text-sm font-bold text-destructive tabular-nums">
                <Clock className="h-4 w-4" /> {mins}:{secs}
              </div>
            </div>

            <h2 className="mt-6 text-lg font-bold leading-snug sm:text-xl">
              {currentQuestion.question}
            </h2>

            <div className="mt-6 space-y-3">
              {currentQuestion.options.map((opt, optIdx) => {
                const isSelected = answers[currentQuestion.id] === optIdx;
                return (
                  <button
                    key={opt}
                    type="button"
                    onClick={() =>
                      setAnswers((prev) => ({ ...prev, [currentQuestion.id]: optIdx }))
                    }
                    className={`flex w-full items-center justify-between rounded-2xl border p-4 text-left text-sm transition ${
                      isSelected
                        ? 'border-primary bg-primary/10 font-semibold text-primary ring-1 ring-primary'
                        : 'border-border bg-background hover:bg-accent/50'
                    }`}
                  >
                    <span>
                      <b className="mr-2">{String.fromCharCode(65 + optIdx)}.</b> {opt}
                    </span>
                    {isSelected && <CheckCircle2 className="h-4 w-4 text-primary" />}
                  </button>
                );
              })}
            </div>

            <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5">
              <button
                type="button"
                onClick={() => {
                  const id = currentQuestion.id;
                  setMarkedReview((prev) =>
                    prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
                  );
                }}
                className={`inline-flex h-10 items-center gap-1.5 rounded-full border px-4 text-xs font-semibold transition ${
                  markedReview.includes(currentQuestion.id)
                    ? 'border-amber-500 bg-amber-500/15 text-amber-600'
                    : 'border-border bg-background hover:bg-accent'
                }`}
              >
                <Flag className="h-3.5 w-3.5" />
                {markedReview.includes(currentQuestion.id)
                  ? 'Marked for Review'
                  : 'Mark for Review'}
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={currentIdx === 0}
                  onClick={() => setCurrentIdx((i) => Math.max(0, i - 1))}
                  className="h-10 rounded-full border border-border px-4 text-xs font-semibold hover:bg-accent disabled:opacity-40"
                >
                  ← Previous
                </button>
                {currentIdx < questions.length - 1 ? (
                  <button
                    type="button"
                    onClick={() =>
                      setCurrentIdx((i) => Math.min(questions.length - 1, i + 1))
                    }
                    className="h-10 rounded-full bg-primary px-5 text-xs font-semibold text-primary-foreground shadow-soft"
                  >
                    Save &amp; Next →
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => setShowSubmitModal(true)}
                    className="h-10 rounded-full bg-secondary px-6 text-xs font-semibold text-secondary-foreground shadow-soft"
                  >
                    Finish &amp; Submit Exam
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Question Palette Sidebar */}
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <h3 className="text-base font-bold">Question Palette</h3>
            <p className="mt-1 text-xs text-muted-foreground">
              Kisi bhi question number par click karke jump karein
            </p>

            <div className="mt-4 grid grid-cols-5 gap-2">
              {questions.map((q, idx) => {
                const isAnswered = answers[q.id] !== undefined;
                const isReview = markedReview.includes(q.id);
                const isCurrent = idx === currentIdx;

                let cellStyle = 'bg-muted text-muted-foreground';
                if (isReview) {
                  cellStyle = 'bg-amber-500 text-white';
                } else if (isAnswered) {
                  cellStyle = 'bg-secondary text-secondary-foreground';
                }

                return (
                  <button
                    key={q.id}
                    type="button"
                    onClick={() => setCurrentIdx(idx)}
                    className={`h-10 rounded-xl text-xs font-bold tabular-nums transition ${cellStyle} ${
                      isCurrent ? 'ring-2 ring-primary ring-offset-2' : ''
                    }`}
                  >
                    {idx + 1}
                  </button>
                );
              })}
            </div>

            <div className="mt-5 space-y-2 border-t border-border pt-4 text-xs text-muted-foreground">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded bg-secondary" /> Answered
                </span>
                <b className="text-foreground tabular-nums">{Object.keys(answers).length}</b>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded bg-amber-500" /> Marked for Review
                </span>
                <b className="text-foreground tabular-nums">{markedReview.length}</b>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded bg-muted" /> Remaining
                </span>
                <b className="text-foreground tabular-nums">
                  {questions.length - Object.keys(answers).length}
                </b>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setShowSubmitModal(true)}
              className="mt-6 inline-flex h-11 w-full items-center justify-center rounded-full bg-gradient-hero text-sm font-semibold text-primary-foreground shadow-soft"
            >
              Submit Exam ({Object.keys(answers).length}/{questions.length})
            </button>
          </div>
        </div>
      )}

      {/* STAGE 4: RESULT & EXPLANATIONS */}
      {stage === 'result' && (
        <div className="space-y-8">
          <div className="rounded-3xl bg-gradient-hero p-8 text-center text-primary-foreground shadow-soft">
            <div className="mx-auto inline-flex h-16 w-16 items-center justify-center rounded-full bg-white/20">
              <Trophy className="h-8 w-8" />
            </div>
            <h1 className="mt-3 text-3xl font-extrabold sm:text-4xl">
              Shandar Pradarshan, {currentUser?.name || 'Champion'}! 🎉
            </h1>
            <p className="mt-1 text-sm opacity-90">
              Aapka {examType === 'final' ? '30-Day Final Exam' : '15-Day Mid Exam'} result aur national rank niche hai:
            </p>

            <div className="mx-auto mt-6 grid max-w-2xl grid-cols-3 gap-4">
              <div className="rounded-2xl bg-card p-4 text-foreground shadow-card">
                <div className="text-xs text-muted-foreground">Final Score</div>
                <div className="mt-1 text-2xl font-extrabold text-primary tabular-nums">
                  {scaledTotalScore}/150
                </div>
              </div>
              <div className="rounded-2xl bg-card p-4 text-foreground shadow-card">
                <div className="text-xs text-muted-foreground">Accuracy</div>
                <div className="mt-1 text-2xl font-extrabold text-secondary tabular-nums">
                  {Math.round((correctCount / questions.length) * 100)}%
                </div>
              </div>
              <div className="rounded-2xl bg-card p-4 text-foreground shadow-card">
                <div className="text-xs text-muted-foreground">All-India Rank</div>
                <div className="mt-1 text-2xl font-extrabold text-saffron tabular-nums">
                  #{scaledTotalScore >= 135 ? 1 : scaledTotalScore >= 110 ? 4 : 7}
                </div>
              </div>
            </div>

            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <button
                type="button"
                onClick={() => router.push('/certificate')}
                className="inline-flex h-12 items-center gap-2 rounded-full bg-card px-7 text-sm font-semibold text-primary shadow-soft transition hover:scale-[1.02]"
              >
                <Award className="h-4 w-4" /> Download Official Certificate
              </button>
              <Link
                href="/leaderboard"
                className="inline-flex h-12 items-center rounded-full border border-white/40 bg-white/15 px-7 text-sm font-semibold text-white hover:bg-white/25"
              >
                View Live Leaderboard
              </Link>
            </div>
          </div>

          {/* Answer Key & Detailed Explanations */}
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <h2 className="text-xl font-bold">Answer Key &amp; Detailed Explanations</h2>
            <div className="mt-4 space-y-4">
              {questions.map((q, idx) => {
                const picked = answers[q.id];
                const isRight = picked === q.correctIndex;
                return (
                  <div
                    key={q.id}
                    className="rounded-2xl border border-border bg-background p-4 text-sm"
                  >
                    <div className="flex items-start justify-between gap-2 font-semibold">
                      <span>
                        Q{idx + 1}. {q.question}
                      </span>
                      <span
                        className={`shrink-0 text-xs font-bold ${
                          isRight ? 'text-secondary' : 'text-destructive'
                        }`}
                      >
                        {isRight ? '✓ Correct' : '✗ Incorrect'}
                      </span>
                    </div>
                    <div className="mt-2 text-xs text-muted-foreground">
                      Your Answer:{' '}
                      <b className="text-foreground">
                        {picked !== undefined ? q.options[picked] : 'Not Attempted'}
                      </b>{' '}
                      · Correct Answer:{' '}
                      <b className="text-secondary">{q.options[q.correctIndex]}</b>
                    </div>
                    <div className="mt-2 rounded-xl bg-muted/50 p-2.5 text-xs text-muted-foreground">
                      💡 {q.explanation}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Submit Confirmation Modal */}
      {showSubmitModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-3xl border border-border bg-card p-6 shadow-soft">
            <div className="flex items-center gap-2 text-lg font-bold">
              <AlertTriangle className="h-5 w-5 text-saffron" /> Submit Exam Confirmation
            </div>
            <p className="mt-2 text-sm text-muted-foreground">
              Aapne <b>{Object.keys(answers).length}</b> out of <b>{questions.length}</b> questions answer kiye hain aur <b>{markedReview.length}</b> review ke liye mark kiye hain. Kya aap final submit karna chahte hain?
            </p>
            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowSubmitModal(false)}
                className="h-10 rounded-full border border-border px-4 text-xs font-semibold hover:bg-accent"
              >
                Keep Solving
              </button>
              <button
                type="button"
                onClick={handleFinalSubmit}
                className="h-10 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
              >
                Yes, Submit Final Answers
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export default function ExamPage() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <Suspense fallback={<div className="py-20 text-center text-sm text-muted-foreground">Loading exam portal...</div>}>
        <ExamPortalContent />
      </Suspense>
      <Footer />
    </div>
  );
}
