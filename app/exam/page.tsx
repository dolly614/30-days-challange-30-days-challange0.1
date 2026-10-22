'use client';

import React, { useState, useEffect, Suspense, useCallback } from 'react';
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
import { RazorpayCheckoutButton } from '@/components/payment/RazorpayCheckoutButton';

interface SanitizedQuestionView {
  id: string;
  questionNumber?: number;
  questionText?: string;
  question?: string;
  options: string[];
  topic: string;
}

interface ReviewQuestionItem {
  id: string;
  questionNumber: number;
  questionText: string;
  options: [string, string, string, string];
  userChoice: number | null;
  correctOption: number;
  isCorrect: boolean;
  explanation: string;
  topic: string;
}

function ExamPortalContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const examType = searchParams.get('type') === 'final' ? 'final' : 'mid';

  const {
    currentUser,
    payForExam,
    submitExamAttempt,
    syncServerSession,
  } = useUyanixStore();

  const [isServerPaid, setIsServerPaid] = useState<boolean>(false);
  const [questions, setQuestions] = useState<SanitizedQuestionView[]>([]);
  const [stage, setStage] = useState<'gate' | 'instructions' | 'live' | 'result'>('gate');
  const [currentIdx, setCurrentIdx] = useState(0);
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const [markedReview, setMarkedReview] = useState<string[]>([]);
  const [secondsLeft, setSecondsLeft] = useState(45 * 60);
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [paying, setPaying] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverAttemptId, setServerAttemptId] = useState<string>('');
  const [serverScore, setServerScore] = useState<number | null>(null);
  const [serverCorrectCount, setServerCorrectCount] = useState<number | null>(null);
  const [serverWrongCount, setServerWrongCount] = useState<number | null>(null);
  const [serverUnansweredCount, setServerUnansweredCount] = useState<number | null>(null);
  const [serverPercentage, setServerPercentage] = useState<number | null>(null);
  const [serverRank, setServerRank] = useState<number | null>(null);
  const [serverReviewQuestions, setServerReviewQuestions] = useState<ReviewQuestionItem[]>([]);
  const [violations, setViolations] = useState(0);
  const [remainingWarnings, setRemainingWarnings] = useState(3);
  const [showProctorAlert, setShowProctorAlert] = useState(false);

  // Authenticate and verify payment entitlement from authoritative server API
  useEffect(() => {
    let active = true;
    syncServerSession().then((serverUser) => {
      if (active && !serverUser) {
        router.replace(`/login?redirect=/exam?type=${examType}`);
        return;
      }

      // Check authoritative payment and attempt status from server
      fetch(`/api/exam?type=${examType}`, { credentials: 'include' })
        .then((r) => r.json())
        .then((data) => {
          if (!active) return;
          if (data?.ok) {
            const hasPaid = data.isPaid || data?.metadata?.isPaid || serverUser?.role === 'admin';
            setIsServerPaid(hasPaid);

            if (data?.hasActiveAttempt && data?.attemptId && Array.isArray(data?.questions) && data.questions.length > 0) {
              setServerAttemptId(data.attemptId);
              setQuestions(data.questions);
              if (typeof data.remainingSeconds === 'number') {
                setSecondsLeft(data.remainingSeconds);
              }
              setStage('live');
            } else if (hasPaid) {
              setStage((curr) => (curr === 'gate' ? 'instructions' : curr));
            } else {
              setStage('gate');
            }
          }
        })
        .catch(() => {});
    });

    return () => {
      active = false;
    };
  }, [syncServerSession, router, examType]);

  // Start live exam attempt
  const handleStartExam = async () => {
    try {
      const res = await fetch('/api/exam', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ action: 'START_ATTEMPT', examType }),
      });
      const data = await res.json();
      if (!res.ok || !data?.ok) {
        if (res.status === 402) {
          toast.error('Payment verification required before starting exam.');
          setStage('gate');
        } else {
          toast.error(data?.error || 'Unable to start exam attempt.');
        }
        return;
      }

      if (data?.attemptId && Array.isArray(data?.questions)) {
        setServerAttemptId(data.attemptId);
        setQuestions(data.questions);
        if (typeof data.remainingSeconds === 'number') {
          setSecondsLeft(data.remainingSeconds);
        }
        setStage('live');
        toast.success('Exam started! 45-minute official timer is live.');
      }
    } catch {
      toast.error('Network error starting exam.');
    }
  };

  const handleSelectOption = (questionId: string, optionIdx: number) => {
    setAnswers((prev) => ({ ...prev, [questionId]: optionIdx }));

    // Real-time server autosave
    if (serverAttemptId) {
      fetch('/api/exam', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          action: 'AUTOSAVE_ANSWER',
          attemptId: serverAttemptId,
          questionId,
          selectedOption: optionIdx,
        }),
      }).catch(() => {});
    }
  };

  const handleFinalSubmit = useCallback(async (options?: { autoSubmit?: boolean }) => {
    if (isSubmitting) return;
    setIsSubmitting(true);

    try {
      const idemKey = `sub_${serverAttemptId || examType}_${Date.now()}`;
      const res = await fetch('/api/exam', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-idempotency-key': idemKey,
        },
        credentials: 'include',
        body: JSON.stringify({
          action: options?.autoSubmit ? 'AUTO_SUBMIT' : 'SUBMIT_ATTEMPT',
          attemptId: serverAttemptId,
          examType,
          answers,
          idempotencyKey: idemKey,
          autoSubmittedDueToTimer: Boolean(options?.autoSubmit),
        }),
      });

      const data = await res.json();
      if (!res.ok || !data?.result) {
        toast.error(
          data?.error || 'Exam submission verification failed. Please try again.'
        );
        setIsSubmitting(false);
        return;
      }

      const resObj = data.result;
      setServerScore(resObj.score);
      setServerPercentage(resObj.percentage);
      setServerCorrectCount(resObj.correctCount);
      setServerWrongCount(resObj.wrongCount);
      setServerUnansweredCount(resObj.unansweredCount);
      setServerRank(resObj.rank ?? 1);
      if (Array.isArray(resObj.reviewQuestions)) {
        setServerReviewQuestions(resObj.reviewQuestions);
      }

      submitExamAttempt(examType, resObj.score, 150, answers);
      setShowSubmitModal(false);
      setStage('result');

      try {
        confetti({
          particleCount: 120,
          spread: 80,
          origin: { y: 0.6 },
          colors: ['#f97316', '#7c3aed', '#10b981', '#f59e0b', '#ec4899'],
        });
        setTimeout(() => {
          confetti({
            particleCount: 60,
            angle: 60,
            spread: 55,
            origin: { x: 0 },
            colors: ['#f97316', '#7c3aed', '#10b981', '#f59e0b', '#ec4899'],
          });
          confetti({
            particleCount: 60,
            angle: 120,
            spread: 55,
            origin: { x: 1 },
            colors: ['#f97316', '#7c3aed', '#10b981', '#f59e0b', '#ec4899'],
          });
        }, 250);
      } catch {
        // ignore
      }

      if (options?.autoSubmit) {
        toast.info('⏱️ Time expired! Exam auto-submitted and evaluated successfully.');
      } else {
        toast.success('Exam submitted successfully! Aapka result ready hai 🏆');
      }
    } catch {
      toast.error(
        'Network error while submitting exam. Please check your connection and try again.'
      );
    } finally {
      setIsSubmitting(false);
    }
  }, [isSubmitting, serverAttemptId, examType, answers, submitExamAttempt]);

  // Anti-cheat proctoring listeners during live exam
  useEffect(() => {
    if (stage !== 'live') return;

    const recordViolation = async (type: string) => {
      try {
        const res = await fetch('/api/exam', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            action: 'RECORD_VIOLATION',
            attemptId: serverAttemptId,
            eventType: type,
          }),
        });
        const d = await res.json();
        if (d?.ok) {
          setViolations(d.violationCount);
          setRemainingWarnings(d.remainingWarnings);
          setShowProctorAlert(true);
          toast.warning(
            `⚠️ Security Alert: Tab switch detected! ${d.remainingWarnings} warning(s) left before auto-submission.`
          );
          if (d.autoSubmitted) {
            toast.error('Multiple security violations detected! Exam auto-submitting...');
            handleFinalSubmit({ autoSubmit: true });
          }
        }
      } catch {
        // fallback
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        recordViolation('TAB_HIDDEN');
      }
    };

    const handleBlur = () => {
      recordViolation('WINDOW_BLUR');
    };

    window.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleBlur);

    return () => {
      window.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleBlur);
    };
  }, [stage, serverAttemptId, handleFinalSubmit]);

  // Server-authoritative timer countdown
  useEffect(() => {
    if (stage !== 'live') return;
    const timer = setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          // Invoke authoritative server submission instead of jumping to client result
          handleFinalSubmit({ autoSubmit: true });
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [stage, handleFinalSubmit]);

  const handleRazorpayPay = async () => {
    setPaying(true);
    try {
      const idemKey = `ord_${examType}_${currentUser?.id || 'session'}_${Date.now()}`;
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
      setIsServerPaid(true);
      toast.success(`₹199 Payment Verified via Razorpay (${data.orderId})! Exam Unlocked 🎉`);
      setStage('instructions');
    } catch {
      toast.error('Unable to reach payment verification server. Please try again.');
    } finally {
      setPaying(false);
    }
  };

  const mins = String(Math.floor(secondsLeft / 60)).padStart(2, '0');
  const secs = String(secondsLeft % 60).padStart(2, '0');

  const currentQuestion = questions[currentIdx] || questions[0];
  const currentQuestionTitle = currentQuestion?.questionText || currentQuestion?.question || '';

  const scaledTotalScore = serverScore ?? 0;
  const correctCount = serverCorrectCount ?? 0;

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
              <span className="font-semibold">{currentUser?.name || 'Student'} (Class {currentUser?.classNum || 10})</span>
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

          <RazorpayCheckoutButton
            amount={19900}
            currency="INR"
            name="Uyanix 30 Days Challenge"
            description={`${examType === 'final' ? '30-Day Grand Final' : '15-Day Mid Challenge'} Exam Registration Fee`}
            prefill={{
              name: currentUser?.name || 'Student',
              email: currentUser?.email || 'student@example.com',
              contact: currentUser?.phone || '9876543210',
            }}
            examType={examType}
            buttonText="Pay ₹199 via Razorpay & Start Exam →"
            className="mt-6 w-full h-12 text-sm shadow-soft transition hover:scale-[1.01]"
            onSuccess={(result) => {
              payForExam(examType, result.order_id);
              setIsServerPaid(true);
              setStage('instructions');
              confetti({ particleCount: 75, spread: 60, origin: { y: 0.6 } });
            }}
            onFailure={(err) => {
              console.log('Payment modal dismissed or failed:', err);
            }}
          />

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
              Negative marking <b>nahi hai</b>. Har sahi uttar ka 1 mark (total scaled to 150).
            </li>
            <li className="flex items-start gap-2">
              <span className="font-bold text-primary">3.</span>
              Tab switch ya minimize karne par proctoring warning milegi (max 3 allowed).
            </li>
            <li className="flex items-start gap-2">
              <span className="font-bold text-primary">4.</span>
              Aap kisi bhi question par jump kar sakte hain ya review ke liye flag kar sakte hain.
            </li>
          </ul>

          <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-6">
            <div className="text-xs text-muted-foreground">
              Candidate: <b>{currentUser?.name || 'Student'}</b> (Class {currentUser?.classNum || 10})
            </div>
            <button
              type="button"
              onClick={handleStartExam}
              className="inline-flex h-12 items-center gap-2 rounded-full bg-gradient-hero px-8 text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.02]"
            >
              Start Official Exam Now →
            </button>
          </div>
        </div>
      )}

      {/* STAGE 3: LIVE EXAM INTERFACE */}
      {stage === 'live' && currentQuestion && (
        <div>
          {/* Top Timer & Header Bar */}
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-3xl border border-border bg-card p-4 shadow-card sm:p-5">
            <div>
              <span className="text-xs font-semibold text-muted-foreground">
                Candidate: {currentUser?.name || 'Student'} (Class {currentUser?.classNum || 10})
              </span>
              <h2 className="text-lg font-bold">
                {examType === 'final' ? '30-Day Grand Final Exam' : '15-Day Mid Challenge'}
              </h2>
            </div>

            <div className="flex items-center gap-3">
              {violations > 0 && (
                <div className="inline-flex items-center gap-1.5 rounded-full bg-destructive/15 px-3 py-1.5 text-xs font-bold text-destructive">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  Warnings: {violations}/3
                </div>
              )}

              <div
                className={`flex items-center gap-2 rounded-full px-4 py-2 font-mono text-base font-bold tabular-nums shadow-soft transition-all duration-300 ${
                  secondsLeft <= 300
                    ? 'bg-destructive text-destructive-foreground animate-pulse-glow ring-2 ring-destructive shadow-[0_0_15px_rgba(239,68,68,0.6)]'
                    : 'bg-primary text-primary-foreground'
                }`}
              >
                <Clock className={`h-4 w-4 ${secondsLeft <= 300 ? 'animate-bounce' : ''}`} />
                <span>
                  {mins}:{secs}
                </span>
              </div>

              <button
                type="button"
                onClick={() => setShowSubmitModal(true)}
                className="inline-flex h-10 items-center rounded-full bg-secondary px-5 text-xs font-semibold text-secondary-foreground shadow-soft transition hover:opacity-95"
              >
                Submit Exam
              </button>
            </div>
          </div>

          {/* Main Exam Workspace */}
          <div className="mt-6 grid gap-6 lg:grid-cols-4">
            {/* Question Panel */}
            <div className="rounded-3xl border border-border bg-card p-6 shadow-card lg:col-span-3 sm:p-8">
              <div className="flex items-center justify-between border-b border-border pb-4">
                <span className="text-xs font-bold uppercase tracking-wider text-primary">
                  Question {currentIdx + 1} of {questions.length} • {currentQuestion.topic}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setMarkedReview((prev) =>
                      prev.includes(currentQuestion.id)
                        ? prev.filter((id) => id !== currentQuestion.id)
                        : [...prev, currentQuestion.id]
                    );
                  }}
                  className={`inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-semibold transition ${
                    markedReview.includes(currentQuestion.id)
                      ? 'bg-saffron text-white'
                      : 'border border-border text-muted-foreground hover:bg-accent'
                  }`}
                >
                  <Flag className="h-3 w-3" />
                  {markedReview.includes(currentQuestion.id) ? 'Marked for Review' : 'Mark for Review'}
                </button>
              </div>

              <div className="mt-6 text-base font-semibold leading-relaxed sm:text-lg">
                Q{currentIdx + 1}. {currentQuestionTitle}
              </div>

              {/* Options */}
              <div className="mt-6 space-y-3">
                {currentQuestion.options.map((opt, optIdx) => {
                  const isSelected = answers[currentQuestion.id] === optIdx;
                  return (
                    <button
                      key={opt}
                      type="button"
                      onClick={() => handleSelectOption(currentQuestion.id, optIdx)}
                      className={`flex w-full items-center justify-between rounded-2xl border p-4 text-left text-sm transition ${
                        isSelected
                          ? 'border-primary bg-primary/10 font-semibold text-primary ring-2 ring-primary/30'
                          : 'border-border bg-background hover:bg-accent/40'
                      }`}
                    >
                      <span className="flex items-center gap-3">
                        <span
                          className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-bold ${
                            isSelected
                              ? 'bg-primary text-primary-foreground'
                              : 'bg-muted text-muted-foreground'
                          }`}
                        >
                          {String.fromCharCode(65 + optIdx)}
                        </span>
                        {opt}
                      </span>
                      {isSelected && <CheckCircle2 className="h-5 w-5 text-primary" />}
                    </button>
                  );
                })}
              </div>

              {/* Navigation Controls */}
              <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-6">
                <button
                  type="button"
                  disabled={currentIdx === 0}
                  onClick={() => setCurrentIdx((prev) => Math.max(0, prev - 1))}
                  className="h-10 rounded-full border border-border px-5 text-xs font-semibold hover:bg-accent disabled:opacity-40"
                >
                  ← Previous
                </button>

                <div className="text-xs text-muted-foreground">
                  Attempted: <b>{Object.keys(answers).length}</b> / {questions.length}
                </div>

                {currentIdx < questions.length - 1 ? (
                  <button
                    type="button"
                    onClick={() => setCurrentIdx((prev) => Math.min(questions.length - 1, prev + 1))}
                    className="h-10 rounded-full bg-primary px-6 text-xs font-semibold text-primary-foreground shadow-soft hover:opacity-95"
                  >
                    Next Question →
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => setShowSubmitModal(true)}
                    className="h-10 rounded-full bg-secondary px-6 text-xs font-semibold text-secondary-foreground shadow-soft hover:opacity-95"
                  >
                    Review &amp; Submit →
                  </button>
                )}
              </div>
            </div>

            {/* Question Navigator Sidebar */}
            <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
              <h3 className="text-sm font-bold">Question Palette</h3>
              <p className="mt-1 text-xs text-muted-foreground">Click number to jump directly</p>

              <div className="mt-4 grid grid-cols-5 gap-2">
                {questions.map((q, idx) => {
                  const isAnswered = answers[q.id] !== undefined;
                  const isMarked = markedReview.includes(q.id);
                  const isCurrent = currentIdx === idx;

                  let style = 'bg-muted text-muted-foreground';
                  if (isCurrent) {
                    style = 'ring-2 ring-primary font-bold text-foreground bg-primary/20';
                  } else if (isMarked) {
                    style = 'bg-saffron text-white font-bold';
                  } else if (isAnswered) {
                    style = 'bg-secondary text-secondary-foreground font-semibold';
                  }

                  return (
                    <button
                      key={q.id}
                      type="button"
                      onClick={() => setCurrentIdx(idx)}
                      className={`flex aspect-square items-center justify-center rounded-xl text-xs transition-all duration-150 hover:scale-115 active:scale-90 ${style}`}
                    >
                      {idx + 1}
                    </button>
                  );
                })}
              </div>

              <div className="mt-5 space-y-2 border-t border-border pt-4 text-xs text-muted-foreground">
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded bg-secondary" /> Answered ({Object.keys(answers).length})
                </div>
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded bg-saffron" /> Marked for Review ({markedReview.length})
                </div>
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded bg-muted" /> Unattempted ({questions.length - Object.keys(answers).length})
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* STAGE 4: RESULT SUMMARY & CERTIFICATE */}
      {stage === 'result' && (
        <div className="mx-auto max-w-3xl space-y-8 animate-fade-up">
          <div className="rounded-3xl bg-gradient-hero p-8 text-center text-primary-foreground shadow-soft sm:p-10">
            <Trophy className="mx-auto h-16 w-16 text-saffron animate-trophy-glow" />
            <span className="mt-4 inline-flex items-center gap-1.5 rounded-full bg-white/20 px-3 py-1 text-xs font-semibold animate-pop-in">
              <CheckCircle2 className="h-3.5 w-3.5" /> Official Exam Evaluated &amp; Certified
            </span>

            <h1 className="mt-3 text-3xl font-extrabold sm:text-4xl animate-pop-in">
              Congratulations, {currentUser?.name || 'Student'}! 🎉
            </h1>
            <p className="mt-2 text-sm opacity-90">
              Aapka official {examType === 'final' ? '30-Day Grand Finale Exam' : '15-Day Mid Challenge Exam'} safalta-poorvak evaluate ho gaya hai.
            </p>

            <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="card-interactive animate-pop-in rounded-2xl bg-card p-4 text-foreground shadow-card">
                <div className="text-xs text-muted-foreground">Marks Scored</div>
                <div className="mt-1 text-2xl font-extrabold text-primary tabular-nums">
                  {scaledTotalScore} / 150
                </div>
              </div>
              <div className="card-interactive animate-pop-in rounded-2xl bg-card p-4 text-foreground shadow-card">
                <div className="text-xs text-muted-foreground">Correct MCQs</div>
                <div className="mt-1 text-2xl font-extrabold text-secondary tabular-nums">
                  {correctCount}
                </div>
              </div>
              <div className="card-interactive animate-pop-in rounded-2xl bg-card p-4 text-foreground shadow-card">
                <div className="text-xs text-muted-foreground">Percentage</div>
                <div className="mt-1 text-2xl font-extrabold text-foreground tabular-nums">
                  {serverPercentage ?? Math.round((scaledTotalScore / 150) * 100)}%
                </div>
              </div>
              <div className="card-interactive animate-pop-in rounded-2xl bg-card p-4 text-foreground shadow-card">
                <div className="text-xs text-muted-foreground">All-India Rank</div>
                <div className="mt-1 text-2xl font-extrabold text-saffron tabular-nums">
                  #{serverRank ?? 1}
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
          {serverReviewQuestions.length > 0 && (
            <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
              <h2 className="text-xl font-bold">Answer Key &amp; Detailed Explanations</h2>
              <div className="mt-4 space-y-4">
                {serverReviewQuestions.map((q) => {
                  const picked = q.userChoice;
                  const isRight = q.isCorrect;
                  return (
                    <div
                      key={q.id}
                      className="rounded-2xl border border-border bg-background p-4 text-sm"
                    >
                      <div className="flex items-start justify-between gap-2 font-semibold">
                        <span>
                          Q{q.questionNumber}. {q.questionText}
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
                          {picked !== null && picked !== undefined ? q.options[picked] : 'Not Attempted'}
                        </b>{' '}
                        · Correct Answer:{' '}
                        <b className="text-secondary">{q.options[q.correctOption]}</b>
                      </div>
                      <div className="mt-2 rounded-xl bg-muted/50 p-2.5 text-xs text-muted-foreground">
                        💡 {q.explanation}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
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
                disabled={isSubmitting}
                onClick={() => handleFinalSubmit({ autoSubmit: false })}
                className="h-10 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft disabled:opacity-50"
              >
                {isSubmitting ? 'Evaluating Exam...' : 'Yes, Submit Final Answers'}
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
