'use client';

import React, { useState, useEffect, use } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  XCircle,
  Download,
  Sparkles,
  Flame,
  HelpCircle,
} from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { useUyanixStore } from '@/lib/store';
import { generateChapterForClassAndDay } from '@/lib/curriculum';
import { toast } from 'sonner';
import confetti from 'canvas-confetti';

interface StudentQuestionView {
  id: string;
  question: string;
  options: [string, string, string, string];
  topic?: string;
}

interface QuestionReviewResult {
  questionId: string;
  userChoice: number;
  correctIndex: number;
  isCorrect: boolean;
  explanation: string;
}

export default function DailyChapterPage({
  params,
}: {
  params: Promise<{ day: string }>;
}) {
  const resolvedParams = use(params);
  const router = useRouter();
  const isValidDayParam = /^(?:[1-9]|[12]\d|30)$/.test(
    String(resolvedParams.day || '').trim()
  );
  const dayNum = Math.max(1, Math.min(30, Number(resolvedParams.day) || 1));

  const {
    currentUser,
    savedChapters,
    completedDays,
    dailyScores,
    completeDay,
    syncServerSession,
    syncStudentProgress,
  } = useUyanixStore();

  const classNum = currentUser?.classNum || 12;

  // Fallback base curriculum structure for offline or instantaneous initial display
  const baseChapter = generateChapterForClassAndDay(classNum, dayNum);
  const override = savedChapters[`${classNum}-${dayNum}`];

  const [chapterTitle, setChapterTitle] = useState(override?.title || baseChapter.title);
  const [chapterContent, setChapterContent] = useState(override?.content || baseChapter.content);
  const [chapterSummary, setChapterSummary] = useState(baseChapter.summary);
  const [keyTakeaways, setKeyTakeaways] = useState<string[]>(baseChapter.keyTakeaways);
  const [sanitizedQuestions, setSanitizedQuestions] = useState<StudentQuestionView[]>(
    baseChapter.mcqs.map((m) => ({
      id: m.id,
      question: m.question,
      options: [m.options[0], m.options[1], m.options[2], m.options[3]],
      topic: m.topic,
    }))
  );

  const [selectedAnswers, setSelectedAnswers] = useState<Record<number, number>>({});
  const [submitted, setSubmitted] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [serverScore, setServerScore] = useState<number | null>(null);
  const [reviewResults, setReviewResults] = useState<Record<number, QuestionReviewResult>>({});

  const isAlreadyDone = completedDays.includes(dayNum);
  const prevBestScore = dailyScores[dayNum];

  useEffect(() => {
    let active = true;
    if (!isValidDayParam) {
      router.replace('/dashboard');
      return () => {
        active = false;
      };
    }
    syncServerSession().then((serverUser) => {
      if (active && !serverUser) {
        router.replace(`/login?redirect=/daily/${dayNum}`);
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, router, dayNum, isValidDayParam]);

  // Load authoritative sanitized chapter from server API
  useEffect(() => {
    let active = true;
    fetch(`/api/daily/${dayNum}`, { credentials: 'include' })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to fetch chapter');
        return res.json();
      })
      .then((data) => {
        if (active && data?.ok && data?.chapter) {
          const ch = data.chapter;
          setChapterTitle(ch.title || baseChapter.title);
          setChapterContent(ch.content || baseChapter.content);
          setChapterSummary(ch.summary || baseChapter.summary);
          if (Array.isArray(ch.keyTakeaways) && ch.keyTakeaways.length > 0) {
            setKeyTakeaways(ch.keyTakeaways);
          }
          if (Array.isArray(ch.mcqs) && ch.mcqs.length > 0) {
            setSanitizedQuestions(ch.mcqs);
          }
        }
      })
      .catch(() => {
        // Safe fallback already mounted
      });

    return () => {
      active = false;
    };
  }, [dayNum, baseChapter.title, baseChapter.content, baseChapter.summary]);

  const handleSelectOption = (qIdx: number, optIdx: number) => {
    if (submitted) return;
    setSelectedAnswers((prev) => ({ ...prev, [qIdx]: optIdx }));
  };

  const handleSubmitQuiz = async (e: React.FormEvent) => {
    e.preventDefault();
    if (Object.keys(selectedAnswers).length < sanitizedQuestions.length) {
      toast.error('Saare 5 MCQs attempt karein submit karne se pehle!');
      return;
    }

    setIsSubmitting(true);
    const answersArray = [
      selectedAnswers[0] ?? 0,
      selectedAnswers[1] ?? 0,
      selectedAnswers[2] ?? 0,
      selectedAnswers[3] ?? 0,
      selectedAnswers[4] ?? 0,
    ];

    try {
      const idemKey = `daily_sub_${dayNum}_${currentUser?.id || 'anon'}_${Date.now()}`;
      const res = await fetch(`/api/daily/${dayNum}/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-idempotency-key': idemKey,
        },
        credentials: 'include',
        body: JSON.stringify({
          answers: answersArray,
          idempotencyKey: idemKey,
        }),
      });

      const data = await res.json();

      if (res.status === 409 || data?.status === 'ALREADY_COMPLETED') {
        const recordedScore = data?.originalScore ?? prevBestScore ?? 5;
        setSubmitted(true);
        setServerScore(recordedScore);
        completeDay(dayNum, recordedScore);
        toast.info(`Day ${dayNum} pehle hi complete ho chuka hai! Score: ${recordedScore}/5`);
        return;
      }

      if (!res.ok || !data?.ok) {
        toast.error(data?.error || 'Quiz submission failed. Please try again.');
        return;
      }

      // Server-calculated score
      const calcScore = data.score ?? 0;
      setSubmitted(true);
      setServerScore(calcScore);
      completeDay(dayNum, calcScore);

      // Store server evaluation results for review & explanations
      if (Array.isArray(data.results)) {
        const revMap: Record<number, QuestionReviewResult> = {};
        data.results.forEach((r: QuestionReviewResult, i: number) => {
          revMap[i] = r;
        });
        setReviewResults(revMap);
      }

      // Synchronize student progress from database
      syncStudentProgress();

      try {
        confetti({
          particleCount: 110,
          spread: 80,
          origin: { y: 0.6 },
          colors: ['#7c3aed', '#f97316', '#10b981', '#ec4899', '#fde047'],
        });
      } catch {
        // ignore
      }

      toast.success(`Badhai ho! Day ${dayNum} complete hua • Score: ${calcScore}/5 🎉`);
    } catch {
      toast.error('Network error while submitting quiz. Please check your connection.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDownloadNotes = () => {
    const blob = new Blob(
      [
        `UYANIX 30 DAYS CHALLENGE — CLASS ${classNum}\nDAY ${dayNum}: ${chapterTitle}\n\n${chapterContent}\n\nKey Takeaways:\n${keyTakeaways.join(
          '\n- '
        )}`,
      ],
      { type: 'text/plain;charset=utf-8' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Uyanix-Class-${classNum}-Day-${dayNum}-${chapterTitle.replace(/\s+/g, '-')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Chapter study notes downloaded!');
  };

  const displayScore = serverScore ?? prevBestScore ?? 5;

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-4xl px-4 py-10 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1.5 text-sm font-semibold text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" /> Back to Dashboard
          </Link>

          <div className="flex items-center gap-2">
            {dayNum > 1 && (
              <Link
                href={`/daily/${dayNum - 1}`}
                className="inline-flex h-9 items-center gap-1 rounded-full border border-border bg-card px-3.5 text-xs font-semibold hover:bg-accent"
              >
                <ArrowLeft className="h-3.5 w-3.5" /> Day {dayNum - 1}
              </Link>
            )}
            {dayNum < 30 && (
              <Link
                href={`/daily/${dayNum + 1}`}
                className="inline-flex h-9 items-center gap-1 rounded-full border border-border bg-card px-3.5 text-xs font-semibold hover:bg-accent"
              >
                Day {dayNum + 1} <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </div>

        {/* Chapter Header Banner */}
        <div className="mt-6 rounded-3xl bg-gradient-hero p-6 text-primary-foreground shadow-soft sm:p-8">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full bg-white/20 px-3 py-1 text-xs font-semibold">
              <BookOpen className="h-3.5 w-3.5" /> Class {classNum} • Day {dayNum} of 30
            </span>
            {isAlreadyDone && (
              <span className="inline-flex items-center gap-1 rounded-full bg-secondary px-3 py-1 text-xs font-bold text-secondary-foreground">
                <CheckCircle2 className="h-3.5 w-3.5" /> Completed ({displayScore}/5)
              </span>
            )}
          </div>

          <h1 className="mt-3 text-2xl font-extrabold sm:text-4xl">
            Day {dayNum}: {chapterTitle}
          </h1>
          <p className="mt-2 text-sm opacity-90">{chapterSummary}</p>

          <div className="mt-5 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={handleDownloadNotes}
              className="inline-flex h-10 items-center gap-2 rounded-full bg-card px-4 text-xs font-semibold text-primary shadow-soft transition hover:scale-[1.02]"
            >
              <Download className="h-3.5 w-3.5" /> Download Revision Notes
            </button>
          </div>
        </div>

        {/* Study Content Card */}
        <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card sm:p-8">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-primary">
            <Sparkles className="h-4 w-4" /> Daily Concept Study Material
          </div>

          <div className="mt-4 space-y-4 whitespace-pre-line text-sm leading-relaxed text-foreground">
            {chapterContent}
          </div>

          <div className="mt-6 rounded-2xl bg-accent/50 p-5">
            <div className="text-xs font-bold uppercase tracking-wider text-primary">
              Key Takeaways (Exam Quick Points)
            </div>
            <ul className="mt-2.5 space-y-1.5 text-sm text-foreground">
              {keyTakeaways.map((point) => (
                <li key={point} className="flex items-start gap-2">
                  <span className="text-secondary font-bold">✓</span>
                  <span>{point}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* 5 MCQs Interactive Quiz */}
        <form
          onSubmit={handleSubmitQuiz}
          className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card sm:p-8"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-4">
            <div>
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-primary">
                <HelpCircle className="h-4 w-4" /> Daily Practice Quiz
              </div>
              <h2 className="mt-1 text-xl font-bold">
                Solve 5 MCQs to Complete Day {dayNum}
              </h2>
            </div>

            {submitted && (
              <div className="animate-pop-in rounded-2xl bg-secondary/15 px-4 py-2 text-sm font-extrabold text-secondary tabular-nums shadow-sm">
                Score: {displayScore} / 5
              </div>
            )}
          </div>

          <div className="mt-6 space-y-6">
            {sanitizedQuestions.map((mcq, qIdx) => {
              const userChoice = selectedAnswers[qIdx];
              const review = reviewResults[qIdx];
              const hasReview = Boolean(review);
              const isCorrect = review?.isCorrect;

              return (
                <div
                  key={mcq.id}
                  className="rounded-2xl border border-border bg-background p-5"
                >
                  <div className="text-sm font-bold">
                    Q{qIdx + 1}. {mcq.question}
                  </div>

                  <div className="mt-3 grid gap-2.5 sm:grid-cols-2">
                    {mcq.options.map((opt, optIdx) => {
                      const isSelected = userChoice === optIdx;
                      const isOptionTheCorrectAnswer = hasReview && review.correctIndex === optIdx;

                      let btnStyle = 'border-border bg-card hover:bg-accent/50';
                      let extraAnim = '';
                      if (submitted && hasReview) {
                        if (isOptionTheCorrectAnswer) {
                          btnStyle =
                            'border-secondary bg-secondary/15 text-foreground font-semibold ring-1 ring-secondary/50';
                        } else if (isSelected && !isOptionTheCorrectAnswer) {
                          btnStyle =
                            'border-destructive bg-destructive/15 text-destructive font-semibold ring-1 ring-destructive/50';
                          extraAnim = 'animate-shake-x';
                        }
                      } else if (isSelected) {
                        btnStyle = 'border-primary bg-primary/10 text-primary font-semibold ring-1 ring-primary';
                      }

                      return (
                        <button
                          key={opt}
                          type="button"
                          disabled={submitted || isSubmitting}
                          onClick={() => handleSelectOption(qIdx, optIdx)}
                          className={`flex items-center justify-between rounded-xl border px-4 py-3 text-left text-xs transition duration-150 active:scale-[0.98] ${btnStyle} ${extraAnim}`}
                        >
                          <span>
                            <b className="mr-1.5">{String.fromCharCode(65 + optIdx)}.</b> {opt}
                          </span>
                          {submitted && hasReview && isOptionTheCorrectAnswer && (
                            <CheckCircle2 className="animate-pop-in h-4 w-4 shrink-0 text-secondary" />
                          )}
                          {submitted && hasReview && isSelected && !isOptionTheCorrectAnswer && (
                            <XCircle className="animate-pop-in h-4 w-4 shrink-0 text-destructive" />
                          )}
                        </button>
                      );
                    })}
                  </div>

                  {submitted && hasReview && review.explanation && (
                    <div className="mt-3 rounded-xl bg-muted/60 p-3 text-xs text-muted-foreground">
                      <b className="text-foreground">Explanation:</b> {review.explanation}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
            {!submitted ? (
              <button
                type="submit"
                disabled={isSubmitting}
                className="inline-flex h-12 items-center gap-2 rounded-full bg-gradient-hero px-8 text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.02] disabled:opacity-50"
              >
                <Flame className="h-4 w-4" /> {isSubmitting ? 'Evaluating Quiz...' : `Submit 5 MCQs & Complete Day ${dayNum}`}
              </button>
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setSubmitted(false);
                    setSelectedAnswers({});
                    setReviewResults({});
                  }}
                  className="inline-flex h-11 items-center rounded-full border border-border bg-card px-5 text-xs font-semibold hover:bg-accent"
                >
                  Retry Quiz
                </button>
                {dayNum < 30 ? (
                  <button
                    type="button"
                    onClick={() => router.push(`/daily/${dayNum + 1}`)}
                    className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
                  >
                    Next: Day {dayNum + 1} Chapter →
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => router.push('/exam?type=final')}
                    className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
                  >
                    Proceed to Final Exam 🏆
                  </button>
                )}
              </div>
            )}
          </div>
        </form>
      </section>

      <Footer />
    </div>
  );
}
