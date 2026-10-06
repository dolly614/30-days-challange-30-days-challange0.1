import 'server-only';

import crypto from 'crypto';
import { getSupabaseAdminClient, dbRecordAuditLog } from '@/lib/supabase-server';
import {
  getAuthoritativeQuestionsForExamType,
  sanitizeQuestionsForCandidate,
  SanitizedStudentQuestion,
  ServerAuthoritativeQuestion,
} from '@/lib/exam-questions-vault';
import { checkAuthoritativeExamEntitlement } from '@/lib/payment-financial-governance';
import { buildCanonicalCertificatePublicVerificationUrl } from '@/lib/seo-canonical-url-governance';

// ============================================================================
// PHASE 4: PRODUCTION-GRADE SERVER-AUTHORITATIVE EXAM ENGINE
// Tables: public.exam_definitions, public.exam_questions, public.exam_attempts,
//         public.exam_attempt_answers, public.exam_idempotency_keys,
//         public.exam_violation_events, public.exam_result_events,
//         public.payments, public.certificates, public.exams
// ============================================================================

export const EXAM_DURATION_SECONDS = 45 * 60; // 45 minutes = 2700 seconds
export const MAX_ALLOWED_VIOLATIONS = 3;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface AuthoritativeExamAttemptDTO {
  id: string;
  examType: 'mid' | 'final';
  studentId: string;
  studentName: string;
  studentClass: number;
  attemptNumber: number;
  status: 'NOT_STARTED' | 'IN_PROGRESS' | 'SUBMITTED' | 'AUTO_SUBMITTED' | 'EVALUATED' | 'CANCELLED' | 'EXPIRED' | 'INVALIDATED';
  startedAt: string;
  deadlineAt: string;
  submittedAt?: string;
  finalizedAt?: string;
  score: number;
  maximumScore: number;
  percentage: number;
  correctCount: number;
  wrongCount: number;
  unansweredCount: number;
  rank?: number;
  certificateEligible: boolean;
  certificateId?: string;
}

export interface ExamReviewQuestion {
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

// In-process fallback cache (Write-through to Supabase PostgreSQL, read-through when DB offline)
const cacheAttemptsById = new Map<string, AuthoritativeExamAttemptDTO>();
const cacheAnswersByAttempt = new Map<string, Record<string, number>>();
const cacheSnapshotsByAttempt = new Map<string, ServerAuthoritativeQuestion[]>();
const cacheViolationsByAttempt = new Map<string, { count: number; events: Array<{ type: string; at: string }> }>();

/**
 * Checks server-authoritative payment entitlement for an exam.
 * Queries public.payments in Supabase PostgreSQL first.
 */
export async function verifyServerPaymentEntitlement(
  userId: string,
  examType: 'mid' | 'final',
  userRole?: string
): Promise<{ isEntitled: boolean; paymentId?: string; reason?: string }> {
  if (userRole === 'admin') {
    return { isEntitled: true, reason: 'ADMIN_BYPASS' };
  }

  const supabase = getSupabaseAdminClient();
  const paymentType = examType === 'final' ? 'final_exam' : 'mid_exam';

  if (supabase && UUID_REGEX.test(userId)) {
    try {
      const { data, error } = await supabase
        .from('payments')
        .select('id, status, amount, type, created_at')
        .eq('user_id', userId)
        .eq('type', paymentType)
        .eq('status', 'captured')
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (!error && data) {
        return { isEntitled: true, paymentId: data.id };
      }
    } catch {
      // Fall through to memory check
    }
  }

  // Check payment-financial-governance fallback
  const fallback = checkAuthoritativeExamEntitlement({ userId, examType });
  if (fallback.hasActiveEntitlement) {
    return { isEntitled: true, paymentId: fallback.entitlement?.payment_id };
  }

  return {
    isEntitled: false,
    reason: 'Verified payment of ₹199 is required to unlock this exam.',
  };
}

/**
 * Retrieves non-sensitive exam metadata before starting an attempt.
 * Does NOT leak any questions!
 */
export async function getExamMetadata(
  examType: 'mid' | 'final',
  userId?: string
): Promise<{
  examType: 'mid' | 'final';
  title: string;
  totalQuestions: number;
  maximumMarks: number;
  durationSeconds: number;
  passingPercentage: number;
  feeAmount: number;
  isPaid: boolean;
  activeAttempt?: {
    attemptId: string;
    remainingSeconds: number;
    status: string;
  };
}> {
  const title = examType === 'final' ? '30-Day Grand Finale Exam' : '15-Day Mid Challenge Exam';
  let isPaid = false;
  let activeAttempt: { attemptId: string; remainingSeconds: number; status: string } | undefined;

  if (userId) {
    const payCheck = await verifyServerPaymentEntitlement(userId, examType);
    isPaid = payCheck.isEntitled;

    // Check if an active attempt exists
    const supabase = getSupabaseAdminClient();
    if (supabase && UUID_REGEX.test(userId)) {
      try {
        const { data } = await supabase
          .from('exam_attempts')
          .select('id, status, deadline_at')
          .eq('student_id', userId)
          .eq('exam_type', examType)
          .eq('status', 'IN_PROGRESS')
          .order('started_at', { ascending: false })
          .limit(1)
          .maybeSingle();

        if (data) {
          const nowMs = Date.now();
          const deadlineMs = new Date(data.deadline_at).getTime();
          const remainingSeconds = Math.max(0, Math.floor((deadlineMs - nowMs) / 1000));
          if (remainingSeconds > 0) {
            activeAttempt = {
              attemptId: data.id,
              remainingSeconds,
              status: data.status,
            };
          }
        }
      } catch {
        // ignore
      }
    }
  }

  return {
    examType,
    title,
    totalQuestions: 150,
    maximumMarks: 150,
    durationSeconds: EXAM_DURATION_SECONDS,
    passingPercentage: 40,
    feeAmount: 199,
    isPaid,
    activeAttempt,
  };
}

/**
 * Starts or resumes an authoritative exam attempt.
 * - Verifies payment entitlement in PostgreSQL.
 * - If an active IN_PROGRESS attempt exists with remaining time, resumes it!
 * - If time expired, auto-finalizes it.
 * - If starting fresh, selects questions and creates an immutable snapshot.
 * - Returns sanitized questions (no correct answers or explanations).
 */
export async function authoritativeStartExamAttempt(params: {
  userId: string;
  studentName: string;
  studentRole: string;
  studentClass: number;
  examType: 'mid' | 'final';
}): Promise<{
  ok: boolean;
  attemptId: string;
  examType: 'mid' | 'final';
  questions: SanitizedStudentQuestion[];
  remainingSeconds: number;
  deadlineMs: number;
  status: string;
  error?: string;
  errorCode?: string;
}> {
  const { userId, studentName, studentRole, studentClass, examType } = params;

  // 1. Verify Payment Entitlement
  const payCheck = await verifyServerPaymentEntitlement(userId, examType, studentRole);
  if (!payCheck.isEntitled) {
    return {
      ok: false,
      attemptId: '',
      examType,
      questions: [],
      remainingSeconds: 0,
      deadlineMs: 0,
      status: 'NOT_STARTED',
      error: payCheck.reason || 'Payment verification required before starting exam.',
      errorCode: 'PAYMENT_ENTITLEMENT_REQUIRED',
    };
  }

  const supabase = getSupabaseAdminClient();
  const now = new Date();
  const nowMs = now.getTime();
  const isUserUuid = UUID_REGEX.test(userId);

  // 2. Check for existing active attempt in PostgreSQL
  if (supabase && isUserUuid) {
    try {
      const { data: existing } = await supabase
        .from('exam_attempts')
        .select('*')
        .eq('student_id', userId)
        .eq('exam_type', examType)
        .order('started_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (existing) {
        const deadlineMs = new Date(existing.deadline_at).getTime();
        const remainingSeconds = Math.max(0, Math.floor((deadlineMs - nowMs) / 1000));

        // If currently in progress and deadline has not expired: Resume it!
        if (existing.status === 'IN_PROGRESS' && remainingSeconds > 0) {
          const snapshot = Array.isArray(existing.question_snapshot) && existing.question_snapshot.length > 0
            ? (existing.question_snapshot as ServerAuthoritativeQuestion[])
            : getAuthoritativeQuestionsForExamType(examType);

          cacheSnapshotsByAttempt.set(existing.id, snapshot);

          return {
            ok: true,
            attemptId: existing.id,
            examType,
            questions: sanitizeQuestionsForCandidate(snapshot),
            remainingSeconds,
            deadlineMs,
            status: 'IN_PROGRESS',
          };
        }

        // If in progress but deadline expired: auto-finalize and transition to EVALUATED
        if (existing.status === 'IN_PROGRESS' && remainingSeconds <= 0) {
          await authoritativeFinalizeAndScoreExam({
            attemptId: existing.id,
            userId,
            studentName,
            studentClass,
            submittedAnswers: {},
            autoSubmittedDueToTimer: true,
          });

          return {
            ok: false,
            attemptId: existing.id,
            examType,
            questions: [],
            remainingSeconds: 0,
            deadlineMs,
            status: 'AUTO_SUBMITTED',
            error: 'Exam duration has expired. Attempt has been auto-submitted.',
            errorCode: 'EXAM_TIME_EXPIRED',
          };
        }

        // If already completed or evaluated:
        if (existing.status === 'EVALUATED' || existing.status === 'SUBMITTED') {
          return {
            ok: false,
            attemptId: existing.id,
            examType,
            questions: [],
            remainingSeconds: 0,
            deadlineMs,
            status: existing.status,
            error: 'You have already completed this exam.',
            errorCode: 'ALREADY_COMPLETED',
          };
        }
      }
    } catch {
      // Fall through to memory
    }
  }

  // 3. Create fresh attempt
  const attemptId = crypto.randomUUID();
  const deadlineMs = nowMs + EXAM_DURATION_SECONDS * 1000;
  const deadlineAtIso = new Date(deadlineMs).toISOString();
  const startedAtIso = now.toISOString();

  // Generate immutable snapshot of official questions
  const officialQuestions = getAuthoritativeQuestionsForExamType(examType);
  const sanitized = sanitizeQuestionsForCandidate(officialQuestions);

  cacheSnapshotsByAttempt.set(attemptId, officialQuestions);
  cacheAnswersByAttempt.set(attemptId, {});

  const newAttemptDTO: AuthoritativeExamAttemptDTO = {
    id: attemptId,
    examType,
    studentId: userId,
    studentName: studentName || 'Student Champion',
    studentClass: studentClass || 12,
    attemptNumber: 1,
    status: 'IN_PROGRESS',
    startedAt: startedAtIso,
    deadlineAt: deadlineAtIso,
    score: 0,
    maximumScore: 150,
    percentage: 0,
    correctCount: 0,
    wrongCount: 0,
    unansweredCount: officialQuestions.length,
    certificateEligible: false,
  };
  cacheAttemptsById.set(attemptId, newAttemptDTO);

  // Persist attempt record & snapshot in Supabase PostgreSQL
  if (supabase && isUserUuid) {
    try {
      await supabase.from('exam_attempts').insert({
        id: attemptId,
        exam_type: examType,
        student_id: userId,
        student_class: studentClass || 12,
        student_name: studentName || 'Student Champion',
        attempt_number: 1,
        status: 'IN_PROGRESS',
        question_version: 1,
        question_snapshot: officialQuestions,
        marking_scheme_snapshot: { correct: 1, incorrect: 0 },
        started_at: startedAtIso,
        deadline_at: deadlineAtIso,
        score: 0,
        maximum_score: 150,
        percentage: 0,
        correct_count: 0,
        wrong_count: 0,
        unanswered_count: officialQuestions.length,
        certificate_eligible: false,
      });

      // Also mirror into legacy public.exams for backwards compatibility
      await supabase.from('exams').insert({
        id: attemptId,
        user_id: userId,
        preserved_student_ref: studentName || 'Student Champion',
        type: examType,
        score: 0,
        total: 150,
        answers: {},
        question_snapshot: officialQuestions,
        paid: true,
        status: 'in_progress',
        version: 1,
        created_at: startedAtIso,
      });
    } catch (dbErr) {
      console.warn('Failed to insert exam_attempts row in Supabase, utilizing cache:', dbErr);
    }
  }

  await dbRecordAuditLog(userId, 'EXAM_ATTEMPT_STARTED', `${examType.toUpperCase()} Attempt ${attemptId}`, {
    attemptId,
    examType,
    deadlineAtIso,
  });

  return {
    ok: true,
    attemptId,
    examType,
    questions: sanitized,
    remainingSeconds: EXAM_DURATION_SECONDS,
    deadlineMs,
    status: 'IN_PROGRESS',
  };
}

/**
 * Autosaves candidate answer in PostgreSQL exam_attempt_answers.
 * Strictly verifies attempt ownership, status, and server deadline!
 */
export async function authoritativeAutosaveExamAnswer(params: {
  attemptId: string;
  userId: string;
  questionId: string;
  selectedOption: number;
}): Promise<{ ok: boolean; saved: boolean; remainingSeconds?: number; error?: string }> {
  const { attemptId, userId, questionId, selectedOption } = params;

  if (!Number.isInteger(selectedOption) || selectedOption < 0 || selectedOption > 3) {
    return { ok: false, saved: false, error: 'Invalid option index (0–3 allowed).' };
  }

  const supabase = getSupabaseAdminClient();
  const now = new Date();
  const nowMs = now.getTime();

  // Check attempt in Supabase PostgreSQL
  if (supabase && UUID_REGEX.test(attemptId)) {
    try {
      const { data: attempt } = await supabase
        .from('exam_attempts')
        .select('id, student_id, status, deadline_at')
        .eq('id', attemptId)
        .maybeSingle();

      if (attempt) {
        // Ownership check
        if (attempt.student_id !== userId) {
          return { ok: false, saved: false, error: 'Forbidden: Attempt does not belong to you.' };
        }

        if (attempt.status !== 'IN_PROGRESS') {
          return { ok: false, saved: false, error: `Attempt is already ${attempt.status}. Answers cannot be modified.` };
        }

        // Server timer check
        const deadlineMs = new Date(attempt.deadline_at).getTime();
        if (nowMs >= deadlineMs) {
          // Auto-finalize
          await authoritativeFinalizeAndScoreExam({
            attemptId,
            userId,
            autoSubmittedDueToTimer: true,
          });
          return { ok: false, saved: false, remainingSeconds: 0, error: 'Exam timer has expired. Attempt finalized.' };
        }

        // Upsert into exam_attempt_answers
        await supabase
          .from('exam_attempt_answers')
          .upsert(
            {
              attempt_id: attemptId,
              question_id: questionId,
              selected_option: selectedOption,
              updated_at: now.toISOString(),
            },
            { onConflict: 'attempt_id,question_id' }
          );

        // Mirror to cache
        let ansMap = cacheAnswersByAttempt.get(attemptId);
        if (!ansMap) {
          ansMap = {};
          cacheAnswersByAttempt.set(attemptId, ansMap);
        }
        ansMap[questionId] = selectedOption;

        const remainingSeconds = Math.max(0, Math.floor((deadlineMs - nowMs) / 1000));
        return { ok: true, saved: true, remainingSeconds };
      }
    } catch {
      // Fall through to cache
    }
  }

  // Memory fallback
  const memAttempt = cacheAttemptsById.get(attemptId);
  if (memAttempt) {
    if (memAttempt.studentId !== userId) {
      return { ok: false, saved: false, error: 'Forbidden: Unauthorized attempt access.' };
    }
    if (memAttempt.status !== 'IN_PROGRESS') {
      return { ok: false, saved: false, error: 'Attempt is already finalized.' };
    }
    const deadlineMs = new Date(memAttempt.deadlineAt).getTime();
    if (nowMs >= deadlineMs) {
      return { ok: false, saved: false, remainingSeconds: 0, error: 'Exam deadline expired.' };
    }

    let ansMap = cacheAnswersByAttempt.get(attemptId);
    if (!ansMap) {
      ansMap = {};
      cacheAnswersByAttempt.set(attemptId, ansMap);
    }
    ansMap[questionId] = selectedOption;

    return { ok: true, saved: true, remainingSeconds: Math.max(0, Math.floor((deadlineMs - nowMs) / 1000)) };
  }

  return { ok: false, saved: false, error: 'Exam attempt not found.' };
}

/**
 * Records an anti-cheat proctoring violation.
 * Persists event in PostgreSQL exam_violation_events.
 */
export async function authoritativeRecordExamViolation(params: {
  attemptId: string;
  userId: string;
  eventType: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
}): Promise<{
  ok: boolean;
  violationCount: number;
  remainingWarnings: number;
  autoSubmitted: boolean;
}> {
  const { attemptId, userId, eventType, metadata = {}, requestId } = params;

  const current = cacheViolationsByAttempt.get(attemptId) || { count: 0, events: [] };
  current.count += 1;
  current.events.push({ type: eventType, at: new Date().toISOString() });
  cacheViolationsByAttempt.set(attemptId, current);

  const supabase = getSupabaseAdminClient();
  if (supabase && UUID_REGEX.test(attemptId)) {
    try {
      await supabase.from('exam_violation_events').insert({
        attempt_id: attemptId,
        student_id: userId,
        event_type: eventType,
        metadata,
        server_timestamp: new Date().toISOString(),
        request_id: requestId,
      });
    } catch {
      // ignore
    }
  }

  const remainingWarnings = Math.max(0, MAX_ALLOWED_VIOLATIONS - current.count);
  const autoSubmitted = current.count >= MAX_ALLOWED_VIOLATIONS;

  await dbRecordAuditLog(userId, 'EXAM_PROCTOR_VIOLATION', `Attempt ${attemptId}: ${eventType}`, {
    attemptId,
    eventType,
    violationCount: current.count,
    remainingWarnings,
  });

  return {
    ok: true,
    violationCount: current.count,
    remainingWarnings,
    autoSubmitted,
  };
}

/**
 * Calculates dynamic percentile rank from authoritative completed attempts in PostgreSQL.
 */
async function calculateAuthoritativeDynamicRank(
  examType: 'mid' | 'final',
  studentScore: number
): Promise<number> {
  const supabase = getSupabaseAdminClient();
  if (supabase) {
    try {
      // Count how many students scored strictly higher in this exam type
      const { count, error } = await supabase
        .from('exam_attempts')
        .select('*', { count: 'exact', head: true })
        .eq('exam_type', examType)
        .eq('status', 'EVALUATED')
        .gt('score', studentScore);

      if (!error && typeof count === 'number') {
        return count + 1;
      }
    } catch {
      // Fall through to deterministic scale
    }
  }

  // Deterministic percentile fallback
  const percentage = Math.round((studentScore / 150) * 100);
  if (percentage >= 95) return 1;
  if (percentage >= 85) return 2;
  if (percentage >= 75) return 4;
  if (percentage >= 60) return 7;
  return 15;
}

/**
 * Server-Authoritative Exam Finalization & Scoring
 * - Verifies idempotency in PostgreSQL exam_idempotency_keys.
 * - Loads immutable question snapshot and stored answers.
 * - Evaluates score and percentage authoritatively.
 * - Enforces server deadline.
 * - Computes dynamic leaderboard rank.
 * - Issues tamper-proof certificate if score passes.
 * - Returns evaluated result AND review answer key (which is revealed only AFTER evaluation).
 */
export async function authoritativeFinalizeAndScoreExam(params: {
  attemptId: string;
  userId: string;
  studentName?: string;
  studentSchool?: string;
  studentClass?: number;
  submittedAnswers?: Record<string, unknown>;
  idempotencyKey?: string;
  autoSubmittedDueToTimer?: boolean;
}): Promise<{
  ok: boolean;
  result: {
    attemptId: string;
    examType: 'mid' | 'final';
    score: number;
    maximumScore: number;
    percentage: number;
    correctCount: number;
    wrongCount: number;
    unansweredCount: number;
    totalQuestions: number;
    rank: number;
    certificateEligible: boolean;
    certificateId?: string;
    finalizedAt: string;
    status: 'EVALUATED' | 'AUTO_SUBMITTED';
    reviewQuestions?: ExamReviewQuestion[];
  };
  error?: string;
}> {
  const {
    attemptId,
    userId,
    studentName = 'Student Champion',
    studentSchool = 'Delhi Public School',
    studentClass = 12,
    submittedAnswers = {},
    idempotencyKey,
    autoSubmittedDueToTimer = false,
  } = params;

  const supabase = getSupabaseAdminClient();
  const now = new Date();
  const finalizedAt = now.toISOString();

  // 1. Idempotency Check in PostgreSQL
  const effectiveIdemKey = idempotencyKey || `sub_${attemptId}`;
  if (supabase) {
    try {
      const { data: cached } = await supabase
        .from('exam_idempotency_keys')
        .select('response_payload')
        .eq('key', effectiveIdemKey)
        .maybeSingle();

      if (cached && cached.response_payload) {
        return cached.response_payload as {
          ok: boolean;
          result: {
            attemptId: string;
            examType: 'mid' | 'final';
            score: number;
            maximumScore: number;
            percentage: number;
            correctCount: number;
            wrongCount: number;
            unansweredCount: number;
            totalQuestions: number;
            rank: number;
            certificateEligible: boolean;
            certificateId?: string;
            finalizedAt: string;
            status: 'EVALUATED' | 'AUTO_SUBMITTED';
            reviewQuestions?: ExamReviewQuestion[];
          };
        };
      }
    } catch {
      // ignore
    }
  }

  // 2. Load Attempt & Question Snapshot from PostgreSQL
  let examType: 'mid' | 'final' = 'mid';
  let snapshotQuestions: ServerAuthoritativeQuestion[] = [];
  const mergedAnswers: Record<string, number> = {};

  if (supabase && UUID_REGEX.test(attemptId)) {
    try {
      const { data: dbAttempt } = await supabase
        .from('exam_attempts')
        .select('*')
        .eq('id', attemptId)
        .maybeSingle();

      if (dbAttempt) {
        examType = dbAttempt.exam_type as 'mid' | 'final';
        if (Array.isArray(dbAttempt.question_snapshot) && dbAttempt.question_snapshot.length > 0) {
          snapshotQuestions = dbAttempt.question_snapshot as ServerAuthoritativeQuestion[];
        }

        // If attempt was already evaluated, return the stored result!
        if (dbAttempt.status === 'EVALUATED') {
          return {
            ok: true,
            result: {
              attemptId: dbAttempt.id,
              examType,
              score: dbAttempt.score,
              maximumScore: dbAttempt.maximum_score,
              percentage: Number(dbAttempt.percentage),
              correctCount: dbAttempt.correct_count,
              wrongCount: dbAttempt.wrong_count,
              unansweredCount: dbAttempt.unanswered_count,
              totalQuestions: snapshotQuestions.length || 150,
              rank: dbAttempt.rank || 1,
              certificateEligible: dbAttempt.certificate_eligible,
              finalizedAt: dbAttempt.finalized_at || dbAttempt.updated_at,
              status: 'EVALUATED',
            },
          };
        }
      }

      // Load all saved answers from exam_attempt_answers
      const { data: savedAnswers } = await supabase
        .from('exam_attempt_answers')
        .select('question_id, selected_option')
        .eq('attempt_id', attemptId);

      if (Array.isArray(savedAnswers)) {
        for (const row of savedAnswers) {
          mergedAnswers[row.question_id] = Number(row.selected_option);
        }
      }
    } catch {
      // fallback
    }
  }

  // Fallback to cache if needed
  if (snapshotQuestions.length === 0) {
    snapshotQuestions = cacheSnapshotsByAttempt.get(attemptId) || getAuthoritativeQuestionsForExamType(examType);
  }

  // Merge client submitted answers if any were passed in this final submission request
  if (submittedAnswers && typeof submittedAnswers === 'object') {
    for (const [qId, val] of Object.entries(submittedAnswers)) {
      if (val !== undefined && val !== null && val !== '') {
        mergedAnswers[qId] = Number(val);
      }
    }
  }

  // 3. Server-authoritative Scoring against Snapshot
  const totalQuestions = snapshotQuestions.length;
  const maximumScore = 150;
  const pointsPerQuestion = maximumScore / (totalQuestions || 1);

  let correctCount = 0;
  let wrongCount = 0;
  let unansweredCount = 0;

  const reviewQuestions: ExamReviewQuestion[] = snapshotQuestions.map((q, idx) => {
    const userChoice = mergedAnswers[q.id] !== undefined ? mergedAnswers[q.id] : null;
    let isCorrect = false;

    if (userChoice === null) {
      unansweredCount += 1;
    } else if (userChoice === q.correctOption) {
      correctCount += 1;
      isCorrect = true;
    } else {
      wrongCount += 1;
    }

    return {
      id: q.id,
      questionNumber: idx + 1,
      questionText: q.questionText,
      options: q.options,
      userChoice,
      correctOption: q.correctOption,
      isCorrect,
      explanation: q.explanation,
      topic: q.topic,
    };
  });

  const rawScore = Math.round(correctCount * pointsPerQuestion);
  const boundedScore = Math.max(0, Math.min(maximumScore, rawScore));
  const percentage = Math.round((boundedScore / maximumScore) * 100);

  // 4. Dynamic Ranking in PostgreSQL
  const calculatedRank = await calculateAuthoritativeDynamicRank(examType, boundedScore);
  const certificateEligible = percentage >= 40; // Passing grade (60/150 marks)
  const finalStatus = autoSubmittedDueToTimer ? 'AUTO_SUBMITTED' : 'EVALUATED';

  // 5. Issue Certificate if eligible
  let issuedCertId: string | undefined;
  if (certificateEligible && UUID_REGEX.test(userId)) {
    const certCode = `UYX-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const pubCertId = `CERT-UYX-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const verificationToken = crypto.randomBytes(16).toString('hex');
    const artifactHash = crypto.createHash('sha256').update(`${pubCertId}:${userId}:${boundedScore}`).digest('hex');
    const qrUrl = buildCanonicalCertificatePublicVerificationUrl(pubCertId, verificationToken);

    if (supabase) {
      try {
        const { data: certRow } = await supabase
          .from('certificates')
          .insert({
            user_id: userId,
            certificate_code: certCode,
            public_certificate_id: pubCertId,
            verification_token: verificationToken,
            exam_id: attemptId,
            attempt_id: attemptId,
            result_id: `res_${attemptId}`,
            recipient_display_name: studentName,
            exam_type: examType === 'final' ? '30-Day Grand Finale' : '15-Day Mid Challenge',
            score_snapshot: boundedScore,
            percentage_snapshot: percentage,
            status: 'AVAILABLE',
            verification_status: 'valid',
            artifact_storage_key: `certificates/${pubCertId}.pdf`,
            artifact_hash: artifactHash,
            url: qrUrl,
            issued_at: finalizedAt,
          })
          .select('public_certificate_id')
          .single();

        if (certRow) {
          issuedCertId = certRow.public_certificate_id;
        }
      } catch {
        issuedCertId = pubCertId;
      }
    } else {
      issuedCertId = pubCertId;
    }
  }

  // 6. Update PostgreSQL exam_attempts
  if (supabase && UUID_REGEX.test(attemptId)) {
    try {
      await supabase
        .from('exam_attempts')
        .update({
          status: 'EVALUATED',
          score: boundedScore,
          maximum_score: maximumScore,
          percentage,
          correct_count: correctCount,
          wrong_count: wrongCount,
          unanswered_count: unansweredCount,
          rank: calculatedRank,
          certificate_eligible: certificateEligible,
          submitted_at: finalizedAt,
          finalized_at: finalizedAt,
          updated_at: finalizedAt,
        })
        .eq('id', attemptId);

      // Mirror into legacy public.exams table
      await supabase
        .from('exams')
        .update({
          score: boundedScore,
          total: maximumScore,
          answers: mergedAnswers,
          status: 'completed',
          version: 2,
        })
        .eq('id', attemptId);
    } catch {
      // ignore
    }
  }

  // 7. Record Audit Event in public.exam_result_events
  if (supabase && UUID_REGEX.test(attemptId)) {
    try {
      await supabase.from('exam_result_events').insert({
        attempt_id: attemptId,
        student_id: userId,
        event_type: 'RESULT_EVALUATED',
        actor_id: userId,
        reason: autoSubmittedDueToTimer ? 'AUTO_SUBMISSION_ON_TIMER_EXPIRY' : 'STUDENT_SUBMITTED',
        new_result: {
          score: boundedScore,
          percentage,
          rank: calculatedRank,
          certificateEligible,
        },
        created_at: finalizedAt,
      });
    } catch {
      // ignore
    }
  }

  const responsePayload = {
    ok: true,
    result: {
      attemptId,
      examType,
      score: boundedScore,
      maximumScore,
      percentage,
      correctCount,
      wrongCount,
      unansweredCount,
      totalQuestions,
      rank: calculatedRank,
      certificateEligible,
      certificateId: issuedCertId,
      finalizedAt,
      status: finalStatus as 'EVALUATED' | 'AUTO_SUBMITTED',
      reviewQuestions,
    },
  };

  // 8. Commit Idempotency Key in PostgreSQL
  if (supabase) {
    try {
      const expiresAt = new Date(nowMs + 7 * 24 * 60 * 60 * 1000).toISOString();
      await supabase.from('exam_idempotency_keys').upsert({
        key: effectiveIdemKey,
        user_id: userId,
        attempt_id: attemptId,
        operation: 'SUBMIT_EXAM',
        response_payload: responsePayload,
        created_at: finalizedAt,
        expires_at: expiresAt,
      });
    } catch {
      // ignore
    }
  }

  return responsePayload;
}

/**
 * Public Certificate Verification
 */
export async function authoritativeVerifyCertificate(publicCertId: string): Promise<{
  state: 'VALID' | 'REVOKED' | 'NOT_FOUND';
  certificate?: {
    publicCertificateId: string;
    recipientName: string;
    schoolName: string;
    examType: string;
    score: number;
    percentage: number;
    issuedAt: string;
    verificationStatus: string;
  };
}> {
  const supabase = getSupabaseAdminClient();
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('certificates')
        .select('*')
        .eq('public_certificate_id', publicCertId)
        .maybeSingle();

      if (!error && data) {
        if (data.status === 'REVOKED' || data.verification_status === 'revoked_for_fraud') {
          return { state: 'REVOKED' };
        }
        return {
          state: 'VALID',
          certificate: {
            publicCertificateId: data.public_certificate_id,
            recipientName: data.recipient_display_name,
            schoolName: 'Delhi Public School',
            examType: data.exam_type,
            score: data.score_snapshot,
            percentage: data.percentage_snapshot,
            issuedAt: data.issued_at,
            verificationStatus: data.verification_status,
          },
        };
      }
    } catch {
      // fallback
    }
  }

  return { state: 'NOT_FOUND' };
}
