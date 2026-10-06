import 'server-only';

import crypto from 'crypto';
import { getSupabaseAdminClient, dbRecordAuditLog } from '@/lib/supabase-server';
import {
  generateChapterForClassAndDay,
  MCQQuestion,
  ChapterData,
} from '@/lib/curriculum';
import { checkIdempotency, commitIdempotency } from '@/lib/financial-authoritative-service';

// ============================================================================
// PHASE 3: DAILY PROGRESS, CHAPTER ACCESS & ASSESSMENT AUTHORITATIVE SERVICE
// Authoritative source of truth: Supabase PostgreSQL (public.daily_progress, public.chapters)
// ============================================================================

export interface StudentMCQ {
  id: string;
  question: string;
  options: [string, string, string, string];
  topic?: string;
}

export interface ServerMCQ extends StudentMCQ {
  correctIndex: number;
  explanation: string;
}

export interface StudentChapterDTO {
  id: string;
  classNum: number;
  day: number;
  title: string;
  summary: string;
  content: string;
  keyTakeaways: string[];
  pdfUrl?: string;
  mcqs: StudentMCQ[]; // Strictly sanitized - no correctIndex, no explanation
}

export interface DailyProgressRow {
  id: string;
  userId: string;
  day: number;
  score: number;
  completedAt: string;
  attemptId?: string;
  submissionRequestId?: string;
}

export interface StudentProgressSummary {
  userId: string;
  completedDays: number[];
  dailyScores: Record<number, number>;
  completedCount: number;
  nextAvailableDay: number;
  currentStreak: number;
  totalScore: number;
  isAllCompleted: boolean;
}

export type QuizSubmissionResult =
  | {
      ok: true;
      status: 'SUCCESS';
      day: number;
      score: number;
      maxScore: number;
      alreadyCompleted: false;
      streak: number;
      completedDays: number[];
      results: Array<{
        questionId: string;
        userChoice: number;
        correctIndex: number;
        isCorrect: boolean;
        explanation: string;
      }>;
      completedAt: string;
    }
  | {
      ok: false;
      status: 'ALREADY_COMPLETED';
      error: string;
      errorCode: 'ALREADY_COMPLETED';
      httpStatus: 409;
      day: number;
      originalScore: number;
      completedAt: string;
    }
  | {
      ok: false;
      status: 'ERROR';
      error: string;
      errorCode: string;
      httpStatus: number;
    };

// High-resilience in-memory fallback store (Never authoritative when PostgreSQL is available)
// Key: userId -> Map of day -> DailyProgressRow
const inMemoryProgressByStudent = new Map<string, Map<number, DailyProgressRow>>();

// Concurrency mutex per user-day combination to prevent race conditions across parallel calls
const activeSubmissionLocks = new Set<string>();

/**
 * Strips all sensitive answer keys and explanations from questions for student delivery.
 */
export function sanitizeQuestionsForStudent(mcqs: MCQQuestion[]): StudentMCQ[] {
  return mcqs.map((q) => ({
    id: q.id,
    question: q.question,
    options: [q.options[0], q.options[1], q.options[2], q.options[3]],
    topic: q.topic,
  }));
}

/**
 * Loads the server-authoritative questions with answer keys and explanations.
 * NEVER serialize or return this to the student before quiz submission!
 */
export async function getAuthoritativeServerQuestionsForDay(
  classNum: number,
  day: number
): Promise<ServerMCQ[]> {
  const safeClass = Math.max(1, Math.min(12, Math.floor(Number(classNum) || 12)));
  const safeDay = Math.max(1, Math.min(30, Math.floor(Number(day) || 1)));

  const baseChapter = generateChapterForClassAndDay(safeClass, safeDay);
  return baseChapter.mcqs.map((q) => ({
    id: q.id,
    question: q.question,
    options: [q.options[0], q.options[1], q.options[2], q.options[3]],
    correctIndex: q.correctIndex,
    explanation: q.explanation,
    topic: q.topic,
  }));
}

/**
 * Loads a daily chapter for a student.
 * 1. Checks public.chapters in Supabase for any admin updates.
 * 2. Falls back to deterministic curriculum generator.
 * 3. Strips correct answers and explanations before returning.
 */
export async function getAuthoritativeDailyChapter(params: {
  userClass: number;
  day: number;
  requestedClass?: number;
  actorRole: string;
}): Promise<
  | { ok: true; chapter: StudentChapterDTO }
  | { ok: false; error: string; errorCode: string; httpStatus: number }
> {
  const { userClass, day, requestedClass, actorRole } = params;

  if (!Number.isInteger(day) || day < 1 || day > 30) {
    return {
      ok: false,
      error: `Day ${day} is invalid. Daily challenge days must be between 1 and 30.`,
      errorCode: 'INVALID_DAY',
      httpStatus: 400,
    };
  }

  // Section 10: Class-based content enforcement.
  // A student cannot request chapters from another class unless they are an admin.
  if (
    requestedClass !== undefined &&
    requestedClass !== userClass &&
    actorRole !== 'admin'
  ) {
    return {
      ok: false,
      error: `Forbidden: You are enrolled in Class ${userClass}. Access to Class ${requestedClass} curriculum is restricted.`,
      errorCode: 'CLASS_FORBIDDEN',
      httpStatus: 403,
    };
  }

  const effectiveClass = actorRole === 'admin' && requestedClass ? requestedClass : userClass;
  const safeClass = Math.max(1, Math.min(12, Math.floor(Number(effectiveClass) || 12)));

  // Try loading from Supabase public.chapters (where admin overrides are persisted)
  let customTitle: string | null = null;
  let customContent: string | null = null;
  let customPdfUrl: string | null = null;

  const supabase = getSupabaseAdminClient();
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('chapters')
        .select('*')
        .eq('class', safeClass)
        .eq('day', day)
        .maybeSingle();

      if (!error && data) {
        customTitle = data.title;
        customContent = data.content;
        customPdfUrl = data.pdf_url;
      }
    } catch {
      // Gracefully fall back to deterministic curriculum generator
    }
  }

  const baseChapter = generateChapterForClassAndDay(safeClass, day);
  const sanitizedMcqs = sanitizeQuestionsForStudent(baseChapter.mcqs);

  const studentChapter: StudentChapterDTO = {
    id: `c${safeClass}-d${day}`,
    classNum: safeClass,
    day,
    title: customTitle || baseChapter.title,
    summary: baseChapter.summary,
    content: customContent || baseChapter.content,
    keyTakeaways: baseChapter.keyTakeaways,
    pdfUrl: customPdfUrl || baseChapter.pdfUrl,
    mcqs: sanitizedMcqs,
  };

  return { ok: true, chapter: studentChapter };
}

/**
 * Calculates current consecutive streak from a sorted list of completed days.
 */
export function calculateStreakFromCompletedDays(completedDays: number[]): number {
  if (!Array.isArray(completedDays) || completedDays.length === 0) return 0;
  const set = new Set(completedDays);

  // Find the longest sequence of consecutive days ending with the latest completed day
  const maxDay = Math.max(...completedDays);
  let streak = 0;
  for (let d = maxDay; d >= 1; d--) {
    if (set.has(d)) {
      streak++;
    } else {
      break;
    }
  }

  // Also support chain from Day 1 if student started from day 1
  let consecutiveFromStart = 0;
  for (let d = 1; d <= 30; d++) {
    if (set.has(d)) consecutiveFromStart++;
    else break;
  }

  return Math.max(streak, consecutiveFromStart);
}

/**
 * Loads authoritative student progress directly from Supabase PostgreSQL public.daily_progress.
 */
export async function getAuthoritativeStudentProgress(
  userId: string
): Promise<StudentProgressSummary> {
  const normalizedUserId = String(userId || '').trim();
  const supabase = getSupabaseAdminClient();

  const completedDays: number[] = [];
  const dailyScores: Record<number, number> = {};
  let totalScore = 0;

  let loadedFromDb = false;

  if (supabase && normalizedUserId) {
    try {
      const { data, error } = await supabase
        .from('daily_progress')
        .select('day, score, completed_at')
        .eq('user_id', normalizedUserId)
        .order('day', { ascending: true });

      if (!error && Array.isArray(data)) {
        loadedFromDb = true;
        for (const row of data) {
          const d = Number(row.day);
          const s = Number(row.score);
          if (d >= 1 && d <= 30) {
            completedDays.push(d);
            dailyScores[d] = s;
            totalScore += s;
          }
        }
      }
    } catch {
      // Fall through to memory store
    }
  }

  // In-memory fallback if DB unavailable or empty
  if (!loadedFromDb && normalizedUserId) {
    const userMap = inMemoryProgressByStudent.get(normalizedUserId);
    if (userMap) {
      for (const [day, row] of userMap.entries()) {
        completedDays.push(day);
        dailyScores[day] = row.score;
        totalScore += row.score;
      }
      completedDays.sort((a, b) => a - b);
    }
  }

  const completedCount = completedDays.length;
  const nextAvailableDay = Math.min(30, completedCount + 1);
  const currentStreak = calculateStreakFromCompletedDays(completedDays);

  return {
    userId: normalizedUserId,
    completedDays,
    dailyScores,
    completedCount,
    nextAvailableDay,
    currentStreak,
    totalScore,
    isAllCompleted: completedCount >= 30,
  };
}

/**
 * Authoritative quiz submission handler.
 * - Server validates input, checks duplicates, calculates score, and commits to PostgreSQL atomically.
 * - Client score is strictly ignored / rejected.
 */
export async function submitAuthoritativeDailyQuiz(params: {
  userId: string;
  userRole: string;
  userStatus: string;
  userClass: number;
  day: number;
  answers: number[];
  clientScore?: unknown;
  attemptId?: string;
  requestId?: string;
  idempotencyKey?: string;
}): Promise<QuizSubmissionResult> {
  const {
    userId,
    userRole,
    userStatus,
    userClass,
    day,
    answers,
    attemptId,
    requestId,
    idempotencyKey,
  } = params;

  // 1. Session & account validation
  if (!userId) {
    return {
      ok: false,
      status: 'ERROR',
      error: 'Unauthorized: Valid session required.',
      errorCode: 'UNAUTHENTICATED',
      httpStatus: 401,
    };
  }

  if (userStatus === 'banned' || userStatus === 'suspended') {
    return {
      ok: false,
      status: 'ERROR',
      error: `Account is ${userStatus}. Daily challenge submission is blocked.`,
      errorCode: 'ACCOUNT_RESTRICTED',
      httpStatus: 403,
    };
  }

  // 2. Day validation (Day must be integer 1..30)
  if (!Number.isInteger(day) || day < 1 || day > 30) {
    return {
      ok: false,
      status: 'ERROR',
      error: `Invalid day parameter: ${day}. Challenge days must be integers between 1 and 30.`,
      errorCode: 'INVALID_DAY',
      httpStatus: 400,
    };
  }

  // 3. Answers validation
  if (!Array.isArray(answers)) {
    return {
      ok: false,
      status: 'ERROR',
      error: 'Invalid submission: Answers must be provided as an array.',
      errorCode: 'INVALID_ANSWERS',
      httpStatus: 400,
    };
  }

  const EXPECTED_QUESTIONS_COUNT = 5;
  if (answers.length !== EXPECTED_QUESTIONS_COUNT) {
    return {
      ok: false,
      status: 'ERROR',
      error: `All ${EXPECTED_QUESTIONS_COUNT} MCQs must be answered. Received ${answers.length} answers.`,
      errorCode: 'INCOMPLETE_ANSWERS',
      httpStatus: 422,
    };
  }

  // Check each answer index range (0..3 for 4 options: A, B, C, D)
  for (let i = 0; i < answers.length; i++) {
    const val = answers[i];
    if (!Number.isInteger(val) || val < 0 || val > 3) {
      return {
        ok: false,
        status: 'ERROR',
        error: `Invalid answer at question ${i + 1}: Option index ${val} is out of bounds (allowed: 0–3).`,
        errorCode: 'INVALID_OPTION_INDEX',
        httpStatus: 422,
      };
    }
  }

  // 4. Idempotency Check
  const effectiveIdemKey = idempotencyKey || (attemptId ? `daily_${attemptId}` : undefined);
  if (effectiveIdemKey) {
    const cached = await checkIdempotency(userId, 'SUBMIT_DAILY_QUIZ', effectiveIdemKey, params);
    if (cached.hit && cached.responseBody) {
      return cached.responseBody as QuizSubmissionResult;
    }
  }

  // 5. Concurrency Mutex Lock
  const lockKey = `${userId}:${day}`;
  if (activeSubmissionLocks.has(lockKey)) {
    return {
      ok: false,
      status: 'ALREADY_COMPLETED',
      error: `Concurrent submission in progress for Day ${day}. Please wait.`,
      errorCode: 'CONCURRENT_REQUEST',
      httpStatus: 409,
      day,
      originalScore: 0,
      completedAt: new Date().toISOString(),
    };
  }
  activeSubmissionLocks.add(lockKey);

  try {
    const supabase = getSupabaseAdminClient();
    const nowIso = new Date().toISOString();

    // 6. Authoritative Duplicate Check in Supabase PostgreSQL
    if (supabase) {
      const { data: existingRow, error: checkErr } = await supabase
        .from('daily_progress')
        .select('day, score, completed_at')
        .eq('user_id', userId)
        .eq('day', day)
        .maybeSingle();

      if (!checkErr && existingRow) {
        return {
          ok: false,
          status: 'ALREADY_COMPLETED',
          error: `Day ${day} is already completed with score ${existingRow.score}/5. Duplicate submissions are not allowed.`,
          errorCode: 'ALREADY_COMPLETED',
          httpStatus: 409,
          day,
          originalScore: Number(existingRow.score),
          completedAt: String(existingRow.completed_at),
        };
      }
    } else {
      // Memory check fallback
      const userMap = inMemoryProgressByStudent.get(userId);
      const existingMem = userMap?.get(day);
      if (existingMem) {
        return {
          ok: false,
          status: 'ALREADY_COMPLETED',
          error: `Day ${day} is already completed with score ${existingMem.score}/5. Duplicate submissions are not allowed.`,
          errorCode: 'ALREADY_COMPLETED',
          httpStatus: 409,
          day,
          originalScore: existingMem.score,
          completedAt: existingMem.completedAt,
        };
      }
    }

    // 7. Server-Side Score Calculation (NEVER trust clientScore!)
    const serverQuestions = await getAuthoritativeServerQuestionsForDay(userClass, day);
    let calculatedScore = 0;
    const detailedResults = serverQuestions.map((sq, idx) => {
      const userChoice = answers[idx];
      const isCorrect = userChoice === sq.correctIndex;
      if (isCorrect) calculatedScore++;

      return {
        questionId: sq.id,
        userChoice,
        correctIndex: sq.correctIndex,
        isCorrect,
        explanation: sq.explanation,
      };
    });

    // 8. Atomic Database Insert into public.daily_progress
    const attemptUuid = crypto.randomUUID();
    let insertSucceeded = false;

    if (supabase) {
      const { data: inserted, error: insertErr } = await supabase
        .from('daily_progress')
        .insert({
          user_id: userId,
          day,
          score: calculatedScore,
          completed_at: nowIso,
        })
        .select()
        .single();

      if (insertErr) {
        // If unique constraint violated on concurrency race:
        if (insertErr.code === '23505' || insertErr.message?.includes('duplicate key')) {
          // Fetch existing record to return original authoritative score
          const { data: existing } = await supabase
            .from('daily_progress')
            .select('score, completed_at')
            .eq('user_id', userId)
            .eq('day', day)
            .maybeSingle();

          return {
            ok: false,
            status: 'ALREADY_COMPLETED',
            error: `Day ${day} already completed. Duplicate submission blocked by database constraint.`,
            errorCode: 'ALREADY_COMPLETED',
            httpStatus: 409,
            day,
            originalScore: existing ? Number(existing.score) : calculatedScore,
            completedAt: existing ? String(existing.completed_at) : nowIso,
          };
        }

        // Database insert failed
        console.error('Failed to insert daily_progress row:', insertErr);
      } else if (inserted) {
        insertSucceeded = true;
      }
    }

    // Update in-memory fallback
    if (!insertSucceeded) {
      let userMap = inMemoryProgressByStudent.get(userId);
      if (!userMap) {
        userMap = new Map();
        inMemoryProgressByStudent.set(userId, userMap);
      }
      userMap.set(day, {
        id: attemptUuid,
        userId,
        day,
        score: calculatedScore,
        completedAt: nowIso,
        attemptId: attemptUuid,
        submissionRequestId: requestId,
      });
    }

    // 9. Fetch updated progress to return authoritative streak & completed days
    const updatedProgress = await getAuthoritativeStudentProgress(userId);

    // 10. Audit Log
    await dbRecordAuditLog(userId, 'DAILY_QUIZ_COMPLETED', `Day ${day} - Score: ${calculatedScore}/5`, {
      day,
      calculatedScore,
      userClass,
      requestId,
      attemptUuid,
    });

    const successResponse: QuizSubmissionResult = {
      ok: true,
      status: 'SUCCESS',
      day,
      score: calculatedScore,
      maxScore: EXPECTED_QUESTIONS_COUNT,
      alreadyCompleted: false,
      streak: updatedProgress.currentStreak,
      completedDays: updatedProgress.completedDays,
      results: detailedResults,
      completedAt: nowIso,
    };

    // 11. Commit Idempotency
    if (effectiveIdemKey) {
      await commitIdempotency(
        userId,
        'SUBMIT_DAILY_QUIZ',
        effectiveIdemKey,
        params,
        200,
        successResponse
      );
    }

    return successResponse;
  } finally {
    activeSubmissionLocks.delete(lockKey);
  }
}

/**
 * Governed Admin Correction of a Daily Score.
 * Strictly requires actorEmail, reason, and records audit event (Section 20).
 */
export async function adminCorrectAuthoritativeDailyScore(params: {
  adminActorId: string;
  adminActorRole: string;
  adminActorEmail: string;
  studentId: string;
  day: number;
  newScore: number;
  reason: string;
}): Promise<
  | { ok: true; day: number; oldScore: number; newScore: number; updatedAt: string }
  | { ok: false; error: string; httpStatus: number }
> {
  const {
    adminActorRole,
    adminActorEmail,
    studentId,
    day,
    newScore,
    reason,
  } = params;

  if (adminActorRole !== 'admin') {
    return { ok: false, error: 'Forbidden: Admin role required for score corrections.', httpStatus: 403 };
  }

  if (!reason || reason.trim().length < 5) {
    return {
      ok: false,
      error: 'Administrative justification reason (min 5 chars) is mandatory for audit compliance.',
      httpStatus: 400,
    };
  }

  if (!Number.isInteger(day) || day < 1 || day > 30) {
    return { ok: false, error: 'Invalid day parameter.', httpStatus: 400 };
  }

  if (!Number.isInteger(newScore) || newScore < 0 || newScore > 5) {
    return { ok: false, error: 'New score must be an integer between 0 and 5.', httpStatus: 400 };
  }

  const supabase = getSupabaseAdminClient();
  let oldScore = 0;
  const nowIso = new Date().toISOString();

  if (supabase) {
    const { data: existing } = await supabase
      .from('daily_progress')
      .select('score')
      .eq('user_id', studentId)
      .eq('day', day)
      .maybeSingle();

    if (!existing) {
      return { ok: false, error: `Student has not completed Day ${day} yet. Cannot correct non-existent score.`, httpStatus: 404 };
    }

    oldScore = Number(existing.score);

    const { error: updateErr } = await supabase
      .from('daily_progress')
      .update({ score: newScore, completed_at: nowIso })
      .eq('user_id', studentId)
      .eq('day', day);

    if (updateErr) {
      return { ok: false, error: 'Database update failed: ' + updateErr.message, httpStatus: 500 };
    }
  } else {
    const userMap = inMemoryProgressByStudent.get(studentId);
    const existing = userMap?.get(day);
    if (!existing) {
      return { ok: false, error: `Student has not completed Day ${day} yet.`, httpStatus: 404 };
    }
    oldScore = existing.score;
    existing.score = newScore;
  }

  await dbRecordAuditLog(
    params.adminActorId,
    'ADMIN_DAILY_SCORE_CORRECTED',
    `Student ${studentId} Day ${day} Score Changed ${oldScore} -> ${newScore}`,
    {
      studentId,
      day,
      oldScore,
      newScore,
      reason,
      adminEmail: adminActorEmail,
    }
  );

  return {
    ok: true,
    day,
    oldScore,
    newScore,
    updatedAt: nowIso,
  };
}
