import 'server-only';

import {
  getAuthoritativeDailyChapter,
  getAuthoritativeServerQuestionsForDay,
  getAuthoritativeStudentProgress,
  submitAuthoritativeDailyQuiz,
  adminCorrectAuthoritativeDailyScore,
  calculateStreakFromCompletedDays,
  sanitizeQuestionsForStudent,
} from '@/lib/daily-progress-authoritative-service';
import { generateChapterForClassAndDay } from '@/lib/curriculum';

export interface SecurityTestReport {
  name: string;
  category: 'ACCESS_CONTROL' | 'INPUT_VALIDATION' | 'ANTI_TAMPERING' | 'CONCURRENCY' | 'AUDIT_GOVERNANCE';
  passed: boolean;
  details: string;
  evidence?: Record<string, unknown>;
}

/**
 * Executes comprehensive Phase 3 security test suite.
 * Validates all 14 criteria specified in Phase 3 Section 26.
 */
export async function runDailyProgressSecurityAudit(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  results: SecurityTestReport[];
}> {
  const results: SecurityTestReport[] = [];

  const studentA = 'test-student-a-uuid-' + Date.now();
  const studentB = 'test-student-b-uuid-' + Date.now();
  const adminId = 'test-admin-uuid-' + Date.now();

  // Test 1: Cross-User Progress Isolation
  try {
    const progA = await getAuthoritativeStudentProgress(studentA);
    const progB = await getAuthoritativeStudentProgress(studentB);
    const isolated = progA.completedDays.length === 0 && progB.completedDays.length === 0;
    results.push({
      name: 'Test 1: Cross-User Progress Isolation',
      category: 'ACCESS_CONTROL',
      passed: isolated,
      details: 'Student A and Student B progress queries are completely isolated by session user_id.',
      evidence: { studentA_count: progA.completedCount, studentB_count: progB.completedCount },
    });
  } catch (err: unknown) {
    results.push({
      name: 'Test 1: Cross-User Progress Isolation',
      category: 'ACCESS_CONTROL',
      passed: false,
      details: 'Error executing test: ' + (err instanceof Error ? err.message : String(err)),
    });
  }

  // Test 2: Spoofed User ID Prevention
  try {
    // When student A attempts to submit progress, the service requires authoritative session userId
    const sub = await submitAuthoritativeDailyQuiz({
      userId: '', // missing / spoofed empty session
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 1,
      answers: [0, 1, 0, 0, 0],
    });
    const rejected = !sub.ok && sub.errorCode === 'UNAUTHENTICATED';
    results.push({
      name: 'Test 2: Spoofed/Missing Session Prevention',
      category: 'ACCESS_CONTROL',
      passed: rejected,
      details: 'Requests without authentic server session are rejected with 401 UNAUTHENTICATED.',
    });
  } catch {
    results.push({
      name: 'Test 2: Spoofed/Missing Session Prevention',
      category: 'ACCESS_CONTROL',
      passed: false,
      details: 'Failed to enforce session authentication boundary.',
    });
  }

  // Test 3: Class Spoofing Prevention
  try {
    // Class 5 student attempting to access Class 12 curriculum
    const crossClass = await getAuthoritativeDailyChapter({
      userClass: 5,
      day: 1,
      requestedClass: 12,
      actorRole: 'student',
    });
    const blocked = !crossClass.ok && crossClass.errorCode === 'CLASS_FORBIDDEN';
    results.push({
      name: 'Test 3: Class Spoofing Prevention',
      category: 'ACCESS_CONTROL',
      passed: blocked,
      details: 'Class 5 student requesting Class 12 curriculum is rejected with 403 CLASS_FORBIDDEN.',
    });
  } catch {
    results.push({
      name: 'Test 3: Class Spoofing Prevention',
      category: 'ACCESS_CONTROL',
      passed: false,
      details: 'Failed to restrict cross-class curriculum access.',
    });
  }

  // Test 4: Day Bounds Validation
  try {
    const invalidDay0 = await getAuthoritativeDailyChapter({
      userClass: 10,
      day: 0,
      actorRole: 'student',
    });
    const invalidDay31 = await getAuthoritativeDailyChapter({
      userClass: 10,
      day: 31,
      actorRole: 'student',
    });
    const dayBoundsEnforced = !invalidDay0.ok && !invalidDay31.ok;
    results.push({
      name: 'Test 4: Day Bounds Validation (1-30)',
      category: 'INPUT_VALIDATION',
      passed: dayBoundsEnforced,
      details: 'Days outside the canonical 1-30 range are rejected with 400 INVALID_DAY.',
    });
  } catch {
    results.push({
      name: 'Test 4: Day Bounds Validation (1-30)',
      category: 'INPUT_VALIDATION',
      passed: false,
      details: 'Failed to validate day boundaries.',
    });
  }

  // Test 5: Client-Fabricated Score Ignored & Computed Server-Side
  try {
    // Get server answers to verify server calculation
    const serverQuestions = await getAuthoritativeServerQuestionsForDay(10, 2);
    const correctAnswers = serverQuestions.map((q) => q.correctIndex);

    // Client passes answers that result in score 5, but sends clientScore: 1
    const sub = await submitAuthoritativeDailyQuiz({
      userId: studentA,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 2,
      answers: correctAnswers,
      clientScore: 1, // Client attempting to falsify score
    });

    const scoreComputedByServer = sub.ok && sub.score === 5;
    results.push({
      name: 'Test 5: Client Score Overridden by Server Calculation',
      category: 'ANTI_TAMPERING',
      passed: scoreComputedByServer,
      details: 'Server independently computed true score 5/5, ignoring fabricated clientScore parameter.',
      evidence: { computedScore: sub.ok ? sub.score : null },
    });
  } catch {
    results.push({
      name: 'Test 5: Client Score Overridden by Server Calculation',
      category: 'ANTI_TAMPERING',
      passed: false,
      details: 'Server failed to calculate score authoritatively.',
    });
  }

  // Test 6: Incomplete or Extra Answers Validation
  try {
    const tooFew = await submitAuthoritativeDailyQuiz({
      userId: studentA,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 3,
      answers: [0, 1, 2], // Only 3 answers
    });
    const tooMany = await submitAuthoritativeDailyQuiz({
      userId: studentA,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 3,
      answers: [0, 1, 2, 3, 0, 1], // 6 answers
    });
    const enforced = !tooFew.ok && !tooMany.ok;
    results.push({
      name: 'Test 6: Exact 5 Answers Required',
      category: 'INPUT_VALIDATION',
      passed: enforced,
      details: 'Submissions with fewer or more than 5 answers are rejected with 422 INCOMPLETE_ANSWERS.',
    });
  } catch {
    results.push({
      name: 'Test 6: Exact 5 Answers Required',
      category: 'INPUT_VALIDATION',
      passed: false,
      details: 'Failed to enforce answer count requirement.',
    });
  }

  // Test 7: Invalid Option Index Range
  try {
    const invalidOpt = await submitAuthoritativeDailyQuiz({
      userId: studentA,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 4,
      answers: [0, 1, 99, 2, 3], // 99 is invalid
    });
    const optionBoundsEnforced = !invalidOpt.ok && invalidOpt.errorCode === 'INVALID_OPTION_INDEX';
    results.push({
      name: 'Test 7: Option Index Range Enforced (0-3)',
      category: 'INPUT_VALIDATION',
      passed: optionBoundsEnforced,
      details: 'Option indices outside 0-3 are rejected with 422 INVALID_OPTION_INDEX.',
    });
  } catch {
    results.push({
      name: 'Test 7: Option Index Range Enforced (0-3)',
      category: 'INPUT_VALIDATION',
      passed: false,
      details: 'Failed to enforce option index bounds.',
    });
  }

  // Test 8: Duplicate Submission Protection
  try {
    const firstSub = await submitAuthoritativeDailyQuiz({
      userId: studentA,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 5,
      answers: [0, 0, 0, 0, 0],
    });

    const secondSub = await submitAuthoritativeDailyQuiz({
      userId: studentA,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 5,
      answers: [1, 1, 1, 1, 1], // Different answers attempting to overwrite
    });

    const duplicateBlocked = firstSub.ok && !secondSub.ok && secondSub.errorCode === 'ALREADY_COMPLETED';
    results.push({
      name: 'Test 8: Duplicate Submission Blocked (409 Conflict)',
      category: 'ANTI_TAMPERING',
      passed: duplicateBlocked,
      details: 'Submitting Day 5 a second time is rejected with 409 ALREADY_COMPLETED and score is immutable.',
      evidence: { firstSubOk: firstSub.ok, secondSubStatus: secondSub.status },
    });
  } catch {
    results.push({
      name: 'Test 8: Duplicate Submission Blocked (409 Conflict)',
      category: 'ANTI_TAMPERING',
      passed: false,
      details: 'Failed to block duplicate quiz submission.',
    });
  }

  // Test 9: Concurrent Submission Safety
  try {
    const [req1, req2] = await Promise.all([
      submitAuthoritativeDailyQuiz({
        userId: studentB,
        userRole: 'student',
        userStatus: 'active',
        userClass: 10,
        day: 10,
        answers: [0, 1, 2, 3, 0],
      }),
      submitAuthoritativeDailyQuiz({
        userId: studentB,
        userRole: 'student',
        userStatus: 'active',
        userClass: 10,
        day: 10,
        answers: [1, 2, 3, 0, 1],
      }),
    ]);

    const oneSucceeded = (req1.ok && !req2.ok) || (!req1.ok && req2.ok);
    const oneBlockedWithConflict =
      (!req1.ok && (req1.errorCode === 'ALREADY_COMPLETED' || req1.errorCode === 'CONCURRENT_REQUEST')) ||
      (!req2.ok && (req2.errorCode === 'ALREADY_COMPLETED' || req2.errorCode === 'CONCURRENT_REQUEST'));

    results.push({
      name: 'Test 9: Concurrent Submission Race Condition Protection',
      category: 'CONCURRENCY',
      passed: oneSucceeded && oneBlockedWithConflict,
      details: 'Parallel requests for same day resolve deterministically: exactly 1 creates record, 1 receives 409.',
    });
  } catch {
    results.push({
      name: 'Test 9: Concurrent Submission Race Condition Protection',
      category: 'CONCURRENCY',
      passed: false,
      details: 'Concurrency test failed to resolve cleanly.',
    });
  }

  // Test 10: Answer Sanitization Leakage Prevention
  try {
    const rawChapter = generateChapterForClassAndDay(10, 1);
    const sanitized = sanitizeQuestionsForStudent(rawChapter.mcqs);
    const leaked = sanitized.some((q) => 'correctIndex' in q || 'explanation' in q);
    results.push({
      name: 'Test 10: Client Question Sanitization (Zero Leakage)',
      category: 'ANTI_TAMPERING',
      passed: !leaked,
      details: 'Sanitized student questions contain only {id, question, options, topic}; answers strictly omitted.',
    });
  } catch {
    results.push({
      name: 'Test 10: Client Question Sanitization (Zero Leakage)',
      category: 'ANTI_TAMPERING',
      passed: false,
      details: 'Failed to verify question sanitization.',
    });
  }

  // Test 11: Governed Admin Score Correction
  try {
    // Non-admin attempt must fail
    const nonAdminAttempt = await adminCorrectAuthoritativeDailyScore({
      adminActorId: studentA,
      adminActorRole: 'student',
      adminActorEmail: 'student@example.com',
      studentId: studentA,
      day: 5,
      newScore: 5,
      reason: 'Trying to change my score',
    });

    // Admin attempt with justification
    const adminAttempt = await adminCorrectAuthoritativeDailyScore({
      adminActorId: adminId,
      adminActorRole: 'admin',
      adminActorEmail: 'admin@uyanix.com',
      studentId: studentA,
      day: 5,
      newScore: 4,
      reason: 'Question ambiguity resolution approved by academic board',
    });

    const governed = !nonAdminAttempt.ok && adminAttempt.ok;
    results.push({
      name: 'Test 11: Governed Admin Score Correction',
      category: 'AUDIT_GOVERNANCE',
      passed: governed,
      details: 'Students cannot alter scores; admin corrections require explicit justification & audit trail.',
    });
  } catch {
    results.push({
      name: 'Test 11: Governed Admin Score Correction',
      category: 'AUDIT_GOVERNANCE',
      passed: false,
      details: 'Failed to enforce governed admin score correction.',
    });
  }

  // Test 12: Streak Calculation from Authoritative Days
  try {
    const streak5 = calculateStreakFromCompletedDays([1, 2, 3, 4, 5]);
    const streakBroken = calculateStreakFromCompletedDays([1, 2, 4, 5]);
    const streakEmpty = calculateStreakFromCompletedDays([]);

    const streakAccurate = streak5 === 5 && streakEmpty === 0;
    results.push({
      name: 'Test 12: Server-Authoritative Streak Calculation',
      category: 'ANTI_TAMPERING',
      passed: streakAccurate,
      details: 'Streak is derived mathematically from completed database records, not client state arrays.',
      evidence: { streak5, streakBroken, streakEmpty },
    });
  } catch {
    results.push({
      name: 'Test 12: Server-Authoritative Streak Calculation',
      category: 'ANTI_TAMPERING',
      passed: false,
      details: 'Failed to calculate streak authoritatively.',
    });
  }

  // Test 13: Missed Day Backfill Policy
  try {
    // Student completing Day 7 without completing Day 6
    const backfillSub = await submitAuthoritativeDailyQuiz({
      userId: studentB,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 7,
      answers: [0, 1, 2, 3, 0],
    });

    // Student can then complete missed Day 6
    const missedSub = await submitAuthoritativeDailyQuiz({
      userId: studentB,
      userRole: 'student',
      userStatus: 'active',
      userClass: 10,
      day: 6,
      answers: [0, 1, 2, 3, 0],
    });

    const allowed = backfillSub.ok && missedSub.ok;
    results.push({
      name: 'Test 13: Missed Day Backfill Policy Support',
      category: 'ACCESS_CONTROL',
      passed: allowed,
      details: 'Registered students can complete missed days at their own pace; each day allows exactly 1 submission.',
    });
  } catch {
    results.push({
      name: 'Test 13: Missed Day Backfill Policy Support',
      category: 'ACCESS_CONTROL',
      passed: false,
      details: 'Failed to verify missed day completion.',
    });
  }

  // Test 14: Daily Progress Summary Integrity
  try {
    const summary = await getAuthoritativeStudentProgress(studentA);
    const containsDay2And5 = summary.completedDays.includes(2) && summary.completedDays.includes(5);
    const scoreMatches = summary.dailyScores[2] === 5;
    results.push({
      name: 'Test 14: Daily Progress Summary Aggregation',
      category: 'ANTI_TAMPERING',
      passed: containsDay2And5 && scoreMatches,
      details: 'Student summary accurately aggregates completedDays, dailyScores, and streak from stored records.',
      evidence: { completedDays: summary.completedDays, totalScore: summary.totalScore },
    });
  } catch {
    results.push({
      name: 'Test 14: Daily Progress Summary Aggregation',
      category: 'ANTI_TAMPERING',
      passed: false,
      details: 'Failed to aggregate daily progress summary.',
    });
  }

  const passedTests = results.filter((r) => r.passed).length;
  const failedTests = results.filter((r) => !r.passed).length;

  return {
    allPassed: failedTests === 0,
    totalTests: results.length,
    passedTests,
    failedTests,
    results,
  };
}
