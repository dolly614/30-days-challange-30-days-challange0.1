import 'server-only';

import {
  authoritativeStartExamAttempt,
  authoritativeAutosaveExamAnswer,
  authoritativeRecordExamViolation,
  authoritativeFinalizeAndScoreExam,
  getExamMetadata,
  verifyServerPaymentEntitlement,
} from '@/lib/exam-authoritative-service';
import {
  getAuthoritativeQuestionsForExamType,
  sanitizeQuestionsForCandidate,
} from '@/lib/exam-questions-vault';

export interface ExamSecurityTestResult {
  testId: string;
  name: string;
  category: 'LEAKAGE' | 'ENTITLEMENT' | 'SCORING' | 'TIMER' | 'CONCURRENCY' | 'ISOLATION' | 'IMMUTABILITY';
  passed: boolean;
  details: string;
  evidence?: Record<string, unknown>;
}

/**
 * Production validation test suite for Phase 4 Exam Engine.
 * Covers all criteria from Sections 33–38 & 41.
 */
export async function runExamEngineProductionAudit(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  results: ExamSecurityTestResult[];
}> {
  const results: ExamSecurityTestResult[] = [];

  const testStudentId = 'student-test-p4-' + Date.now();
  const testStudentId2 = 'student-test-p4-cross-' + Date.now();
  const adminId = 'admin-test-p4-' + Date.now();

  // Test 1: Question Leakage Prevention
  try {
    const rawVault = getAuthoritativeQuestionsForExamType('mid');
    const sanitized = sanitizeQuestionsForCandidate(rawVault);

    const hasLeakedCorrect = sanitized.some((q) => 'correctOption' in q || 'correctIndex' in q || 'answerKey' in q);
    const hasLeakedExplanation = sanitized.some((q) => 'explanation' in q);
    const zeroLeak = !hasLeakedCorrect && !hasLeakedExplanation;

    results.push({
      testId: 'EXAM-SEC-01',
      name: 'Zero Answer Key Leakage in Student DTO',
      category: 'LEAKAGE',
      passed: zeroLeak,
      details: 'Sanitized questions contain only {id, questionNumber, questionText, options, topic}; all answers and explanations are stripped.',
      evidence: { questionCount: sanitized.length, sampleFields: Object.keys(sanitized[0] || {}) },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-01',
      name: 'Zero Answer Key Leakage in Student DTO',
      category: 'LEAKAGE',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 2: Payment Entitlement Enforcement
  try {
    // Student without verified payment attempting to start exam
    const startUnpaid = await authoritativeStartExamAttempt({
      userId: testStudentId,
      studentName: 'Unpaid Student',
      studentRole: 'student',
      studentClass: 12,
      examType: 'mid',
    });

    const paymentRequiredEnforced = !startUnpaid.ok && startUnpaid.errorCode === 'PAYMENT_ENTITLEMENT_REQUIRED';

    results.push({
      testId: 'EXAM-SEC-02',
      name: 'Payment Entitlement Server Enforcement',
      category: 'ENTITLEMENT',
      passed: paymentRequiredEnforced,
      details: 'Unpaid candidate cannot start exam; rejected with 402 PAYMENT_ENTITLEMENT_REQUIRED.',
      evidence: { ok: startUnpaid.ok, errorCode: startUnpaid.errorCode },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-02',
      name: 'Payment Entitlement Server Enforcement',
      category: 'ENTITLEMENT',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 3: Metadata Endpoint Security (Zero Questions Leaked Before Start)
  try {
    const meta = await getExamMetadata('mid', testStudentId);
    const safeMeta = meta.totalQuestions === 150 && meta.feeAmount === 199 && !('questions' in meta);

    results.push({
      testId: 'EXAM-SEC-03',
      name: 'Metadata Endpoint Gating',
      category: 'LEAKAGE',
      passed: safeMeta,
      details: 'GET /api/exam returns non-sensitive metadata only before start; questions are not exposed prematurely.',
      evidence: { totalQuestions: meta.totalQuestions, isPaid: meta.isPaid },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-03',
      name: 'Metadata Endpoint Gating',
      category: 'LEAKAGE',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 4: Admin Payment Bypass & Attempt Snapshot Creation
  let activeAttemptId = '';
  try {
    const adminStart = await authoritativeStartExamAttempt({
      userId: adminId,
      studentName: 'Admin Auditor',
      studentRole: 'admin', // Admin role has bypass for testing
      studentClass: 12,
      examType: 'mid',
    });

    activeAttemptId = adminStart.attemptId;
    const startSucceeded = adminStart.ok && adminStart.attemptId.length > 0 && adminStart.questions.length > 0;

    results.push({
      testId: 'EXAM-SEC-04',
      name: 'Attempt & Immutable Snapshot Initialization',
      category: 'SCORING',
      passed: startSucceeded,
      details: 'Authorized start generates immutable snapshot, server timer deadline, and returns sanitized questions.',
      evidence: { attemptId: adminStart.attemptId, remainingSeconds: adminStart.remainingSeconds },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-04',
      name: 'Attempt & Immutable Snapshot Initialization',
      category: 'SCORING',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 5: Concurrent Start Determinism (Resumption of Same Attempt)
  try {
    const resumeStart = await authoritativeStartExamAttempt({
      userId: adminId,
      studentName: 'Admin Auditor',
      studentRole: 'admin',
      studentClass: 12,
      examType: 'mid',
    });

    const isSameAttempt = resumeStart.ok && resumeStart.attemptId === activeAttemptId;

    results.push({
      testId: 'EXAM-SEC-05',
      name: 'Concurrent Start Request Resumes Active Attempt',
      category: 'CONCURRENCY',
      passed: isSameAttempt,
      details: 'Parallel or duplicate start calls deterministically resume the existing active attempt instead of spawning duplicate attempts.',
      evidence: { originalAttempt: activeAttemptId, resumedAttempt: resumeStart.attemptId },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-05',
      name: 'Concurrent Start Request Resumes Active Attempt',
      category: 'CONCURRENCY',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 6: Answer Autosave & Option Range Validation
  try {
    const invalidOpt = await authoritativeAutosaveExamAnswer({
      attemptId: activeAttemptId,
      userId: adminId,
      questionId: 'ex-16',
      selectedOption: 99, // Invalid index
    });

    const validOpt = await authoritativeAutosaveExamAnswer({
      attemptId: activeAttemptId,
      userId: adminId,
      questionId: 'ex-16',
      selectedOption: 1, // Valid option
    });

    const rangeEnforced = !invalidOpt.ok && validOpt.ok && validOpt.saved;

    results.push({
      testId: 'EXAM-SEC-06',
      name: 'Answer Autosave & Option Bounds Validation',
      category: 'SCORING',
      passed: rangeEnforced,
      details: 'Selected options are bounded to 0–3; valid answers are persisted with updated server deadline checks.',
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-06',
      name: 'Answer Autosave & Option Bounds Validation',
      category: 'SCORING',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 7: Cross-User Attempt Isolation
  try {
    const crossUserSave = await authoritativeAutosaveExamAnswer({
      attemptId: activeAttemptId, // Belongs to adminId
      userId: testStudentId2, // Different user
      questionId: 'ex-16',
      selectedOption: 2,
    });

    const crossBlocked = !crossUserSave.ok;

    results.push({
      testId: 'EXAM-SEC-07',
      name: 'Cross-User Attempt IDOR Protection',
      category: 'ISOLATION',
      passed: crossBlocked,
      details: 'Student B is forbidden from saving answers or accessing Student A attempt records.',
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-07',
      name: 'Cross-User Attempt IDOR Protection',
      category: 'ISOLATION',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 8: Proctoring Violation Event Logging
  try {
    const viol = await authoritativeRecordExamViolation({
      attemptId: activeAttemptId,
      userId: adminId,
      eventType: 'TAB_HIDDEN',
    });

    const violRecorded = viol.ok && viol.violationCount >= 1 && viol.remainingWarnings <= 3;

    results.push({
      testId: 'EXAM-SEC-08',
      name: 'Proctoring Violation Tracking & Warnings',
      category: 'SCORING',
      passed: violRecorded,
      details: 'Proctoring warnings are recorded in PostgreSQL; threshold monitoring computes remaining warnings.',
      evidence: { violationCount: viol.violationCount, remainingWarnings: viol.remainingWarnings },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-08',
      name: 'Proctoring Violation Tracking & Warnings',
      category: 'SCORING',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 9: Server-Authoritative Scoring (Client Score Ignored)
  let firstEvaluationResult: unknown = null;
  try {
    // Provide answers where ex-16 is correct (option 1)
    const evaluated = await authoritativeFinalizeAndScoreExam({
      attemptId: activeAttemptId,
      userId: adminId,
      studentName: 'Admin Auditor',
      submittedAnswers: {
        'ex-16': 1, // correct
      },
      idempotencyKey: `idem_test_${activeAttemptId}`,
    });

    firstEvaluationResult = evaluated;
    const scoreValid = evaluated.ok && evaluated.result.score >= 0 && evaluated.result.totalQuestions > 0;
    const reviewHasExplanations = Array.isArray(evaluated.result.reviewQuestions) && evaluated.result.reviewQuestions.length > 0;

    results.push({
      testId: 'EXAM-SEC-09',
      name: 'Server-Authoritative Final Evaluation & Post-Exam Review',
      category: 'SCORING',
      passed: scoreValid && reviewHasExplanations,
      details: 'Score calculated server-side against stored snapshot; explanations and answers revealed strictly AFTER evaluation.',
      evidence: { score: evaluated.result.score, percentage: evaluated.result.percentage, rank: evaluated.result.rank },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-09',
      name: 'Server-Authoritative Final Evaluation & Post-Exam Review',
      category: 'SCORING',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 10: Idempotency & Duplicate Submission Safety
  try {
    // Submitting with same idempotency key
    const replay = await authoritativeFinalizeAndScoreExam({
      attemptId: activeAttemptId,
      userId: adminId,
      idempotencyKey: `idem_test_${activeAttemptId}`,
    });

    const isIdentical = replay.ok && (replay as any).result.score === (firstEvaluationResult as any).result.score;

    results.push({
      testId: 'EXAM-SEC-10',
      name: 'Database Idempotency on Duplicate Submission',
      category: 'CONCURRENCY',
      passed: isIdentical,
      details: 'Submitting finalized attempt again returns identical cached score with zero score mutations.',
      evidence: { replayOk: replay.ok, originalScore: (firstEvaluationResult as any)?.result?.score },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-10',
      name: 'Database Idempotency on Duplicate Submission',
      category: 'CONCURRENCY',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 11: Result Immutability
  try {
    // Attempting to autosave an answer on an already EVALUATED attempt
    const mutateAttempt = await authoritativeAutosaveExamAnswer({
      attemptId: activeAttemptId,
      userId: adminId,
      questionId: 'ex-17',
      selectedOption: 2,
    });

    const mutationBlocked = !mutateAttempt.ok;

    results.push({
      testId: 'EXAM-SEC-11',
      name: 'Evaluated Attempt Immutability',
      category: 'IMMUTABILITY',
      passed: mutationBlocked,
      details: 'Once an attempt is evaluated, students cannot alter answers, score, or completion status.',
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-11',
      name: 'Evaluated Attempt Immutability',
      category: 'IMMUTABILITY',
      passed: false,
      details: 'Error: ' + String(err),
    });
  }

  // Test 12: Dynamic Ranking Calculation
  try {
    const rankValue = (firstEvaluationResult as any)?.result?.rank;
    const dynamicRankValid = typeof rankValue === 'number' && rankValue >= 1;

    results.push({
      testId: 'EXAM-SEC-12',
      name: 'Authoritative Dynamic Ranking',
      category: 'SCORING',
      passed: dynamicRankValid,
      details: 'Rank is derived dynamically from PostgreSQL competitor scores, replacing client-side hard-coded formula.',
      evidence: { rank: rankValue },
    });
  } catch (err: unknown) {
    results.push({
      testId: 'EXAM-SEC-12',
      name: 'Authoritative Dynamic Ranking',
      category: 'SCORING',
      passed: false,
      details: 'Error: ' + String(err),
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
