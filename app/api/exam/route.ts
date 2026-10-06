import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import {
  authoritativeStartExamAttempt,
  authoritativeAutosaveExamAnswer,
  authoritativeRecordExamViolation,
  authoritativeFinalizeAndScoreExam,
  getExamMetadata,
} from '@/lib/exam-authoritative-service';
import {
  executeControlledAdminExamResultCorrection,
} from '@/lib/exam-engine-governance';

export async function GET(req: NextRequest) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  const rate = enforceRateLimit(`exam_read:${auth.user.id}`, 60, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Rate limit exceeded.', errorCode: 'RATE_LIMITED' },
      { status: 429 }
    );
  }

  const examType =
    req.nextUrl.searchParams.get('type') === 'final' ? 'final' : 'mid';

  // Section 16: Return non-sensitive metadata before start.
  // Only return questions if student has a valid active attempt!
  const meta = await getExamMetadata(examType, auth.user.id);

  if (meta.activeAttempt && meta.isPaid) {
    // Resume active attempt
    const resumed = await authoritativeStartExamAttempt({
      userId: auth.user.id,
      studentName: auth.user.name || 'Student Champion',
      studentRole: auth.user.role,
      studentClass: auth.user.classNum || 12,
      examType,
    });

    if (resumed.ok) {
      return NextResponse.json(
        {
          ok: true,
          examType,
          isPaid: meta.isPaid,
          hasActiveAttempt: true,
          attemptId: resumed.attemptId,
          remainingSeconds: resumed.remainingSeconds,
          deadlineMs: resumed.deadlineMs,
          questions: resumed.questions,
          metadata: meta,
        },
        {
          status: 200,
          headers: { 'Cache-Control': 'no-store, private' },
        }
      );
    }
  }

  // Before starting attempt or before paying: return metadata only with zero questions
  return NextResponse.json(
    {
      ok: true,
      examType,
      isPaid: meta.isPaid,
      hasActiveAttempt: false,
      questions: [],
      metadata: meta,
    },
    {
      status: 200,
      headers: { 'Cache-Control': 'no-store, private' },
    }
  );
}

export async function POST(req: NextRequest) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  const rate = enforceRateLimit(`exam_mut:${auth.user.id}`, 120, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Rate limit exceeded.', errorCode: 'RATE_LIMITED' },
      { status: 429 }
    );
  }

  try {
    const body = await req.json();
    const action = typeof body?.action === 'string' ? body.action : 'SUBMIT_ATTEMPT';
    const examType: 'mid' | 'final' =
      body?.examType === 'final' ? 'final' : 'mid';

    // 1. START OR RESUME ATTEMPT
    if (action === 'START_ATTEMPT') {
      const started = await authoritativeStartExamAttempt({
        userId: auth.user.id,
        studentName: auth.user.name || 'Student Champion',
        studentRole: auth.user.role,
        studentClass: auth.user.classNum || 12,
        examType,
      });

      if (!started.ok) {
        return NextResponse.json(
          { error: started.error, errorCode: started.errorCode },
          { status: started.errorCode === 'PAYMENT_ENTITLEMENT_REQUIRED' ? 402 : 400 }
        );
      }

      return NextResponse.json(started, { status: 200 });
    }

    // 2. AUTOSAVE SINGLE ANSWER
    if (action === 'AUTOSAVE_ANSWER') {
      const saved = await authoritativeAutosaveExamAnswer({
        attemptId: String(body?.attemptId || ''),
        userId: auth.user.id,
        questionId: String(body?.questionId || ''),
        selectedOption: Number(body?.selectedOption),
      });

      if (!saved.ok) {
        return NextResponse.json(
          { error: saved.error, errorCode: 'AUTOSAVE_FAILED' },
          { status: 400 }
        );
      }

      return NextResponse.json(saved, { status: 200 });
    }

    // 3. PROCTORING VIOLATION RECORDING
    if (action === 'RECORD_VIOLATION') {
      const recorded = await authoritativeRecordExamViolation({
        attemptId: String(body?.attemptId || ''),
        userId: auth.user.id,
        eventType: String(body?.eventType || 'TAB_HIDDEN'),
        metadata:
          body?.metadata && typeof body.metadata === 'object'
            ? body.metadata
            : {},
        requestId: req.headers.get('x-request-id') || undefined,
      });

      return NextResponse.json(recorded, { status: 200 });
    }

    // 4. ADMIN CORRECTION OF RESULT
    if (action === 'ADMIN_CORRECT_RESULT') {
      const corrected = executeControlledAdminExamResultCorrection({
        attemptId: String(body?.attemptId || ''),
        actorId: auth.user.id,
        actorRole: auth.user.role,
        correctedScore: Number(body?.correctedScore),
        reason: String(body?.reason || ''),
      });

      if (!corrected.ok) {
        return NextResponse.json(
          { error: corrected.reason, errorCode: corrected.errorCode },
          { status: corrected.httpStatus }
        );
      }

      return NextResponse.json(corrected, { status: 200 });
    }

    // 5. SUBMIT ATTEMPT OR AUTO_SUBMIT (Server-authoritative scoring; ignores client score/total/rank)
    let attemptId = String(body?.attemptId || '');
    if (!attemptId) {
      const autoStart = await authoritativeStartExamAttempt({
        userId: auth.user.id,
        studentName: auth.user.name || 'Student Champion',
        studentRole: auth.user.role,
        studentClass: auth.user.classNum || 12,
        examType,
      });
      if (!autoStart.ok) {
        return NextResponse.json(
          { error: autoStart.error, errorCode: autoStart.errorCode },
          { status: autoStart.errorCode === 'PAYMENT_ENTITLEMENT_REQUIRED' ? 402 : 400 }
        );
      }
      attemptId = autoStart.attemptId;
    }

    const idempotencyKey =
      req.headers.get('idempotency-key') ||
      req.headers.get('x-idempotency-key') ||
      (typeof body?.idempotencyKey === 'string' ? body.idempotencyKey : undefined);

    const isAutoSubmit = action === 'AUTO_SUBMIT' || body?.autoSubmittedDueToTimer === true;

    const finalized = await authoritativeFinalizeAndScoreExam({
      attemptId,
      userId: auth.user.id,
      studentName: auth.user.name || 'Student Champion',
      studentSchool: auth.user.school || 'Delhi Public School',
      studentClass: auth.user.classNum || 12,
      submittedAnswers:
        body?.answers && typeof body.answers === 'object' ? body.answers : {},
      idempotencyKey,
      autoSubmittedDueToTimer: isAutoSubmit,
    });

    if (!finalized.ok) {
      return NextResponse.json(
        { error: finalized.error, errorCode: 'SUBMIT_FAILED' },
        { status: 400 }
      );
    }

    return NextResponse.json(finalized, { status: 200 });
  } catch {
    return NextResponse.json(
      { error: 'Invalid exam request payload.' },
      { status: 400 }
    );
  }
}
