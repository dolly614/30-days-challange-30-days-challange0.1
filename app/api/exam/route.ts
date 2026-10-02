import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import {
  executeControlledAdminExamResultCorrection,
  finalizeAndScoreServerExamAttempt,
  getSanitizedQuestionsForClient,
  hasServerExamPaymentEntitlement,
  recordExamViolationEvent,
  saveExamAttemptAnswer,
  startOrResumeServerExamAttempt,
} from '@/lib/exam-engine-governance';
import { checkAuthoritativeExamEntitlement } from '@/lib/payment-financial-governance';

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

  // Return sanitized questions ONLY (no correctIndex, correctAnswer, or explanation before submission)
  return NextResponse.json(
    {
      examType,
      questions: getSanitizedQuestionsForClient(),
    },
    { status: 200 }
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

    if (action === 'START_ATTEMPT') {
      const hasEntitlement =
        checkAuthoritativeExamEntitlement({
          userId: auth.user.id,
          examType,
        }).hasActiveEntitlement ||
        hasServerExamPaymentEntitlement(auth.user.id, examType);

      if (!hasEntitlement && auth.user.role !== 'admin') {
        return NextResponse.json(
          {
            error:
              'Verified server-side payment entitlement is required before starting this exam.',
            errorCode: 'PAYMENT_ENTITLEMENT_REQUIRED',
          },
          { status: 402 }
        );
      }

      const started = startOrResumeServerExamAttempt({
        studentId: auth.user.id,
        actorRole: auth.user.role,
        studentClass: auth.user.classNum || 12,
        examType,
        requirePaymentEntitlement: auth.user.role !== 'admin',
      });

      if (!started.ok) {
        return NextResponse.json(
          { error: started.reason, errorCode: started.errorCode },
          { status: started.httpStatus }
        );
      }

      return NextResponse.json(started, { status: started.httpStatus });
    }

    if (action === 'AUTOSAVE_ANSWER') {
      const saved = saveExamAttemptAnswer({
        attemptId: String(body?.attemptId || ''),
        studentId: auth.user.id,
        questionId: String(body?.questionId || ''),
        selectedOption: Number(body?.selectedOption),
      });

      if (!saved.ok) {
        return NextResponse.json(
          { error: saved.reason, errorCode: saved.errorCode },
          { status: saved.httpStatus }
        );
      }

      return NextResponse.json(saved, { status: 200 });
    }

    if (action === 'RECORD_VIOLATION') {
      const recorded = recordExamViolationEvent({
        attemptId: String(body?.attemptId || ''),
        studentId: auth.user.id,
        eventType: String(body?.eventType || ''),
        metadata:
          body?.metadata && typeof body.metadata === 'object'
            ? body.metadata
            : {},
      });

      if (!recorded.ok) {
        return NextResponse.json(
          { error: recorded.reason, errorCode: recorded.errorCode },
          { status: recorded.httpStatus }
        );
      }

      return NextResponse.json(recorded, { status: 200 });
    }

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

    // Default: SUBMIT_ATTEMPT (Server-authoritative scoring; ignores client score/total/rank)
    let attemptId = String(body?.attemptId || '');
    if (!attemptId) {
      const hasEntitlement =
        checkAuthoritativeExamEntitlement({
          userId: auth.user.id,
          examType,
        }).hasActiveEntitlement ||
        hasServerExamPaymentEntitlement(auth.user.id, examType);

      if (!hasEntitlement && auth.user.role !== 'admin') {
        return NextResponse.json(
          {
            error:
              'Verified server-side payment entitlement is required to submit an exam attempt.',
            errorCode: 'PAYMENT_ENTITLEMENT_REQUIRED',
          },
          { status: 402 }
        );
      }

      const autoStart = startOrResumeServerExamAttempt({
        studentId: auth.user.id,
        actorRole: auth.user.role,
        studentClass: auth.user.classNum || 12,
        examType,
        requirePaymentEntitlement: auth.user.role !== 'admin',
      });
      if (!autoStart.ok) {
        return NextResponse.json(
          { error: autoStart.reason, errorCode: autoStart.errorCode },
          { status: autoStart.httpStatus }
        );
      }
      attemptId = autoStart.attemptId;
    }

    const idempotencyKey =
      req.headers.get('idempotency-key') ||
      (typeof body?.idempotencyKey === 'string' ? body.idempotencyKey : undefined);

    const finalized = finalizeAndScoreServerExamAttempt({
      attemptId,
      actorId: auth.user.id,
      actorRole: auth.user.role,
      submittedAnswers:
        body?.answers && typeof body.answers === 'object' ? body.answers : {},
      idempotencyKey,
    });

    if (!finalized.ok) {
      return NextResponse.json(
        { error: finalized.reason, errorCode: finalized.errorCode },
        { status: finalized.httpStatus }
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
