import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import { submitAuthoritativeDailyQuiz } from '@/lib/daily-progress-authoritative-service';

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ day: string }> }
) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  // Rate limit: 30 submissions per minute per student
  const rate = enforceRateLimit(`daily_submit:${auth.user.id}`, 30, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      {
        ok: false,
        error: 'Too many requests. Please wait before submitting again.',
        errorCode: 'RATE_LIMITED',
      },
      { status: 429 }
    );
  }

  const resolvedParams = await params;
  const rawDay = Number(resolvedParams?.day);
  if (!Number.isInteger(rawDay) || rawDay < 1 || rawDay > 30) {
    return NextResponse.json(
      {
        ok: false,
        error: `Invalid day parameter: '${resolvedParams?.day}'. Day must be an integer between 1 and 30.`,
        errorCode: 'INVALID_DAY',
      },
      { status: 400 }
    );
  }

  try {
    const body = await req.json();

    const answers = body?.answers;
    if (!Array.isArray(answers)) {
      return NextResponse.json(
        {
          ok: false,
          error: 'Missing required field: answers must be an array of option indices.',
          errorCode: 'INVALID_INPUT',
        },
        { status: 400 }
      );
    }

    if (answers.length !== 5) {
      return NextResponse.json(
        {
          ok: false,
          error: `Exactly 5 answers are required. Received ${answers.length}.`,
          errorCode: 'INCOMPLETE_ANSWERS',
        },
        { status: 422 }
      );
    }

    // Check bounds of option indices
    for (let i = 0; i < answers.length; i++) {
      const idx = answers[i];
      if (!Number.isInteger(idx) || idx < 0 || idx > 3) {
        return NextResponse.json(
          {
            ok: false,
            error: `Invalid answer for Question ${i + 1}: Value ${idx} is outside allowed range (0–3).`,
            errorCode: 'VALIDATION_ERROR',
          },
          { status: 422 }
        );
      }
    }

    const requestId =
      req.headers.get('x-request-id') ||
      req.headers.get('request-id') ||
      `req_${Date.now()}`;
    const idempotencyKey =
      req.headers.get('idempotency-key') ||
      req.headers.get('x-idempotency-key') ||
      (typeof body?.idempotencyKey === 'string' ? body.idempotencyKey : undefined);

    // Call server-authoritative submission logic.
    // Client-supplied score (if any) is completely ignored/discarded!
    const result = await submitAuthoritativeDailyQuiz({
      userId: auth.user.id,
      userRole: auth.user.role,
      userStatus: 'active',
      userClass: auth.user.classNum || 12,
      day: rawDay,
      answers,
      clientScore: body?.score, // Passed for auditing/anti-cheat validation only
      attemptId: typeof body?.attemptId === 'string' ? body.attemptId : undefined,
      requestId,
      idempotencyKey,
    });

    if (!result.ok) {
      return NextResponse.json(result, { status: result.httpStatus });
    }

    return NextResponse.json(result, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Invalid JSON payload';
    return NextResponse.json(
      {
        ok: false,
        error: `Failed to process daily quiz submission: ${msg}`,
        errorCode: 'INVALID_REQUEST',
      },
      { status: 400 }
    );
  }
}
