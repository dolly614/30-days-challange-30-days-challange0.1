import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import { getAuthoritativeDailyChapter } from '@/lib/daily-progress-authoritative-service';

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ day: string }> }
) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  const rate = enforceRateLimit(`daily_read:${auth.user.id}`, 60, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      {
        ok: false,
        error: 'Too many requests. Please slow down.',
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

  const searchParams = req.nextUrl.searchParams;
  const requestedClassParam = searchParams.get('class');
  const requestedClass = requestedClassParam ? Number(requestedClassParam) : undefined;

  const userClass = auth.user.classNum || 12;

  // Enforce Section 10: Class-based content.
  // Student cannot spoof classNum in query params.
  const result = await getAuthoritativeDailyChapter({
    userClass,
    day: rawDay,
    requestedClass,
    actorRole: auth.user.role,
  });

  if (!result.ok) {
    return NextResponse.json(
      { ok: false, error: result.error, errorCode: result.errorCode },
      { status: result.httpStatus }
    );
  }

  return NextResponse.json(
    {
      ok: true,
      day: rawDay,
      classNum: result.chapter.classNum,
      chapter: result.chapter,
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'private, no-cache, no-store, must-revalidate',
      },
    }
  );
}
