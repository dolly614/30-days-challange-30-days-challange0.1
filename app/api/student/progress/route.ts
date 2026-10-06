import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import { getAuthoritativeStudentProgress } from '@/lib/daily-progress-authoritative-service';

export async function GET(req: NextRequest) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  const rate = enforceRateLimit(`student_progress:${auth.user.id}`, 60, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      {
        ok: false,
        error: 'Too many requests. Please wait a moment.',
        errorCode: 'RATE_LIMITED',
      },
      { status: 429 }
    );
  }

  // Section 18: Prevent cross-user access.
  // ALWAYS derive user identity from secure session cookie, NEVER from request params/body.
  const progress = await getAuthoritativeStudentProgress(auth.user.id);

  return NextResponse.json(
    {
      ok: true,
      progress,
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'private, no-cache, no-store, must-revalidate',
      },
    }
  );
}
