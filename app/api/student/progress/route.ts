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

  // Server-side check: Students must possess a valid Registration ID to access progress & dashboard
  if (auth.user.role === 'student' && !auth.user.registrationId) {
    return NextResponse.json(
      {
        ok: false,
        error:
          'Registration ID anivarya hai (e.g. OEC2609535). Bina Registration ID ke student progress access nahi kiya ja sakta.',
        errorCode: 'REGISTRATION_ID_REQUIRED',
        requiresRegistrationId: true,
      },
      { status: 403 }
    );
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
