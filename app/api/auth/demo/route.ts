import { NextRequest, NextResponse } from 'next/server';
import { enforceRateLimit, getClientIp } from '@/lib/server-auth';

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rate = enforceRateLimit(`demo:${ip}`, 10, 15 * 60 * 1000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many requests.' },
      { status: 429 }
    );
  }

  // Demo login bypass is strictly disabled to prevent unauthenticated privilege escalation
  return NextResponse.json(
    {
      error:
        'Quick Demo login is disabled for security. Please sign in with your registered password, OTP, or Google account.',
    },
    { status: 403 }
  );
}
