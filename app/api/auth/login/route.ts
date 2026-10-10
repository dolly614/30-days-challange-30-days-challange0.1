import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import {
  authenticateWithPassword,
  enforceDistributedRateLimit,
  extractSessionTokenFromRequest,
  getClientIp,
  hasForbiddenUrlTokenParams,
  setSessionCookie,
  signSessionToken,
  verifyCsrfAndCors,
} from '@/lib/server-auth';

const loginSchema = z.object({
  identifier: z.string().trim().min(3).max(160),
  password: z.string().min(1).max(128),
});

export async function POST(req: NextRequest) {
  try {
    const csrfCorsCheck = verifyCsrfAndCors(req);
    if (!csrfCorsCheck.ok) {
      return csrfCorsCheck.response;
    }

    if (hasForbiddenUrlTokenParams(req)) {
      return NextResponse.json(
        { error: 'Authentication tokens are not permitted in URL parameters.' },
        { status: 400 }
      );
    }

    const ip = getClientIp(req);
    const ipRate = await enforceDistributedRateLimit(`login:ip:${ip}`, 10, 15 * 60 * 1000);
    if (!ipRate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many login attempts. Please wait before trying again.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(ipRate.retryAfterSec) },
        }
      );
    }

    const rawBody = await req.json();
    const parsed = loginSchema.safeParse(rawBody);
    if (!parsed.success) {
      return NextResponse.json(
        { error: 'Invalid email/mobile or password.' },
        { status: 400 }
      );
    }

    const idRate = await enforceDistributedRateLimit(
      `login:id:${parsed.data.identifier.toLowerCase()}`,
      8,
      15 * 60 * 1000
    );
    if (!idRate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many failed login attempts for this account. Please try again later.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(idRate.retryAfterSec) },
        }
      );
    }

    const result = await authenticateWithPassword(
      parsed.data.identifier,
      parsed.data.password
    );

    if (!result.ok) {
      return NextResponse.json(
        { error: result.error },
        { status: result.status }
      );
    }

    // AUTH-06 #14: Revoke any pre-existing session token before issuing new authenticated session
    const preExistingToken = extractSessionTokenFromRequest(req);
    const token = signSessionToken(result.user, { preExistingToken });
    const res = NextResponse.json({
      authenticated: true,
      user: result.user,
      token,
    });
    setSessionCookie(res, token);
    return res;
  } catch {
    return NextResponse.json(
      { error: 'Authentication service error. Please try again.' },
      { status: 500 }
    );
  }
}
