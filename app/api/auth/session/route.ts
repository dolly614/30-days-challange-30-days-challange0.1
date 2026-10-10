import { NextRequest, NextResponse } from 'next/server';
import {
  clearSessionCookie,
  extractSessionTokenFromRequest,
  getAuthenticatedUser,
  getAuthoritativeUser,
  getUserPhoneVerificationStatus,
  hasForbiddenUrlTokenParams,
  rotateSessionToken,
  setSessionCookie,
  verifyCsrfAndCors,
} from '@/lib/server-auth';

export async function GET(req: NextRequest) {
  const corsCheck = verifyCsrfAndCors(req);
  if (!corsCheck.ok) {
    return corsCheck.response;
  }

  if (hasForbiddenUrlTokenParams(req)) {
    const res = NextResponse.json(
      {
        authenticated: false,
        phoneVerified: false,
        user: null,
        error: 'Session tokens are not permitted in URL parameters.',
      },
      { status: 401, headers: { 'Cache-Control': 'no-store' } }
    );
    clearSessionCookie(res);
    return res;
  }

  const auth = await getAuthoritativeUser(req);
  if (!auth) {
    const res = NextResponse.json(
      { authenticated: false, phoneVerified: false, user: null },
      { status: 401, headers: { 'Cache-Control': 'no-store' } }
    );
    clearSessionCookie(res);
    return res;
  }

  const token = extractSessionTokenFromRequest(req);
  return NextResponse.json(
    {
      authenticated: true,
      phoneVerified: getUserPhoneVerificationStatus(auth.user.id),
      user: auth.user,
      token,
    },
    { headers: { 'Cache-Control': 'no-store' } }
  );
}

/**
 * Explicit session refresh / rotation endpoint (SESSION_REFRESH_ROTATION = true).
 * Invalidates the previous session credential and issues a rotated credential in the same session family.
 */
export async function POST(req: NextRequest) {
  const csrfCorsCheck = verifyCsrfAndCors(req);
  if (!csrfCorsCheck.ok) {
    return csrfCorsCheck.response;
  }

  if (hasForbiddenUrlTokenParams(req)) {
    const res = NextResponse.json(
      {
        authenticated: false,
        error: 'Session tokens are not permitted in URL parameters.',
      },
      { status: 401, headers: { 'Cache-Control': 'no-store' } }
    );
    clearSessionCookie(res);
    return res;
  }

  const currentToken = extractSessionTokenFromRequest(req);
  const rotated = await rotateSessionToken(currentToken);
  if (!rotated.ok) {
    const res = NextResponse.json(
      { authenticated: false, phoneVerified: false, user: null, error: rotated.error },
      { status: 401, headers: { 'Cache-Control': 'no-store' } }
    );
    clearSessionCookie(res);
    return res;
  }

  const res = NextResponse.json(
    {
      authenticated: true,
      rotated: true,
      phoneVerified: getUserPhoneVerificationStatus(rotated.user.id),
      user: rotated.user,
    },
    { headers: { 'Cache-Control': 'no-store' } }
  );
  setSessionCookie(res, rotated.token);
  return res;
}

