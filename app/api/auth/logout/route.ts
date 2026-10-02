import { NextRequest, NextResponse } from 'next/server';
import {
  clearOtpBindingCookie,
  clearSessionCookie,
  extractSessionTokenFromRequest,
  getAuthenticatedUser,
  revokeAllUserSessions,
  revokeSessionToken,
  verifyCsrfAndCors,
} from '@/lib/server-auth';

export async function POST(req: NextRequest) {
  const csrfCorsCheck = verifyCsrfAndCors(req);
  if (!csrfCorsCheck.ok) {
    return csrfCorsCheck.response;
  }

  let logoutAllSessions = false;
  try {
    const rawText = await req.text();
    if (rawText) {
      const parsed = JSON.parse(rawText) as { allSessions?: boolean };
      logoutAllSessions = parsed?.allSessions === true;
    }
  } catch {
    // Proceed with single-session revocation even if request body is empty
  }

  const auth = getAuthenticatedUser(req, { touchActivity: false });
  const token = extractSessionTokenFromRequest(req);

  if (logoutAllSessions && auth) {
    revokeAllUserSessions(auth.user.id, { reason: 'user_logout_all_sessions' });
  } else if (token) {
    revokeSessionToken(token, 'user_logout');
  }

  const res = NextResponse.json(
    {
      authenticated: false,
      loggedOut: true,
    },
    { headers: { 'Cache-Control': 'no-store' } }
  );
  clearSessionCookie(res);
  clearOtpBindingCookie(res);
  return res;
}

