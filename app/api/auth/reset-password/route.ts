import { NextRequest, NextResponse } from 'next/server';
import {
  PASSWORD_SECURITY_CONFIG,
  clearSessionCookie,
  consumePasswordResetToken,
  enforceRateLimit,
  extractSessionTokenFromRequest,
  getClientIp,
  hasForbiddenUrlTokenParams,
  revokeSessionToken,
  verifyCsrfAndCors,
} from '@/lib/server-auth';

const MAX_RESET_PAYLOAD_BYTES = 4 * 1024; // 4 KB

const ALLOWED_RESET_FIELDS = new Set([
  'token',
  'resetToken',
  'newPassword',
  'password',
  'confirmPassword',
]);

const FORBIDDEN_RESET_FIELDS = new Set([
  'userId',
  'user_id',
  'id',
  'email',
  'phone',
  'role',
  'isAdmin',
  'is_admin',
  'admin',
  'teacher',
  'status',
  'verified',
  'isVerified',
  'idVerified',
  'id_verified',
  'phoneVerified',
  'phone_verified',
  'emailVerified',
  'email_verified',
  'passwordHash',
  'passwordSalt',
  'expiresAt',
]);

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

    // Reject any query-parameter or header bypasses
    const forbiddenQueryKeys = [
      'userId',
      'user_id',
      'id',
      'email',
      'phone',
      'role',
      'bypass',
      'password',
      'newPassword',
    ];
    for (const key of forbiddenQueryKeys) {
      if (req.nextUrl.searchParams.has(key)) {
        return NextResponse.json(
          { error: 'Forbidden parameter in URL query string.' },
          { status: 403 }
        );
      }
    }

    const contentType = req.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      return NextResponse.json(
        { error: 'Content-Type must be application/json.' },
        { status: 415 }
      );
    }

    const ip = getClientIp(req);
    const rate = enforceRateLimit(
      `reset_pwd:ip:${ip}`,
      PASSWORD_SECURITY_CONFIG.RESET_MAX_PER_IP_PER_15_MINUTES,
      15 * 60 * 1000
    );
    if (!rate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many password reset verification attempts. Please wait before trying again.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(rate.retryAfterSec) },
        }
      );
    }

    const rawText = await req.text();
    if (!rawText || rawText.length > MAX_RESET_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Invalid request payload.' },
        { status: 400 }
      );
    }

    let body: unknown;
    try {
      body = JSON.parse(rawText);
    } catch {
      return NextResponse.json(
        { error: 'Malformed JSON request body.' },
        { status: 400 }
      );
    }

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return NextResponse.json(
        { error: 'Request body must be a JSON object.' },
        { status: 400 }
      );
    }

    const payload = body as Record<string, unknown>;

    // Block target userId manipulation, role manipulation, or mass-assignment fields
    for (const key of Object.keys(payload)) {
      if (FORBIDDEN_RESET_FIELDS.has(key)) {
        return NextResponse.json(
          {
            error: `Forbidden: Cannot specify "${key}" in password reset request. Target user is resolved exclusively from the verified token.`,
          },
          { status: 403 }
        );
      }
      if (!ALLOWED_RESET_FIELDS.has(key)) {
        return NextResponse.json(
          { error: `Unexpected field "${key}" in password reset payload.` },
          { status: 400 }
        );
      }
    }

    const token = payload.token ?? payload.resetToken;
    const newPassword = payload.newPassword ?? payload.password;
    const confirmPassword = payload.confirmPassword;

    if (confirmPassword === undefined) {
      return NextResponse.json(
        { error: 'Password confirmation is required.' },
        { status: 400 }
      );
    }

    const result = await consumePasswordResetToken({
      token,
      newPassword,
      confirmPassword,
    });

    if (!result.ok) {
      return NextResponse.json(
        { error: result.error },
        { status: result.status }
      );
    }

    // Revoke any existing session cookie on this browser & require clean login with new password
    const existingToken = extractSessionTokenFromRequest(req);
    if (existingToken) {
      await revokeSessionToken(existingToken);
    }

    const res = NextResponse.json({
      reset: true,
      sessionsInvalidated: true,
      message:
        'Your password has been reset successfully. Please sign in with your new password.',
    });
    clearSessionCookie(res);
    return res;
  } catch {
    return NextResponse.json(
      { error: 'Unable to complete password reset. Please try again.' },
      { status: 500 }
    );
  }
}
