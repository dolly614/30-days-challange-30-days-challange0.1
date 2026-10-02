import { NextRequest, NextResponse } from 'next/server';
import {
  PASSWORD_SECURITY_CONFIG,
  changeAuthenticatedUserPassword,
  enforceRateLimit,
  getClientIp,
  requireAuthenticatedUser,
  setSessionCookie,
} from '@/lib/server-auth';

const MAX_CHANGE_PASSWORD_BYTES = 4 * 1024; // 4 KB

const ALLOWED_CHANGE_PASSWORD_FIELDS = new Set([
  'currentPassword',
  'newPassword',
  'confirmPassword',
]);

const FORBIDDEN_CHANGE_PASSWORD_FIELDS = new Set([
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
  'idVerified',
  'id_verified',
  'phoneVerified',
  'phone_verified',
  'emailVerified',
  'email_verified',
  'passwordHash',
  'passwordSalt',
]);

export async function POST(req: NextRequest) {
  try {
    // 1. Require valid authenticated server session
    const auth = requireAuthenticatedUser(req);
    if (!auth.ok) {
      return auth.response;
    }

    const contentType = req.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      return NextResponse.json(
        { error: 'Content-Type must be application/json.' },
        { status: 415 }
      );
    }

    // 2. Rate limit per authenticated account and per IP
    const ip = getClientIp(req);
    const ipRate = enforceRateLimit(
      `chg_pwd:ip:${ip}`,
      PASSWORD_SECURITY_CONFIG.CHANGE_PASSWORD_MAX_ATTEMPTS_PER_15_MINUTES * 2,
      15 * 60 * 1000
    );
    if (!ipRate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many password change attempts. Please wait before trying again.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(ipRate.retryAfterSec) },
        }
      );
    }

    const userRate = enforceRateLimit(
      `chg_pwd:user:${auth.user.id}`,
      PASSWORD_SECURITY_CONFIG.CHANGE_PASSWORD_MAX_ATTEMPTS_PER_15_MINUTES,
      15 * 60 * 1000
    );
    if (!userRate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many password change attempts for this account. Please try again later.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(userRate.retryAfterSec) },
        }
      );
    }

    const rawText = await req.text();
    if (!rawText || rawText.length > MAX_CHANGE_PASSWORD_BYTES) {
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

    for (const key of Object.keys(payload)) {
      if (FORBIDDEN_CHANGE_PASSWORD_FIELDS.has(key)) {
        return NextResponse.json(
          {
            error: `Forbidden: Cannot override "${key}" during password change.`,
          },
          { status: 403 }
        );
      }
      if (!ALLOWED_CHANGE_PASSWORD_FIELDS.has(key)) {
        return NextResponse.json(
          { error: `Unexpected field "${key}" in password change request.` },
          { status: 400 }
        );
      }
    }

    if (payload.confirmPassword === undefined) {
      return NextResponse.json(
        { error: 'Password confirmation is required.' },
        { status: 400 }
      );
    }

    const result = changeAuthenticatedUserPassword({
      authenticatedUserId: auth.user.id,
      currentSessionJti: auth.session.jti,
      currentSessionExp: auth.session.exp,
      currentPassword: payload.currentPassword,
      newPassword: payload.newPassword,
      confirmPassword: payload.confirmPassword,
    });

    if (!result.ok) {
      return NextResponse.json(
        { error: result.error },
        { status: result.status }
      );
    }

    const res = NextResponse.json({
      changed: true,
      sessionRotated: true,
      user: result.user,
      message: 'Your password has been updated and your session has been rotated.',
    });
    setSessionCookie(res, result.rotatedSessionToken);
    return res;
  } catch {
    return NextResponse.json(
      { error: 'Unable to update password. Please try again.' },
      { status: 500 }
    );
  }
}
