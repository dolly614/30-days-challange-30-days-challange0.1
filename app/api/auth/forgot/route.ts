import { NextRequest, NextResponse } from 'next/server';
import {
  PASSWORD_SECURITY_CONFIG,
  createPasswordResetRequest,
  enforceRateLimit,
  getClientIp,
  hasForbiddenUrlTokenParams,
  verifyCsrfAndCors,
} from '@/lib/server-auth';

const MAX_FORGOT_PAYLOAD_BYTES = 4 * 1024; // 4 KB

const FORBIDDEN_FORGOT_FIELDS = new Set([
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
  'userId',
  'user_id',
  'id',
  'resetToken',
  'reset_token',
  'tokenHash',
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

    const contentType = req.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      return NextResponse.json(
        { error: 'Content-Type must be application/json.' },
        { status: 415 }
      );
    }

    const ip = getClientIp(req);
    const rate = enforceRateLimit(
      `forgot:ip:${ip}`,
      PASSWORD_SECURITY_CONFIG.FORGOT_MAX_PER_IP_PER_15_MINUTES,
      15 * 60 * 1000
    );
    if (!rate.allowed) {
      return NextResponse.json(
        { error: 'Too many password reset requests. Please try again later.' },
        {
          status: 429,
          headers: { 'Retry-After': String(rate.retryAfterSec) },
        }
      );
    }

    const rawText = await req.text();
    if (!rawText || rawText.length > MAX_FORGOT_PAYLOAD_BYTES) {
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
      if (FORBIDDEN_FORGOT_FIELDS.has(key)) {
        return NextResponse.json(
          {
            error: `Forbidden: Unauthorized parameter "${key}" in password reset request.`,
          },
          { status: 403 }
        );
      }
    }

    const identifier =
      typeof payload.identifier === 'string' ? payload.identifier.trim() : '';

    const result = await createPasswordResetRequest({ identifier });
    if (!result.ok) {
      const headers: Record<string, string> = {};
      if (result.retryAfterSec) {
        headers['Retry-After'] = String(result.retryAfterSec);
      }
      return NextResponse.json(
        { error: result.error },
        { status: result.status, headers }
      );
    }

    // Return a generic non-enumerating success response (NEVER return _internalResetToken)
    return NextResponse.json({
      sent: true,
      message: result.message,
    });
  } catch {
    return NextResponse.json(
      { error: 'Unable to process password reset request.' },
      { status: 500 }
    );
  }
}

