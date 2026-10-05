import { NextRequest, NextResponse } from 'next/server';
import {
  clearOtpBindingCookie,
  createOtpChallenge,
  enforceRateLimit,
  extractSessionTokenFromRequest,
  getAuthenticatedUser,
  getClientIp,
  hasForbiddenUrlTokenParams,
  OTP_BINDING_COOKIE_NAME,
  OTP_SECURITY_CONFIG,
  recordServerAuditLog,
  setOtpBindingCookie,
  setSessionCookie,
  signSessionToken,
  verifyCsrfAndCors,
  verifyOtpBindingToken,
  verifyOtpChallenge,
} from '@/lib/server-auth';

const MAX_OTP_PAYLOAD_BYTES = 8 * 1024;

const FORBIDDEN_OTP_FIELDS = new Set([
  'expiresAt',
  'expires_at',
  'remainingSeconds',
  'remaining_seconds',
  'isExpired',
  'is_expired',
  'attempts',
  'maxAttempts',
  'max_attempts',
  'resendCount',
  'resend_count',
  'cooldown',
  'canResend',
  'can_resend',
  'countdown',
  'verified',
  'phoneVerified',
  'phone_verified',
  'mobileVerified',
  'mobile_verified',
  'isVerified',
  'is_verified',
  'idVerified',
  'id_verified',
  'used',
  'createdAt',
  'created_at',
  'otpStatus',
  'otp_status',
  'status',
  'role',
  'isAdmin',
  'is_admin',
  'isTeacher',
  'is_teacher',
  'userId',
  'user_id',
  'id',
  'uid',
  'otpHash',
  'otp_hash',
  'otpSalt',
  'devOtpPreview',
  'testOtp',
  'test_otp',
  'dev',
  'allowDevOtp',
  'verificationToken',
]);

const ALLOWED_OTP_FIELDS = new Set(['action', 'phone', 'otpCode']);

const FORBIDDEN_BYPASS_HEADERS = [
  'x-test-otp',
  'x-dev-otp',
  'x-bypass-otp',
  'x-mock-otp',
];

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

    // 1. Reject any header attempting to activate a test/dev OTP bypass
    for (const headerName of FORBIDDEN_BYPASS_HEADERS) {
      if (req.headers.has(headerName)) {
        recordServerAuditLog({
          actorId: `anon_${ip}`,
          actorEmail: 'anonymous',
          actorRole: 'student',
          action: 'OTP_HEADER_BYPASS_BLOCKED',
          target: `Blocked header: ${headerName}`,
        });
        return NextResponse.json(
          { error: 'Forbidden: OTP bypass headers are not permitted.' },
          { status: 403 }
        );
      }
    }

    // 2. Reject any query parameter attempting to bypass or inject OTP state
    for (const key of req.nextUrl.searchParams.keys()) {
      if (
        FORBIDDEN_OTP_FIELDS.has(key) ||
        key === 'otp' ||
        key === 'otpCode' ||
        key === 'code'
      ) {
        recordServerAuditLog({
          actorId: `anon_${ip}`,
          actorEmail: 'anonymous',
          actorRole: 'student',
          action: 'OTP_QUERY_INJECTION_BLOCKED',
          target: `Blocked query param: ${key}`,
        });
        return NextResponse.json(
          {
            error: `Forbidden: Query parameter "${key}" is not allowed on OTP endpoint.`,
          },
          { status: 403 }
        );
      }
    }

    // 3. Enforce payload size cap
    const contentLength = Number(req.headers.get('content-length') || '0');
    if (contentLength > MAX_OTP_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Request payload too large.' },
        { status: 413 }
      );
    }

    const rawText = await req.text();
    if (!rawText || rawText.length > MAX_OTP_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Invalid OTP request payload.' },
        { status: 400 }
      );
    }

    let rawBody: unknown;
    try {
      rawBody = JSON.parse(rawText);
    } catch {
      return NextResponse.json(
        { error: 'Malformed JSON request body.' },
        { status: 400 }
      );
    }

    if (!rawBody || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
      return NextResponse.json(
        { error: 'Invalid OTP request body.' },
        { status: 400 }
      );
    }

    const body = rawBody as Record<string, unknown>;

    // 4. Reject any client-supplied security parameters / verification-state injection
    for (const key of Object.keys(body)) {
      if (FORBIDDEN_OTP_FIELDS.has(key)) {
        recordServerAuditLog({
          actorId: `anon_${ip}`,
          actorEmail: 'anonymous',
          actorRole: 'student',
          action: 'OTP_PAYLOAD_INJECTION_BLOCKED',
          target: `Blocked body field: ${key}`,
        });
        return NextResponse.json(
          {
            error: `Forbidden: Field "${key}" cannot be controlled by the client.`,
          },
          { status: 403 }
        );
      }
      if (!ALLOWED_OTP_FIELDS.has(key)) {
        return NextResponse.json(
          { error: `Unexpected field "${key}" in OTP request.` },
          { status: 400 }
        );
      }
    }

    const rawAction =
      typeof body.action === 'string' ? body.action.trim().toLowerCase() : 'send';
    if (
      rawAction !== 'send' &&
      rawAction !== 'resend' &&
      rawAction !== 'verify'
    ) {
      return NextResponse.json(
        { error: 'Invalid OTP action. Must be "send", "resend", or "verify".' },
        { status: 400 }
      );
    }

    const phone = typeof body.phone === 'string' ? body.phone : '';
    const activeSession = getAuthenticatedUser(req);
    const otpBindingCookie = req.cookies.get(OTP_BINDING_COOKIE_NAME)?.value;
    const boundContext = verifyOtpBindingToken(otpBindingCookie);

    if (rawAction === 'send' || rawAction === 'resend') {
      const window10mMs =
        OTP_SECURITY_CONFIG.OTP_ABUSE_WINDOW_MINUTES * 60 * 1000;
      const sendIpRate = enforceRateLimit(
        `otp:send:ip:${ip}`,
        OTP_SECURITY_CONFIG.OTP_MAX_SENDS_PER_PHONE_PER_24_HOURS,
        window10mMs
      );
      if (!sendIpRate.allowed) {
        return NextResponse.json(
          {
            error:
              'Too many OTP requests from this network. Please wait before requesting another OTP.',
          },
          {
            status: 429,
            headers: { 'Retry-After': String(sendIpRate.retryAfterSec) },
          }
        );
      }

      const result = await createOtpChallenge(phone, {
        isResend: rawAction === 'resend',
        boundUserId: activeSession?.user.id,
      });

      if (!result.ok) {
        return NextResponse.json(
          { error: result.error },
          {
            status: result.status,
            ...(result.retryAfterSec
              ? { headers: { 'Retry-After': String(result.retryAfterSec) } }
              : {}),
          }
        );
      }

      // Never return actual OTP or hash in API response (Test 12 & ALLOW_DEV_OTP_BYPASS_IN_PRODUCTION = false)
      const res = NextResponse.json({
        sent: true,
        expiresInSeconds: OTP_SECURITY_CONFIG.OTP_EXPIRY_SECONDS,
        cooldownSeconds: OTP_SECURITY_CONFIG.OTP_RESEND_COOLDOWN_SECONDS,
        message:
          'A 6-digit OTP has been sent to your registered mobile number.',
      });
      setOtpBindingCookie(res, result.bindingToken);
      return res;
    }

    // Verify OTP action
    // Enforce OTP_VERIFY_MAX_REQUESTS_PER_IP_PER_10_MINUTES = 30
    const verifyWindowMs =
      OTP_SECURITY_CONFIG.OTP_ABUSE_WINDOW_MINUTES * 60 * 1000;
    const verifyIpRate = enforceRateLimit(
      `otp:verify:ip:${ip}`,
      OTP_SECURITY_CONFIG.OTP_VERIFY_MAX_REQUESTS_PER_IP_PER_10_MINUTES,
      verifyWindowMs
    );
    if (!verifyIpRate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many OTP verification attempts. Please wait before trying again.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(verifyIpRate.retryAfterSec) },
        }
      );
    }

    const code = typeof body.otpCode === 'string' ? body.otpCode : '';
    const verifyResult = await verifyOtpChallenge(phone, code, {
      boundPhone: boundContext?.phone,
      boundUserId: boundContext?.userId || activeSession?.user.id,
      boundChallengeId: boundContext?.challengeId,
    });

    if (!verifyResult.ok) {
      return NextResponse.json(
        { error: verifyResult.error },
        { status: verifyResult.status }
      );
    }

    const preExistingToken = extractSessionTokenFromRequest(req);
    const sessionToken = signSessionToken(verifyResult.user, {
      preExistingToken,
    });
    const res = NextResponse.json({
      authenticated: true,
      phoneVerified: true,
      user: verifyResult.user,
    });
    clearOtpBindingCookie(res);
    setSessionCookie(res, sessionToken);
    return res;
  } catch {
    return NextResponse.json(
      { error: 'Unable to process OTP request.' },
      { status: 500 }
    );
  }
}
