import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  extractSessionTokenFromRequest,
  getClientIp,
  hasForbiddenUrlTokenParams,
  recordServerAuditLog,
  registerNewUser,
  setSessionCookie,
  signSessionToken,
  validateFullName,
  validateIndianMobile,
  validateOptionalEmail,
  validateSchoolName,
  validateStudentClass,
  verifyCsrfAndCors,
} from '@/lib/server-auth';
import {
  getActivePolicyVersion,
  recordServerAuthoritativeConsent,
} from '@/lib/privacy-consent-governance';

const MAX_PAYLOAD_BYTES = 16 * 1024; // 16 KB max registration payload

const FORBIDDEN_REGISTRATION_FIELDS = new Set([
  'id',
  'uid',
  'userId',
  'user_id',
  'sub',
  'role',
  'userRole',
  'user_role',
  'isAdmin',
  'is_admin',
  'isTeacher',
  'is_teacher',
  'isStudent',
  'is_student',
  'admin',
  'teacher',
  'permissions',
  'authorization',
  'status',
  'accountStatus',
  'account_status',
  'verificationStatus',
  'verification_status',
  'id_verification_status',
  'verified',
  'phoneVerified',
  'phone_verified',
  'mobileVerified',
  'mobile_verified',
  'isVerified',
  'is_verified',
  'idVerified',
  'id_verified',
  'emailVerified',
  'email_verified',
  'kycVerified',
  'kyc_verified',
  'verificationCode',
  'verificationToken',
  'approved',
  'approvedAt',
  'approved_at',
  'balance',
  'wallet',
  'commission',
  'totalEarned',
  'total_earned',
  'thisMonthEarned',
  'prizePaid',
  'examPaid',
  'createdAt',
  'created_at',
  'updatedAt',
  'updated_at',
  'passwordHash',
  'passwordSalt',
]);

const ALLOWED_REGISTRATION_FIELDS = new Set([
  'name',
  'classNum',
  'school',
  'city',
  'phone',
  'email',
  'password',
  'confirmPassword',
  'agreed',
  'termsAccepted',
  'policyVersion',
  'referralCode',
  'idempotencyKey',
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

    const ip = getClientIp(req);

    // 1. IP-based rate limit for registration abuse protection
    const ipRate = enforceRateLimit(`register:ip:${ip}`, 10, 15 * 60 * 1000);
    if (!ipRate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many registration attempts. Please wait a few minutes before trying again.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(ipRate.retryAfterSec) },
        }
      );
    }

    // 2. Reject any privilege/status/role parameters in URL query string
    for (const key of req.nextUrl.searchParams.keys()) {
      if (FORBIDDEN_REGISTRATION_FIELDS.has(key)) {
        recordServerAuditLog({
          actorId: `anon_${ip}`,
          actorEmail: 'anonymous',
          actorRole: 'student',
          action: 'REGISTRATION_QUERY_INJECTION_ATTEMPT',
          target: `Blocked query param: ${key}`,
        });
        return NextResponse.json(
          { error: `Forbidden: Parameter "${key}" is not allowed during registration.` },
          { status: 403 }
        );
      }
    }

    // 3. Enforce payload size cap to prevent oversized payload DoS
    const contentLength = Number(req.headers.get('content-length') || '0');
    if (contentLength > MAX_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Registration payload is too large.' },
        { status: 413 }
      );
    }

    const rawText = await req.text();
    if (!rawText || rawText.length > MAX_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Invalid or oversized registration request.' },
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
        { error: 'Invalid registration payload.' },
        { status: 400 }
      );
    }

    const bodyObj = rawBody as Record<string, unknown>;

    // 4. Mass-assignment & role/status/balance/userId injection protection
    for (const key of Object.keys(bodyObj)) {
      if (FORBIDDEN_REGISTRATION_FIELDS.has(key)) {
        recordServerAuditLog({
          actorId: `anon_${ip}`,
          actorEmail: typeof bodyObj.email === 'string' ? bodyObj.email.slice(0, 80) : 'anonymous',
          actorRole: 'student',
          action: 'REGISTRATION_MASS_ASSIGNMENT_ATTEMPT',
          target: `Blocked protected field: ${key}`,
        });
        return NextResponse.json(
          {
            error: `Forbidden: Cannot supply protected field "${key}" during registration.`,
          },
          { status: 403 }
        );
      }

      if (!ALLOWED_REGISTRATION_FIELDS.has(key)) {
        return NextResponse.json(
          { error: `Unexpected field "${key}" in registration payload.` },
          { status: 400 }
        );
      }
    }

    // 5. Server-side validation of each field
    const nameResult = validateFullName(bodyObj.name);
    if (!nameResult.ok) {
      return NextResponse.json({ error: nameResult.error }, { status: 400 });
    }

    const classResult = validateStudentClass(bodyObj.classNum);
    if (!classResult.ok) {
      return NextResponse.json({ error: classResult.error }, { status: 400 });
    }

    const schoolResult = validateSchoolName(bodyObj.school);
    if (!schoolResult.ok) {
      return NextResponse.json({ error: schoolResult.error }, { status: 400 });
    }

    const phoneResult = validateIndianMobile(bodyObj.phone);
    if (!phoneResult.ok) {
      return NextResponse.json({ error: phoneResult.error }, { status: 400 });
    }

    // Rate limit per normalized mobile number to prevent targeted phone flooding
    const phoneRate = enforceRateLimit(
      `register:phone:${phoneResult.value}`,
      5,
      15 * 60 * 1000
    );
    if (!phoneRate.allowed) {
      return NextResponse.json(
        {
          error:
            'Too many registration attempts for this mobile number. Please wait before trying again.',
        },
        {
          status: 429,
          headers: { 'Retry-After': String(phoneRate.retryAfterSec) },
        }
      );
    }

    const emailResult = validateOptionalEmail(bodyObj.email);
    if (!emailResult.ok) {
      return NextResponse.json({ error: emailResult.error }, { status: 400 });
    }

    const password = bodyObj.password;
    if (
      typeof password !== 'string' ||
      password.length < 6 ||
      password.length > 128 ||
      password.trim().length < 6
    ) {
      return NextResponse.json(
        { error: 'Password must be between 6 and 128 characters.' },
        { status: 400 }
      );
    }

    // Confirm Password validation (never persisted)
    if ('confirmPassword' in bodyObj && bodyObj.confirmPassword !== undefined) {
      if (
        typeof bodyObj.confirmPassword !== 'string' ||
        bodyObj.confirmPassword !== password
      ) {
        return NextResponse.json(
          { error: 'Password and Confirm Password do not match.' },
          { status: 400 }
        );
      }
    } else {
      return NextResponse.json(
        { error: 'Please confirm your password.' },
        { status: 400 }
      );
    }

    // Terms & Conditions acceptance enforcement (Section 9 & 10)
    const termsConsent =
      bodyObj.agreed === true || bodyObj.termsAccepted === true;
    if (!termsConsent) {
      return NextResponse.json(
        { error: 'You must accept the Terms & Conditions to register.' },
        { status: 400 }
      );
    }

    const activeTerms = getActivePolicyVersion('TERMS_AND_CONDITIONS');
    if (
      typeof bodyObj.policyVersion === 'string' &&
      bodyObj.policyVersion.trim() &&
      bodyObj.policyVersion.trim() !== activeTerms?.version
    ) {
      return NextResponse.json(
        {
          error: `Policy version '${bodyObj.policyVersion}' is invalid or superseded. Active version is '${activeTerms?.version}'.`,
          errorCode: 'INVALID_OR_INACTIVE_POLICY_VERSION',
        },
        { status: 422 }
      );
    }

    const idempotencyKey =
      req.headers.get('idempotency-key') ||
      (typeof bodyObj.idempotencyKey === 'string'
        ? bodyObj.idempotencyKey
        : undefined);

    // 6. Explicitly map validated fields into atomic server registration
    const result = await registerNewUser({
      name: nameResult.value,
      classNum: classResult.value,
      school: schoolResult.value,
      city: typeof bodyObj.city === 'string' ? bodyObj.city : undefined,
      phone: phoneResult.value,
      email: emailResult.value,
      password,
      agreed: true,
      referralCode:
        typeof bodyObj.referralCode === 'string'
          ? bodyObj.referralCode
          : undefined,
      idempotencyKey,
    });

    if (!result.ok) {
      return NextResponse.json(
        { error: result.error },
        { status: result.status }
      );
    }

    const ua = req.headers.get('user-agent') || undefined;
    recordServerAuthoritativeConsent({
      authenticatedUserId: result.user.id,
      consentType: 'TERMS_AND_CONDITIONS',
      policyVersion: activeTerms?.version,
      accepted: true,
      source: 'REGISTRATION',
      method: 'EXPLICIT_CHECKBOX',
      rawIp: ip,
      rawUserAgent: ua,
    });

    recordServerAuthoritativeConsent({
      authenticatedUserId: result.user.id,
      consentType: 'PRIVACY_NOTICE',
      accepted: true,
      source: 'REGISTRATION',
      method: 'EXPLICIT_CHECKBOX',
      rawIp: ip,
      rawUserAgent: ua,
    });

    const preExistingToken = extractSessionTokenFromRequest(req);
    const sessionToken = signSessionToken(result.user, { preExistingToken });
    const res = NextResponse.json({
      authenticated: true,
      user: result.user,
    });
    setSessionCookie(res, sessionToken);
    return res;
  } catch {
    return NextResponse.json(
      { error: 'Unable to complete registration. Please try again.' },
      { status: 500 }
    );
  }
}
