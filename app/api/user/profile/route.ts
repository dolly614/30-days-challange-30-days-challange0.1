import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import {
  clearSessionCookie,
  enforceRateLimit,
  extractSessionTokenFromRequest,
  getClientIp,
  getUserPhoneVerificationStatus,
  requireAuthenticatedUser,
  requireOwnershipOrAdmin,
  revokeSessionToken,
  rotateSessionToken,
  setSessionCookie,
  signSessionToken,
  updateServerUserProfile,
  verifyCsrfAndCors,
} from '@/lib/server-auth';
import { enforceDataMinimizationGuard } from '@/lib/data-lifecycle-governance';
import {
  downloadAuthorizedUserDataExport,
  executeControlledAccountDeletionLifecycle,
  executeVerifiedIdentityContactChange,
  getUserConsentHistory,
  PolicyType,
  recordServerAuthoritativeConsent,
  requestAuthorizedUserDataExport,
  updateCommunicationPreference,
  withdrawOptionalUserConsent,
} from '@/lib/privacy-consent-governance';

const PRIVATE_NO_STORE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
};

const FORBIDDEN_PROFILE_FIELDS = new Set([
  'role',
  'isAdmin',
  'is_admin',
  'isTeacher',
  'is_teacher',
  'permissions',
  'status',
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
  'balance',
  'wallet',
  'commission',
  'termsAccepted',
  'privacyAccepted',
]);

const profileUpdateSchema = z.object({
  userId: z.string().optional(),
  name: z.string().trim().min(1).max(100).optional(),
  classNum: z.coerce.number().int().min(1).max(12).optional(),
  school: z.string().trim().min(1).max(160).optional(),
  city: z.string().trim().min(1).max(100).optional(),
  phone: z.string().trim().min(10).max(20).optional(),
  email: z.string().trim().email().max(160).optional(),
  streakReminders: z.boolean().optional(),
  idCardName: z.string().trim().max(120).optional(),
});

export async function GET(req: NextRequest) {
  const exportId = req.nextUrl.searchParams.get('exportId');
  const exportToken = req.nextUrl.searchParams.get('token');

  if (exportId && exportToken) {
    const authGuard = requireAuthenticatedUser(req);
    if (!authGuard.ok) {
      return authGuard.response;
    }

    const dl = downloadAuthorizedUserDataExport({
      authenticatedActorId: authGuard.user.id,
      authenticatedActorRole: authGuard.user.role,
      exportId,
      downloadToken: exportToken,
      redirectAfterDownload: req.nextUrl.searchParams.get('redirect') || undefined,
      untrustedHostHeader: req.headers.get('x-forwarded-host') || undefined,
    });

    if (!dl.ok) {
      return NextResponse.json(
        { error: dl.reason, errorCode: dl.errorCode },
        { status: dl.httpStatus, headers: PRIVATE_NO_STORE_HEADERS }
      );
    }

    return NextResponse.json(dl.data, {
      status: 200,
      headers: dl.headers,
    });
  }

  const requestedUserId = req.nextUrl.searchParams.get('userId');
  const requestedRole = req.nextUrl.searchParams.get('role');

  // Never allow client-supplied role parameters to influence profile lookups
  if (requestedRole) {
    return NextResponse.json(
      { error: 'Forbidden: Client-supplied role parameter is not allowed.' },
      { status: 403, headers: PRIVATE_NO_STORE_HEADERS }
    );
  }

  const guard = requireOwnershipOrAdmin(req, requestedUserId);
  if (!guard.ok) {
    return guard.response;
  }

  return NextResponse.json(
    {
      user: guard.user,
      phoneVerified: getUserPhoneVerificationStatus(guard.user.id),
      consentHistory: getUserConsentHistory(guard.user.id),
    },
    { headers: PRIVATE_NO_STORE_HEADERS }
  );
}

export async function POST(req: NextRequest) {
  try {
    const csrf = verifyCsrfAndCors(req);
    if (!csrf.ok) {
      return csrf.response;
    }

    const authGuard = requireAuthenticatedUser(req);
    if (!authGuard.ok) {
      return authGuard.response;
    }

    const ip = getClientIp(req);
    const rate = enforceRateLimit(
      `privacy_post:${ip}:${authGuard.user.id}`,
      15,
      60_000
    );
    if (!rate.allowed) {
      return NextResponse.json(
        { error: 'Privacy operation rate limit exceeded.' },
        { status: 429, headers: PRIVATE_NO_STORE_HEADERS }
      );
    }

    const body = await req.json();
    const action = typeof body?.action === 'string' ? body.action : '';

    if (action === 'request_data_export') {
      const exp = requestAuthorizedUserDataExport({
        authenticatedActorId: authGuard.user.id,
        authenticatedActorRole: authGuard.user.role,
        requestedTargetUserId: body.userId || body.accountId || body.studentId,
      });
      if (!exp.ok) {
        return NextResponse.json(
          { error: exp.reason, errorCode: exp.errorCode },
          { status: exp.httpStatus, headers: PRIVATE_NO_STORE_HEADERS }
        );
      }
      return NextResponse.json(exp, {
        status: exp.httpStatus,
        headers: PRIVATE_NO_STORE_HEADERS,
      });
    }

    if (action === 'withdraw_consent') {
      const withdrawn = withdrawOptionalUserConsent({
        authenticatedUserId: authGuard.user.id,
        requestedTargetUserId: body.userId,
        consentType: (body.consentType || 'OPTIONAL_STREAK_REMINDERS') as PolicyType,
      });
      if (!withdrawn.ok) {
        return NextResponse.json(
          { error: withdrawn.reason, errorCode: withdrawn.errorCode },
          { status: withdrawn.httpStatus, headers: PRIVATE_NO_STORE_HEADERS }
        );
      }
      return NextResponse.json(withdrawn, {
        status: 200,
        headers: PRIVATE_NO_STORE_HEADERS,
      });
    }

    if (action === 'update_communication_preference') {
      const comm = updateCommunicationPreference({
        authenticatedUserId: authGuard.user.id,
        category: body.category,
        enabled: Boolean(body.enabled),
      });
      if (!comm.ok) {
        return NextResponse.json(
          { error: comm.reason, errorCode: comm.errorCode },
          { status: comm.httpStatus, headers: PRIVATE_NO_STORE_HEADERS }
        );
      }
      return NextResponse.json(comm, {
        status: 200,
        headers: PRIVATE_NO_STORE_HEADERS,
      });
    }

    if (action === 'verified_contact_change') {
      const changed = executeVerifiedIdentityContactChange({
        authenticatedActorId: authGuard.user.id,
        targetUserId: body.targetUserId || authGuard.user.id,
        field: body.field === 'email' ? 'email' : 'phone',
        newValue: String(body.newValue || ''),
        otpVerifiedForNewContact: Boolean(body.otpVerifiedForNewContact),
        recentReauthVerified: body.recentReauthVerified !== false,
      });
      if (!changed.ok) {
        return NextResponse.json(
          { error: changed.reason, errorCode: changed.errorCode },
          { status: changed.httpStatus, headers: PRIVATE_NO_STORE_HEADERS }
        );
      }
      return NextResponse.json(changed, {
        status: 200,
        headers: PRIVATE_NO_STORE_HEADERS,
      });
    }

    return NextResponse.json(
      { error: 'Unsupported privacy action.' },
      { status: 400, headers: PRIVATE_NO_STORE_HEADERS }
    );
  } catch {
    return NextResponse.json(
      { error: 'Failed to process privacy request.' },
      { status: 500, headers: PRIVATE_NO_STORE_HEADERS }
    );
  }
}

export async function PATCH(req: NextRequest) {
  try {
    const csrf = verifyCsrfAndCors(req);
    if (!csrf.ok) {
      return csrf.response;
    }

    const authGuard = requireAuthenticatedUser(req);
    if (!authGuard.ok) {
      return authGuard.response;
    }

    const rawBody = await req.json();

    // Explicitly reject any attempt to elevate role, verification state, or privileges via profile update payload
    if (rawBody && typeof rawBody === 'object' && !Array.isArray(rawBody)) {
      const minCheck = enforceDataMinimizationGuard(
        rawBody as Record<string, unknown>
      );
      if (!minCheck.allowed) {
        return NextResponse.json(
          { error: minCheck.error },
          { status: 400, headers: PRIVATE_NO_STORE_HEADERS }
        );
      }
      for (const key of Object.keys(rawBody)) {
        if (FORBIDDEN_PROFILE_FIELDS.has(key)) {
          return NextResponse.json(
            {
              error: `Forbidden: Field "${key}" cannot be modified from the client.`,
            },
            { status: 403, headers: PRIVATE_NO_STORE_HEADERS }
          );
        }
      }
    }

    const parsed = profileUpdateSchema.safeParse(rawBody);
    if (!parsed.success) {
      return NextResponse.json(
        { error: 'Invalid profile update payload.' },
        { status: 400, headers: PRIVATE_NO_STORE_HEADERS }
      );
    }

    const guard = requireOwnershipOrAdmin(req, parsed.data.userId);
    if (!guard.ok) {
      return guard.response;
    }

    const targetUserId = parsed.data.userId || guard.user.id;
    const result = updateServerUserProfile(
      guard.user,
      targetUserId,
      parsed.data
    );
    if (!result.ok) {
      return NextResponse.json(
        { error: result.error },
        { status: result.status, headers: PRIVATE_NO_STORE_HEADERS }
      );
    }

    // Section 11: Sync optional streak reminders toggle with auditable consent history
    if (parsed.data.streakReminders !== undefined && targetUserId === guard.user.id) {
      if (parsed.data.streakReminders) {
        recordServerAuthoritativeConsent({
          authenticatedUserId: guard.user.id,
          consentType: 'OPTIONAL_STREAK_REMINDERS',
          accepted: true,
          source: 'PROFILE_SETTINGS',
          method: 'EXPLICIT_TOGGLE',
        });
      } else {
        withdrawOptionalUserConsent({
          authenticatedUserId: guard.user.id,
          consentType: 'OPTIONAL_STREAK_REMINDERS',
        });
      }
    }

    const res = NextResponse.json(
      {
        success: true,
        user: result.user,
        phoneVerified: getUserPhoneVerificationStatus(result.user.id),
      },
      { headers: PRIVATE_NO_STORE_HEADERS }
    );

    if (targetUserId === guard.user.id) {
      const currentToken = extractSessionTokenFromRequest(req);
      const rotated = rotateSessionToken(currentToken);
      if (rotated.ok) {
        setSessionCookie(res, rotated.token);
      } else {
        setSessionCookie(res, signSessionToken(result.user));
      }
    }

    return res;
  } catch {
    return NextResponse.json(
      { error: 'Failed to update user profile.' },
      { status: 500, headers: PRIVATE_NO_STORE_HEADERS }
    );
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const csrf = verifyCsrfAndCors(req);
    if (!csrf.ok) {
      return csrf.response;
    }

    // Section 17: Authenticated identity must come strictly from the trusted server-side session
    const authGuard = requireAuthenticatedUser(req);
    if (!authGuard.ok) {
      return authGuard.response;
    }

    const body = await req.json().catch(() => ({}));
    const requestedTargetUserId =
      typeof body?.targetUserId === 'string' && body.targetUserId.trim()
        ? body.targetUserId.trim()
        : authGuard.user.id;

    const deletionResult = executeControlledAccountDeletionLifecycle({
      authenticatedActorId: authGuard.user.id,
      authenticatedActorEmail: authGuard.user.email,
      authenticatedActorRole: authGuard.user.role,
      requestedTargetUserId,
      reason:
        typeof body?.reason === 'string' ? body.reason : 'User account deletion',
      explicitConfirmation: Boolean(body?.confirmDeletion),
      recentReauthVerified: body?.recentReauthVerified !== false,
      csrfVerified: true,
    });

    if (!deletionResult.ok) {
      return NextResponse.json(
        {
          error: deletionResult.reason,
          errorCode: deletionResult.errorCode,
          lifecycle_status: deletionResult.lifecycleState,
        },
        {
          status: deletionResult.httpStatus,
          headers: PRIVATE_NO_STORE_HEADERS,
        }
      );
    }

    const res = NextResponse.json(
      {
        success: true,
        lifecycle_status: deletionResult.lifecycleState,
        tombstone_id: deletionResult.tombstoneId,
        dispositions: deletionResult.dispositions,
        verification: deletionResult.verification,
      },
      { status: 200, headers: PRIVATE_NO_STORE_HEADERS }
    );

    if (requestedTargetUserId === authGuard.user.id) {
      const token = extractSessionTokenFromRequest(req);
      if (token) {
        revokeSessionToken(token, 'account_deleted');
      }
      clearSessionCookie(res);
    }

    return res;
  } catch {
    return NextResponse.json(
      { error: 'Failed to process account deletion request.' },
      { status: 500, headers: PRIVATE_NO_STORE_HEADERS }
    );
  }
}
