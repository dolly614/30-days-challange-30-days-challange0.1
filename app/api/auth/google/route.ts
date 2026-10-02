import { NextRequest, NextResponse } from 'next/server';
import firebaseConfig from '@/firebase-applet-config.json';
import {
  enforceRateLimit,
  extractSessionTokenFromRequest,
  getClientIp,
  hasForbiddenUrlTokenParams,
  setSessionCookie,
  signSessionToken,
  upsertGoogleAuthenticatedUser,
  verifyCsrfAndCors,
} from '@/lib/server-auth';
import { appendImmutableAdminAuditEvent } from '@/lib/admin-control-plane-governance';
import { validateGoogleUpstreamUrlAgainstSsrf } from '@/lib/google-workspace-security-governance';

interface IdentityToolkitUser {
  localId: string;
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  photoUrl?: string;
  disabled?: boolean;
}

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
    const rate = enforceRateLimit(`google-auth:${ip}`, 15, 15 * 60 * 1000);
    if (!rate.allowed) {
      return NextResponse.json(
        { error: 'Too many authentication requests. Please try again later.' },
        { status: 429 }
      );
    }

    const body = await req.json();
    if (body?.role !== undefined || body?.permissions !== undefined) {
      return NextResponse.json(
        {
          error: 'Client-provided role or permission claims during Google OAuth are forbidden.',
          errorCode: 'CLIENT_ROLE_INJECTION_REJECTED',
        },
        { status: 403 }
      );
    }

    const idToken = typeof body?.idToken === 'string' ? body.idToken.trim() : '';
    if (!idToken) {
      return NextResponse.json(
        { error: 'Missing Firebase authentication token.' },
        { status: 400 }
      );
    }

    const lookupUrl = `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(
      firebaseConfig.apiKey
    )}`;
    const ssrfCheck = validateGoogleUpstreamUrlAgainstSsrf(lookupUrl);
    if (!ssrfCheck.ok) {
      return NextResponse.json(
        { error: ssrfCheck.reason, errorCode: ssrfCheck.errorCode },
        { status: ssrfCheck.httpStatus }
      );
    }

    // Verify Firebase ID token server-side with Google Identity Toolkit
    const verifyRes = await fetch(ssrfCheck.safeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken }),
    });

    if (!verifyRes.ok) {
      return NextResponse.json(
        { error: 'Invalid or expired Google authentication token.' },
        { status: 401 }
      );
    }

    const verifyData = (await verifyRes.json()) as {
      users?: IdentityToolkitUser[];
    };
    const verifiedAccount = verifyData.users?.[0];

    if (
      !verifiedAccount ||
      !verifiedAccount.localId ||
      !verifiedAccount.email ||
      verifiedAccount.disabled
    ) {
      return NextResponse.json(
        { error: 'Unable to verify Google account identity.' },
        { status: 401 }
      );
    }

    const userProfile = upsertGoogleAuthenticatedUser({
      googleUid: verifiedAccount.localId,
      email: verifiedAccount.email,
      emailVerified: Boolean(verifiedAccount.emailVerified),
      displayName: verifiedAccount.displayName,
      photoUrl: verifiedAccount.photoUrl,
    });

    appendImmutableAdminAuditEvent({
      actorId: userProfile.id,
      actorRole: userProfile.role,
      action: 'GOOGLE_FIREBASE_OAUTH_LOGIN_VERIFIED',
      resourceType: 'GOOGLE_IDENTITY',
      resourceId: verifiedAccount.localId,
      newState: {
        user_id: userProfile.id,
        assigned_role: userProfile.role,
        ip,
      },
      reason: 'Verified Google Firebase ID token and issued HttpOnly Uyanix session',
      result: 'ALLOW',
    });

    const preExistingToken = extractSessionTokenFromRequest(req);
    const sessionToken = signSessionToken(userProfile, { preExistingToken });
    const res = NextResponse.json({
      authenticated: true,
      user: userProfile,
    });
    setSessionCookie(res, sessionToken);
    return res;
  } catch {
    return NextResponse.json(
      { error: 'Google authentication failed.' },
      { status: 500 }
    );
  }
}
