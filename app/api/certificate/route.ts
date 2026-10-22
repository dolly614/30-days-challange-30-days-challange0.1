import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  getClientIp,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import {
  authorizeCertificateArtifactDownload,
  CertificateRevocationReason,
  issueOrRetrieveAuthoritativeCertificate,
  replaceOrReissueAuthoritativeCertificate,
  revokeAuthoritativeCertificate,
  verifyCertificatePublicly,
} from '@/lib/certificate-security-governance';
import { authoritativeVerifyCertificate } from '@/lib/exam-authoritative-service';
import { getSupabaseAdminClient } from '@/lib/supabase-server';

export async function GET(req: NextRequest) {
  const verifyId = req.nextUrl.searchParams.get('verify');
  const token = req.nextUrl.searchParams.get('token');
  const downloadId = req.nextUrl.searchParams.get('download');
  const ip = getClientIp(req);

  // 1. Public Verification Endpoint (Sections 17, 18, 19, 20, 34, 35)
  if (verifyId !== null) {
    const dbVerified = await authoritativeVerifyCertificate(verifyId);
    if (dbVerified.state === 'VALID' && dbVerified.certificate) {
      return NextResponse.json({
        state: 'VALID',
        verified: true,
        certificate: dbVerified.certificate,
      }, {
        status: 200,
        headers: {
          'Cache-Control': 'public, max-age=300, stale-while-revalidate=600',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    } else if (dbVerified.state === 'REVOKED') {
      return NextResponse.json({
        state: 'REVOKED',
        verified: false,
        error: 'This certificate has been revoked for administrative or integrity reasons.',
      }, { status: 410 });
    }

    const verified = verifyCertificatePublicly({
      publicCertificateId: verifyId,
      verificationToken: token,
      clientIp: ip,
      requestId: req.headers.get('x-request-id') || undefined,
    });

    return NextResponse.json(verified.payload, {
      status: verified.httpStatus,
      headers: {
        'Cache-Control': verified.payload.cache_control,
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }

  // 2. Authenticated Certificate Download or Retrieval (Section 27)
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  if (downloadId) {
    const dl = authorizeCertificateArtifactDownload({
      actorId: auth.user.id,
      actorRole: auth.user.role,
      publicCertificateId: downloadId,
      requestId: req.headers.get('x-request-id') || undefined,
    });

    if (!dl.authorized) {
      return NextResponse.json(
        { error: dl.reason, errorCode: dl.errorCode },
        { status: dl.httpStatus }
      );
    }

    return new NextResponse(new Uint8Array(dl.artifactBuffer), {
      status: 200,
      headers: dl.responseHeaders,
    });
  }

  // Check Supabase PostgreSQL public.certificates first
  const supabase = getSupabaseAdminClient();
  if (supabase) {
    try {
      const { data: dbCert } = await supabase
        .from('certificates')
        .select('*')
        .or(`user_id.eq.${auth.user.id},recipient_display_name.eq.${auth.user.name || 'nobody'}`)
        .eq('status', 'AVAILABLE')
        .order('issued_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (dbCert) {
        return NextResponse.json({
          ok: true,
          publicCertificateId: dbCert.public_certificate_id,
          qrVerificationUrl: dbCert.url,
          status: dbCert.status,
          issueDate: dbCert.issued_at,
          scoreSnapshot: dbCert.score_snapshot,
          rankSnapshot: 4,
          recipientName: dbCert.recipient_display_name,
          verificationVersion: dbCert.verification_version,
        }, {
          status: 200,
          headers: { 'Cache-Control': 'private, no-store' },
        });
      }
    } catch {
      // fallback
    }
  }

  // Query Supabase PostgreSQL for actual evaluated exam attempts
  if (supabase) {
    try {
      const { data: dbAttempt } = await supabase
        .from('exam_attempts')
        .select('*')
        .or(`student_id.eq.${auth.user.id},user_id.eq.${auth.user.id}`)
        .in('status', ['EVALUATED', 'completed', 'AUTO_SUBMITTED'])
        .order('finalized_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (
        dbAttempt &&
        (dbAttempt.certificate_eligible || (dbAttempt.percentage ?? 0) >= 40)
      ) {
        const issued = issueOrRetrieveAuthoritativeCertificate({
          actorId: auth.user.id,
          actorRole: auth.user.role,
          accountStatus: 'active',
          authoritativeResult: {
            result_id: `RES-AUTH-${dbAttempt.id || auth.user.id}`,
            attempt_id: dbAttempt.id || `ATT-AUTH-${auth.user.id}`,
            exam_id: dbAttempt.exam_id || 'EXAM-UYANIX-2026',
            exam_type: dbAttempt.exam_type || 'mid',
            student_id: auth.user.id,
            student_name: auth.user.name || 'Student Champion',
            student_school: auth.user.school || 'Enrolled School',
            student_class: auth.user.classNum || dbAttempt.student_class || 10,
            completed_days: 30,
            score: dbAttempt.score,
            maximum_score: dbAttempt.maximum_score || 150,
            percentage: dbAttempt.percentage,
            rank: dbAttempt.rank || 1,
            attempt_status: 'EVALUATED',
            result_valid: true,
            requires_payment: false,
            finalized_at: dbAttempt.finalized_at || new Date().toISOString(),
          },
          untrustedRequestHostHeader: req.headers.get('host'),
          requestId: req.headers.get('x-request-id') || undefined,
        });

        if (issued.ok) {
          return NextResponse.json(
            {
              ok: true,
              publicCertificateId: issued.certificate.public_certificate_id,
              qrVerificationUrl: issued.certificate.qr_verification_url,
              status: issued.certificate.status,
              issueDate: issued.certificate.issue_date,
              scoreSnapshot: issued.certificate.score_snapshot,
              rankSnapshot: issued.certificate.rank_snapshot,
              recipientName: issued.certificate.recipient_name_snapshot,
              verificationVersion: issued.certificate.verification_version,
            },
            {
              status: 200,
              headers: { 'Cache-Control': 'private, no-store' },
            }
          );
        }
      }
    } catch {
      // non-blocking fallback
    }
  }

  // Only issue certificates if student has completed and evaluated an exam
  return NextResponse.json(
    {
      ok: false,
      error:
        'No completed exam found. You must complete and evaluate your 30-Day Challenge or Mid-Term Exam before claiming a certificate.',
      errorCode: 'NO_EVALUATED_EXAM',
    },
    { status: 404 }
  );
}

export async function POST(req: NextRequest) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  const ip = getClientIp(req);
  const rate = enforceRateLimit(`cert_mut:${ip}:${auth.user.id}`, 20, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many certificate requests.', errorCode: 'RATE_LIMITED' },
      { status: 429 }
    );
  }

  try {
    const body = await req.json();
    const action =
      typeof body?.action === 'string' ? body.action.trim() : 'ISSUE';

    if (action === 'REVOKE') {
      const revoked = revokeAuthoritativeCertificate({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        publicCertificateIdOrInternalId: String(
          body?.publicCertificateId || body?.certificateId || ''
        ),
        reason: (body?.reason as CertificateRevocationReason) || 'OTHER',
        notes: typeof body?.notes === 'string' ? body.notes : undefined,
        requestId: req.headers.get('x-request-id') || undefined,
      });

      if (!revoked.ok) {
        return NextResponse.json(
          { error: revoked.reason, errorCode: revoked.errorCode },
          { status: revoked.httpStatus }
        );
      }

      return NextResponse.json(revoked, { status: 200 });
    }

    if (action === 'REPLACE') {
      const replaced = replaceOrReissueAuthoritativeCertificate({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        existingPublicOrInternalId: String(
          body?.publicCertificateId || body?.certificateId || ''
        ),
        updatedRecipientName:
          typeof body?.updatedRecipientName === 'string'
            ? body.updatedRecipientName
            : undefined,
        updatedScoreSnapshot:
          typeof body?.updatedScoreSnapshot === 'number'
            ? body.updatedScoreSnapshot
            : undefined,
        updatedRankSnapshot:
          typeof body?.updatedRankSnapshot === 'number'
            ? body.updatedRankSnapshot
            : undefined,
        reason: String(body?.reason || ''),
        requestId: req.headers.get('x-request-id') || undefined,
      });

      if (!replaced.ok) {
        return NextResponse.json(
          { error: replaced.reason, errorCode: replaced.errorCode },
          { status: replaced.httpStatus }
        );
      }

      return NextResponse.json(replaced, { status: 201 });
    }

    const issued = issueOrRetrieveAuthoritativeCertificate({
      actorId: auth.user.id,
      actorRole: auth.user.role,
      accountStatus: 'active',
      authoritativeResult: body?.authoritativeResult,
      clientPayload: body?.clientPayload,
      untrustedRequestHostHeader: req.headers.get('host'),
      requestId: req.headers.get('x-request-id') || undefined,
    });

    if (!issued.ok) {
      return NextResponse.json(
        { error: issued.reason, errorCode: issued.errorCode },
        { status: issued.httpStatus }
      );
    }

    return NextResponse.json(issued, { status: issued.httpStatus });
  } catch {
    return NextResponse.json(
      { error: 'Invalid certificate request payload.' },
      { status: 400 }
    );
  }
}
