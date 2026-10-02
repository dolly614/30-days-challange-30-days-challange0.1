import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  getAuthenticatedUser,
  getClientIp,
} from '@/lib/server-auth';
import {
  evaluateSafeHealthCheck,
  HealthCheckType,
} from '@/lib/observability-control';
import { createServerVerifiedSupportTicket } from '@/lib/production-data-integrity-governance';
import { verifyAndProcessProviderDeliveryWebhook } from '@/lib/communication-reliability-governance';

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rate = enforceRateLimit(`support_ticket:${ip}`, 15, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many requests. Please wait before submitting another ticket.' },
      { status: 429 }
    );
  }

  try {
    const rawBody = await req.text();
    const body = rawBody ? JSON.parse(rawBody) : {};

    if (body?.action === 'PROVIDER_DELIVERY_WEBHOOK') {
      const sig = req.headers.get('x-webhook-signature') || '';
      const whRes = verifyAndProcessProviderDeliveryWebhook({
        webhookEventId: String(body?.webhookEventId || ''),
        messageId: String(body?.messageId || ''),
        eventStatus:
          body?.eventStatus === 'BOUNCED'
            ? 'BOUNCED'
            : body?.eventStatus === 'COMPLAINT'
            ? 'COMPLAINT'
            : 'DELIVERED',
        rawPayload: rawBody,
        signatureHeader: sig,
      });
      if (!whRes.ok) {
        return NextResponse.json(
          { error: whRes.reason, errorCode: whRes.errorCode },
          { status: whRes.httpStatus }
        );
      }
      return NextResponse.json(whRes, { status: 200 });
    }

    if (body?.action === 'CREATE_SUPPORT_TICKET') {
      const auth = getAuthenticatedUser(req, { touchActivity: false });
      const created = createServerVerifiedSupportTicket({
        name: String(body?.name || ''),
        contactEmailOrPhone: String(body?.contactEmailOrPhone || ''),
        issueType: String(body?.issueType || ''),
        message: String(body?.message || ''),
        actorId: auth?.user?.id,
      });
      if (!created.ok) {
        return NextResponse.json(
          { error: created.reason, errorCode: created.errorCode },
          { status: created.httpStatus }
        );
      }
      return NextResponse.json(
        { ok: true, ticket: created.ticket },
        { status: 201 }
      );
    }
    return NextResponse.json({ status: 'received' }, { status: 200 });
  } catch {
    return NextResponse.json({ error: 'Invalid request payload.' }, { status: 400 });
  }
}

export async function GET(req: NextRequest) {
  const rawType = (
    req.nextUrl.searchParams.get('type') || 'LIVENESS'
  ).toUpperCase();

  const checkType: HealthCheckType =
    rawType === 'READINESS'
      ? 'READINESS'
      : rawType === 'DEPENDENCY_HEALTH'
        ? 'DEPENDENCY_HEALTH'
        : 'LIVENESS';

  const auth = getAuthenticatedUser(req, { touchActivity: false });
  const isAuthorizedOperator = Boolean(auth && auth.user.role === 'admin');

  const result = evaluateSafeHealthCheck({
    checkType,
    isAuthorizedOperator,
    requestId: req.headers.get('x-request-id'),
  });

  const res = NextResponse.json(result.payload, {
    status: result.httpStatus,
    headers: {
      'Cache-Control': 'no-store',
      'X-Request-Id': String(result.payload.request_id || ''),
    },
  });

  return res;
}
