import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import {
  enforceRateLimit,
  getClientIp,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import {
  buildStandardApiErrorEnvelope,
  evaluateAuthoritativePaymentContract,
} from '@/lib/api-contract-governance';
import {
  checkAuthoritativeExamEntitlement,
  createAuthoritativePaymentOrder,
  executeAuthoritativePaymentRefund,
  generateRazorpayPaymentSignature,
  getAuthorizedPaymentOrderStatusAndReceipt,
  processAuthoritativePaymentWebhook,
  reconcilePaymentAndFinancialState,
  resolvePaymentProviderSecrets,
  verifyAndCaptureAuthoritativePayment,
} from '@/lib/payment-financial-governance';

export async function GET(req: NextRequest) {
  const authGuard = requireAuthenticatedUser(req);
  if (!authGuard.ok) {
    return authGuard.response;
  }

  const ip = getClientIp(req);
  const rate = enforceRateLimit(`payment_poll:${ip}:${authGuard.user.id}`, 60, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many payment status requests.', errorCode: 'RATE_LIMITED' },
      { status: 429 }
    );
  }

  const orderId = req.nextUrl.searchParams.get('orderId')?.trim() || undefined;
  const paymentId = req.nextUrl.searchParams.get('paymentId')?.trim() || undefined;
  const examTypeParam = req.nextUrl.searchParams.get('examType');

  if (orderId || paymentId) {
    const statusRes = getAuthorizedPaymentOrderStatusAndReceipt({
      actorId: authGuard.user.id,
      actorRole: authGuard.user.role,
      orderId,
      paymentId,
    });
    if (!statusRes.ok) {
      return NextResponse.json(
        { error: statusRes.reason, errorCode: statusRes.errorCode },
        { status: statusRes.httpStatus, headers: { 'Cache-Control': 'no-store' } }
      );
    }
    return NextResponse.json(statusRes, {
      status: 200,
      headers: { 'Cache-Control': 'no-store' },
    });
  }

  const examType = examTypeParam === 'final' ? 'final' : 'mid';
  const entitlementCheck = checkAuthoritativeExamEntitlement({
    userId: authGuard.user.id,
    examType,
  });

  return NextResponse.json(
    {
      ok: true,
      examType,
      hasActiveEntitlement: entitlementCheck.hasActiveEntitlement,
      entitlement: entitlementCheck.entitlement || null,
    },
    { status: 200, headers: { 'Cache-Control': 'no-store' } }
  );
}

export async function POST(req: NextRequest) {
  try {
    const rawText = await req.text();
    const webhookSig = req.headers.get('x-razorpay-signature');

    // 1. Authoritative Webhook Endpoint Processing (Section 14, 15, 16)
    if (webhookSig) {
      const whRes = processAuthoritativePaymentWebhook({
        rawBody: rawText,
        signatureHeader: webhookSig,
        requestId: req.headers.get('x-request-id') || undefined,
      });
      if (!whRes.ok) {
        return NextResponse.json(
          { error: whRes.reason, errorCode: whRes.errorCode },
          { status: whRes.httpStatus }
        );
      }
      return NextResponse.json(whRes, { status: 200 });
    }

    const authGuard = requireAuthenticatedUser(req);
    if (!authGuard.ok) {
      return authGuard.response;
    }

    const ip = getClientIp(req);
    const rate = enforceRateLimit(
      `payment:${ip}:${authGuard.user.id}`,
      20,
      10 * 60 * 1000
    );
    if (!rate.allowed) {
      return NextResponse.json(
        {
          success: false,
          error: 'Too many payment requests. Please wait.',
          errorCode: 'RATE_LIMITED',
        },
        { status: 429 }
      );
    }

    const body = rawText ? JSON.parse(rawText) : {};
    const action =
      typeof body?.action === 'string' ? body.action.trim() : 'CREATE_ORDER';
    const idempotencyKey =
      req.headers.get('idempotency-key') ||
      (typeof body?.idempotencyKey === 'string' ? body.idempotencyKey : null);

    // 2. Server-Side Payment Verification (Section 12 & 13)
    if (action === 'VERIFY_PAYMENT') {
      const verified = verifyAndCaptureAuthoritativePayment({
        actorId: authGuard.user.id,
        actorRole: authGuard.user.role,
        providerOrderId: String(body?.providerOrderId || body?.orderId || ''),
        providerPaymentId: String(
          body?.providerPaymentId || body?.paymentId || ''
        ),
        providerSignature: String(
          body?.providerSignature || body?.signature || ''
        ),
        providerReportedAmountMinor:
          typeof body?.amountMinor === 'number' ? body.amountMinor : undefined,
        providerReportedCurrency:
          typeof body?.currency === 'string' ? body.currency : undefined,
        providerCaptured:
          typeof body?.captured === 'boolean' ? body.captured : true,
        source: 'VERIFY_API',
        idempotencyKey,
        requestId: req.headers.get('x-request-id') || undefined,
      });

      if (!verified.ok) {
        return NextResponse.json(
          {
            success: false,
            error: verified.reason,
            errorCode: verified.errorCode,
          },
          { status: verified.httpStatus }
        );
      }

      return NextResponse.json(
        {
          success: true,
          paymentState: verified.payment.status,
          orderId: verified.order.provider_order_id,
          paymentId: verified.payment.id,
          receiptId: verified.payment.receipt_id,
          amountMinor: verified.payment.amount_minor,
          currency: verified.payment.currency,
          entitlement: verified.entitlement,
        },
        { status: 200, headers: { 'Cache-Control': 'no-store' } }
      );
    }

    // 3. Server-Authorized Admin Refund Processing (Section 20, 21, 22)
    if (action === 'REFUND') {
      const refundRes = executeAuthoritativePaymentRefund({
        actorId: authGuard.user.id,
        actorRole: authGuard.user.role,
        paymentId: String(body?.paymentId || ''),
        refundAmountMinor:
          typeof body?.refundAmountMinor === 'number'
            ? body.refundAmountMinor
            : undefined,
        reason: String(body?.reason || 'Admin initiated refund'),
        idempotencyKey,
        requestId: req.headers.get('x-request-id') || undefined,
      });

      if (!refundRes.ok) {
        return NextResponse.json(
          {
            success: false,
            error: refundRes.reason,
            errorCode: refundRes.errorCode,
          },
          { status: refundRes.httpStatus }
        );
      }

      return NextResponse.json(refundRes, {
        status: 200,
        headers: { 'Cache-Control': 'no-store' },
      });
    }

    // 4. Server-Authorized Admin Reconciliation (Section 34)
    if (action === 'RECONCILE') {
      if (authGuard.user.role !== 'admin') {
        return NextResponse.json(
          {
            success: false,
            error: 'Only administrators may run financial reconciliation.',
            errorCode: 'NOT_AUTHORIZED',
          },
          { status: 403 }
        );
      }
      const reconRes = reconcilePaymentAndFinancialState({
        orderId: String(body?.orderId || ''),
        providerSnapshot: body?.providerSnapshot,
        requestId: req.headers.get('x-request-id') || undefined,
      });
      return NextResponse.json(reconRes, { status: 200 });
    }

    // 5. Reject client-supplied payment state claims (paymentSuccessful, amountPaid, examUnlocked)
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      const paymentContractCheck = evaluateAuthoritativePaymentContract({
        clientPayload: body as Record<string, unknown>,
        serverVerifiedSignature: true,
      });
      if (!paymentContractCheck.allowed) {
        return NextResponse.json(
          buildStandardApiErrorEnvelope({
            code: paymentContractCheck.errorCode || 'FORBIDDEN',
            message:
              'Client-supplied payment status, amountPaid, or examUnlocked claims are forbidden.',
            requestId: req.headers.get('x-request-id'),
          }),
          { status: paymentContractCheck.httpStatus }
        );
      }
    }

    const examType: 'mid' | 'final' =
      body?.examType === 'final' ? 'final' : 'mid';
    const clientUserId =
      typeof body?.userId === 'string' && body.userId.trim() !== 'guest'
        ? body.userId.trim()
        : undefined;

    const orderRes = createAuthoritativePaymentOrder({
      actorId: authGuard.user.id,
      actorRole: authGuard.user.role,
      clientSuppliedUserId: clientUserId,
      examType,
      couponCode:
        typeof body?.couponCode === 'string' ? body.couponCode : undefined,
      referralTeacherId:
        typeof body?.referralTeacherId === 'string'
          ? body.referralTeacherId
          : undefined,
      clientPayload: body as Record<string, unknown>,
      idempotencyKey,
      requestId: req.headers.get('x-request-id') || undefined,
    });

    if (!orderRes.ok) {
      return NextResponse.json(
        {
          success: false,
          error: orderRes.reason,
          errorCode: orderRes.errorCode,
        },
        { status: orderRes.httpStatus }
      );
    }

    // In non-production preview environments, if server-side checkout completion is requested,
    // verify and capture through the authoritative server pipeline (impossible in PRODUCTION).
    if (
      process.env.NODE_ENV !== 'production' &&
      body?.completeServerVerifiedCheckout === true
    ) {
      const secrets = resolvePaymentProviderSecrets({
        environment: 'DEVELOPMENT',
      });
      if (secrets.ok) {
        const providerPaymentId = `pay_Rzp_${crypto.randomBytes(6).toString('hex')}`;
        const sig = generateRazorpayPaymentSignature({
          providerOrderId: orderRes.order.provider_order_id,
          providerPaymentId,
          keySecret: secrets.keySecret,
        });
        const captured = verifyAndCaptureAuthoritativePayment({
          actorId: authGuard.user.id,
          actorRole: authGuard.user.role,
          providerOrderId: orderRes.order.provider_order_id,
          providerPaymentId,
          providerSignature: sig,
          environment: 'DEVELOPMENT',
        });
        if (captured.ok) {
          return NextResponse.json(
            {
              ...orderRes.checkoutPayload,
              paymentState: 'PAYMENT_CAPTURED',
              paymentId: captured.payment.id,
              providerPaymentId,
              receiptId: captured.payment.receipt_id,
              entitlementStatus: captured.entitlement.status,
            },
            { status: 200, headers: { 'Cache-Control': 'no-store' } }
          );
        }
      }
    }

    return NextResponse.json(orderRes.checkoutPayload, {
      status: orderRes.httpStatus,
      headers: { 'Cache-Control': 'no-store' },
    });
  } catch {
    return NextResponse.json(
      { success: false, error: 'Unable to process payment request.' },
      { status: 400 }
    );
  }
}
