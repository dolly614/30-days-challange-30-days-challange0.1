import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { verifyAndCaptureAuthoritativePaymentDb } from '@/lib/payment-database-authoritative-service';
import { requireAuthenticatedUser } from '@/lib/server-auth';

export async function POST(req: NextRequest) {
  try {
    const keySecret = process.env.RAZORPAY_KEY_SECRET;

    if (!keySecret) {
      return NextResponse.json(
        {
          success: false,
          error:
            'Razorpay secret key is not configured on the server. Please set RAZORPAY_KEY_SECRET in .env.',
        },
        { status: 401 }
      );
    }

    let body: Record<string, unknown> = {};
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { success: false, error: 'Invalid JSON request payload.' },
        { status: 400 }
      );
    }

    // Accept both naming conventions: razorpay_order_id vs order_id, razorpay_payment_id vs payment_id
    const orderId =
      typeof body.razorpay_order_id === 'string' && body.razorpay_order_id.trim()
        ? body.razorpay_order_id.trim()
        : typeof body.order_id === 'string' && body.order_id.trim()
        ? body.order_id.trim()
        : '';

    const paymentId =
      typeof body.razorpay_payment_id === 'string' && body.razorpay_payment_id.trim()
        ? body.razorpay_payment_id.trim()
        : typeof body.payment_id === 'string' && body.payment_id.trim()
        ? body.payment_id.trim()
        : '';

    const signature =
      typeof body.razorpay_signature === 'string' && body.razorpay_signature.trim()
        ? body.razorpay_signature.trim()
        : typeof body.signature === 'string' && body.signature.trim()
        ? body.signature.trim()
        : '';

    // Validate missing fields: return 400
    if (!orderId || !paymentId || !signature) {
      return NextResponse.json(
        {
          success: false,
          error:
            'Missing required payment verification fields. Both order_id, payment_id, and signature are required.',
          received: {
            order_id: Boolean(orderId),
            payment_id: Boolean(paymentId),
            signature: Boolean(signature),
          },
        },
        { status: 400 }
      );
    }

    // Algorithm: HMAC-SHA256(order_id + "|" + payment_id, KEY_SECRET)
    const payload = `${orderId}|${paymentId}`;
    const expectedSignature = crypto
      .createHmac('sha256', keySecret)
      .update(payload)
      .digest('hex');

    // Constant-time comparison to prevent timing attacks
    let isMatch = false;
    try {
      const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
      const receivedBuffer = Buffer.from(signature, 'utf8');
      if (expectedBuffer.length === receivedBuffer.length) {
        isMatch = crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
      }
    } catch {
      isMatch = false;
    }

    if (!isMatch) {
      console.warn('⚠️ Razorpay Signature Mismatch detected for order:', orderId);
      return NextResponse.json(
        {
          success: false,
          error: 'Payment verification failed: Signature mismatch.',
          verified: false,
        },
        { status: 400 }
      );
    }

    // Signature verified successfully!
    // Optional integration with platform exam entitlement if examType is present
    const examType =
      body.examType === 'final' || body.examType === 'mid'
        ? (body.examType as 'mid' | 'final')
        : undefined;

    let entitlementResult = null;
    try {
      const authGuard = requireAuthenticatedUser(req);
      if (authGuard.ok && examType) {
        const captureRes = await verifyAndCaptureAuthoritativePaymentDb({
          actorId: authGuard.user.id,
          actorRole: authGuard.user.role,
          providerOrderId: orderId,
          providerPaymentId: paymentId,
          providerSignature: signature,
          environment: process.env.NODE_ENV === 'production' ? 'PRODUCTION' : 'DEVELOPMENT',
        });
        if (captureRes.ok) {
          entitlementResult = captureRes.entitlement;
        }
      }
    } catch {
      // Optional entitlement recording fallback for unauthenticated demo/testing
    }

    return NextResponse.json(
      {
        success: true,
        message: 'Payment verified successfully.',
        order_id: orderId,
        payment_id: paymentId,
        verified: true,
        entitlement: entitlementResult,
      },
      { status: 200 }
    );
  } catch (error: unknown) {
    const err = error as { message?: string };
    console.error('❌ Razorpay Verify Signature Error:', error);

    return NextResponse.json(
      {
        success: false,
        error: err?.message || 'Server error while verifying payment signature.',
      },
      { status: 500 }
    );
  }
}
