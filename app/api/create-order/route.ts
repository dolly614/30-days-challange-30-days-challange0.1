import { NextRequest, NextResponse } from 'next/server';
import Razorpay from 'razorpay';

export async function POST(req: NextRequest) {
  try {
    const keyId =
      process.env.RAZORPAY_KEY_ID || process.env.NEXT_PUBLIC_RAZORPAY_KEY_ID;
    const keySecret = process.env.RAZORPAY_KEY_SECRET;

    if (!keyId || !keySecret) {
      return NextResponse.json(
        {
          success: false,
          error:
            'Razorpay credentials are missing. Please check RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in .env.',
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

    const rawAmount = body.amount;
    const inputAmount = Number(rawAmount);

    if (!Number.isFinite(inputAmount) || inputAmount <= 0) {
      return NextResponse.json(
        {
          success: false,
          error:
            'Invalid amount specified. Please provide a valid exam fee amount.',
        },
        { status: 400 }
      );
    }

    // Convert input amount to paise if specified in rupees (e.g. 199 -> 19900, 99 -> 9900)
    let amountInPaise = inputAmount;
    if (amountInPaise === 199 || amountInPaise === 99) {
      amountInPaise = amountInPaise * 100;
    }

    // Authorized exam prices: ₹199 (19900 paise) or ₹99 (9900 paise).
    // Client-side price tampering (e.g. creating ₹1 / 100 paise orders) is strictly rejected.
    const AUTHORIZED_PRICES = new Set([19900, 9900]);

    if (!AUTHORIZED_PRICES.has(amountInPaise)) {
      return NextResponse.json(
        {
          success: false,
          error:
            'Unauthorized order amount. Price tampering is strictly prohibited. Authorized exam fee is ₹199 (19900 paise).',
          errorCode: 'UNAUTHORIZED_PRICE',
        },
        { status: 400 }
      );
    }

    const amount = amountInPaise;

    const currency =
      typeof body.currency === 'string' && body.currency.trim()
        ? body.currency.trim().toUpperCase()
        : 'INR';

    const receipt =
      typeof body.receipt === 'string' && body.receipt.trim()
        ? body.receipt.trim().slice(0, 40)
        : `rcpt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    const notes =
      body.notes && typeof body.notes === 'object' && !Array.isArray(body.notes)
        ? (body.notes as Record<string, string>)
        : undefined;

    const razorpay = new Razorpay({
      key_id: keyId,
      key_secret: keySecret,
    });

    const orderOptions = {
      amount, // In paise (e.g. 19900 for ₹199)
      currency,
      receipt,
      ...(notes ? { notes } : {}),
    };

    const order = await razorpay.orders.create(orderOptions);

    return NextResponse.json(
      {
        success: true,
        order_id: order.id,
        id: order.id,
        amount: order.amount,
        currency: order.currency,
        receipt: order.receipt,
        key_id: keyId,
      },
      { status: 200 }
    );
  } catch (error: unknown) {
    const err = error as { statusCode?: number; error?: { description?: string }; message?: string };
    const statusCode = err?.statusCode === 401 ? 401 : 500;
    const errorMessage =
      err?.error?.description || err?.message || 'Failed to create Razorpay order.';

    console.error('❌ Razorpay Create Order Error:', error);

    return NextResponse.json(
      {
        success: false,
        error: errorMessage,
      },
      { status: statusCode }
    );
  }
}
