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
    const amount = Number(rawAmount);

    // Minimum amount validation: must be a valid number >= 100 paise (₹1)
    if (!Number.isFinite(amount) || !Number.isInteger(amount) || amount < 100) {
      return NextResponse.json(
        {
          success: false,
          error:
            'Invalid amount. Amount must be an integer and at least 100 paise (₹1).',
        },
        { status: 400 }
      );
    }

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
