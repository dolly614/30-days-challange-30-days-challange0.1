import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { examType = 'mid', amount = 199, userId = 'guest' } = body;

    const orderId = `order_Rzp_${crypto.randomBytes(6).toString('hex')}`;
    const signature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'uyanix_secret')
      .update(`${orderId}|${userId}`)
      .digest('hex');

    return NextResponse.json({
      success: true,
      orderId,
      amount: amount * 100, // in paise
      currency: 'INR',
      examType,
      signature,
      verifiedAt: new Date().toISOString(),
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: (error as Error).message },
      { status: 400 }
    );
  }
}
