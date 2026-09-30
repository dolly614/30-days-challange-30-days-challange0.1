import { NextRequest, NextResponse } from 'next/server';

const ipRequestMap = new Map<string, { count: number; resetAt: number }>();

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
    const now = Date.now();
    const record = ipRequestMap.get(ip);

    if (record && now < record.resetAt) {
      if (record.count >= 20) {
        return NextResponse.json(
          { error: 'Rate limit exceeded. Kripya thodi der baad try karein.' },
          { status: 429 }
        );
      }
      record.count += 1;
    } else {
      ipRequestMap.set(ip, { count: 1, resetAt: now + 60_000 });
    }

    const body = await req.json();
    const { teacherEmail, studentEmail, referralCode } = body;

    // Self-referral fraud check
    if (
      teacherEmail &&
      studentEmail &&
      teacherEmail.toLowerCase() === studentEmail.toLowerCase()
    ) {
      return NextResponse.json(
        {
          valid: false,
          fraudFlag: 'SELF_REFERRAL_DETECTED',
          message: 'Self-referral allowed nahi hai.',
        },
        { status: 403 }
      );
    }

    return NextResponse.json({
      valid: true,
      referralCode: referralCode || 'DOLLOXW0',
      commissionTier: 10,
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    return NextResponse.json(
      { valid: false, error: (error as Error).message },
      { status: 400 }
    );
  }
}
