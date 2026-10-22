import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  getClientIp,
  signSessionToken,
  setSessionCookie,
  UserProfile,
} from '@/lib/server-auth';

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rate = enforceRateLimit(`demo:${ip}`, 30, 5 * 60 * 1000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many requests. Please wait a moment.' },
      { status: 429 }
    );
  }

  // 1. Permanently disable demo backdoor in production
  if (process.env.NODE_ENV === 'production') {
    return NextResponse.json(
      {
        error:
          'Demo authentication backdoor is permanently disabled in production environments.',
        errorCode: 'DEMO_MODE_DISABLED',
      },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const role = body?.role || 'student';

    let demoUser: UserProfile;

    if (role === 'admin') {
      demoUser = {
        id: 'usr_admin_demo',
        name: 'System Administrator',
        teacherShortName: 'admin',
        email: 'admin@uyanix.in',
        phone: '9000000001',
        classNum: 12,
        school: 'Uyanix Administrative Portal',
        city: 'Jaipur',
        role: 'admin',
        idVerified: true,
        streakReminders: true,
        createdAt: new Date().toISOString(),
      };
    } else if (role === 'teacher') {
      demoUser = {
        id: 'usr_teacher_demo',
        name: 'Demo Educator',
        teacherShortName: 'educator',
        email: 'teacher@uyanix.in',
        phone: '9000000002',
        classNum: 10,
        school: 'Central Academy',
        city: 'Jaipur',
        role: 'teacher',
        idVerified: true,
        streakReminders: true,
        createdAt: new Date().toISOString(),
      };
    } else {
      demoUser = {
        id: 'usr_student_demo',
        name: 'Aarav Sharma (Student)',
        teacherShortName: 'aarav',
        email: 'student.aarav@uyanix.in',
        phone: '9000012345',
        classNum: 12,
        school: 'Delhi Public School',
        city: 'Jaipur',
        role: 'student',
        registrationId: 'OEC2609535',
        idVerified: false,
        streakReminders: true,
        createdAt: new Date().toISOString(),
      };
    }

    const sessionToken = signSessionToken(demoUser);
    const res = NextResponse.json({
      ok: true,
      authenticated: true,
      user: demoUser,
      token: sessionToken,
    });
    setSessionCookie(res, sessionToken);
    return res;
  } catch {
    return NextResponse.json(
      { error: 'Unable to process demo login.' },
      { status: 500 }
    );
  }
}
