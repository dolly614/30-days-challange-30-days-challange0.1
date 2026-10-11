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

  try {
    const body = await req.json();
    const role = body?.role || 'student';

    let demoUser: UserProfile;

    if (role === 'admin') {
      demoUser = {
        id: 'usr_admin_dolly',
        name: 'Dolly Singh (Admin)',
        teacherShortName: 'dolly',
        email: 'admin@uyanix.in',
        phone: '9897320579',
        classNum: 12,
        school: 'Uyanix Headquarters',
        city: 'Jaipur',
        role: 'admin',
        idVerified: true,
        streakReminders: true,
        createdAt: new Date().toISOString(),
      };
    } else if (role === 'teacher') {
      demoUser = {
        id: 'usr_teacher_dolly',
        name: 'Dolly Ma’am (Educator)',
        teacherShortName: 'dolly',
        email: 'teacher@uyanix.in',
        phone: '9876543210',
        classNum: 10,
        school: 'KV No. 1, Jaipur',
        city: 'Jaipur',
        role: 'teacher',
        idVerified: true,
        streakReminders: true,
        createdAt: new Date().toISOString(),
      };
    } else {
      demoUser = {
        id: 'usr_student_demo',
        name: 'Dolly Singh',
        teacherShortName: 'dolly',
        email: 'dollysingh1268@gmail.com',
        phone: '9000012345',
        classNum: 12,
        school: 'Delhi Public School',
        city: 'Jaipur',
        role: 'student',
        registrationId: 'OEC2609535',
        idVerified: true,
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
