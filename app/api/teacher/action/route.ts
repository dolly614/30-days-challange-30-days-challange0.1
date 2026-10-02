import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  getClientIp,
  recordServerAuditLog,
  requireTeacherOrAdmin,
} from '@/lib/server-auth';

const ALLOWED_TEACHER_ACTIONS = new Set([
  'REQUEST_WITHDRAWAL',
  'SUBMIT_KYC',
  'SIMULATE_REFERRAL',
]);

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rate = enforceRateLimit(`teacher-action:${ip}`, 30, 5 * 60 * 1000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many requests. Please wait before trying again.' },
      { status: 429 }
    );
  }

  // Centralized Server-Side Teacher/Admin Guard
  const guard = requireTeacherOrAdmin(req);
  if (!guard.ok) {
    return guard.response;
  }

  try {
    const body = await req.json();
    const action = typeof body?.action === 'string' ? body.action.trim() : '';

    if (!action || !ALLOWED_TEACHER_ACTIONS.has(action)) {
      return NextResponse.json(
        { error: 'Invalid teacher action.' },
        { status: 400 }
      );
    }

    // Ownership enforcement: a teacher cannot act on behalf of another teacher's ID
    const requestedTeacherUserId =
      typeof body?.teacherUserId === 'string'
        ? body.teacherUserId.trim()
        : undefined;

    if (
      requestedTeacherUserId &&
      requestedTeacherUserId !== guard.user.id &&
      guard.user.role !== 'admin'
    ) {
      return NextResponse.json(
        {
          error:
            'Forbidden: Teachers can only perform actions on their own account.',
        },
        { status: 403 }
      );
    }

    if (action === 'REQUEST_WITHDRAWAL') {
      const amount = Number(body?.amount);
      const method = body?.method === 'Bank' ? 'Bank' : 'UPI';
      const destination =
        typeof body?.destination === 'string'
          ? body.destination.trim().slice(0, 120)
          : '';

      if (!Number.isFinite(amount) || amount < 500 || !destination) {
        return NextResponse.json(
          { error: 'Minimum ₹500 withdrawal amount and valid destination required.' },
          { status: 400 }
        );
      }

      const audit = recordServerAuditLog({
        actorId: guard.user.id,
        actorEmail: guard.user.email,
        actorRole: guard.user.role,
        action: 'TEACHER_REQUEST_WITHDRAWAL',
        target: `${method}:${destination} (INR ${amount})`,
      });

      return NextResponse.json({
        authorized: true,
        action,
        teacherId: guard.user.id,
        status: 'pending',
        audit,
      });
    }

    if (action === 'SUBMIT_KYC') {
      const pan =
        typeof body?.pan === 'string'
          ? body.pan.trim().toUpperCase().slice(0, 16)
          : '';
      const upiId =
        typeof body?.upiId === 'string' ? body.upiId.trim().slice(0, 120) : '';

      if (!pan || !upiId) {
        return NextResponse.json(
          { error: 'Valid PAN and UPI ID are required for KYC.' },
          { status: 400 }
        );
      }

      // Only an Admin can immediately mark status as approved; a teacher submission stays pending admin review unless already approved
      const approvedStatus =
        guard.user.role === 'admin' ? 'approved' : 'pending';

      const audit = recordServerAuditLog({
        actorId: guard.user.id,
        actorEmail: guard.user.email,
        actorRole: guard.user.role,
        action: 'TEACHER_SUBMIT_KYC',
        target: `${pan} (${upiId}) -> ${approvedStatus}`,
      });

      return NextResponse.json({
        authorized: true,
        action,
        teacherId: guard.user.id,
        status: approvedStatus,
        audit,
      });
    }

    if (action === 'SIMULATE_REFERRAL') {
      return NextResponse.json(
        {
          authorized: false,
          error:
            'Simulated referrals and demo bonuses are disabled in production. Commissions are credited only from verified student registrations and exam payments.',
          errorCode: 'SIMULATION_DISABLED_IN_PRODUCTION',
        },
        { status: 403 }
      );
    }

    const audit = recordServerAuditLog({
      actorId: guard.user.id,
      actorEmail: guard.user.email,
      actorRole: guard.user.role,
      action: `TEACHER_${action}`,
      target: guard.user.id,
    });

    return NextResponse.json({
      authorized: true,
      action,
      teacherId: guard.user.id,
      role: guard.user.role,
      audit,
    });
  } catch {
    return NextResponse.json(
      { error: 'Invalid teacher action request.' },
      { status: 400 }
    );
  }
}
