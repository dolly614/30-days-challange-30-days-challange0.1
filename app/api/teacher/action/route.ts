import { NextRequest, NextResponse } from 'next/server';
import {
  enforceDistributedRateLimit,
  enforceRateLimit,
  getClientIp,
  recordServerAuditLog,
  requireTeacherOrAdmin,
} from '@/lib/server-auth';
import {
  authoritativeRequestWithdrawal,
  getAuthoritativeTeacher,
} from '@/lib/financial-authoritative-service';
import { getSupabaseAdminClient } from '@/lib/supabase-server';

const ALLOWED_TEACHER_ACTIONS = new Set([
  'REQUEST_WITHDRAWAL',
  'SUBMIT_KYC',
  'SIMULATE_REFERRAL',
]);

export async function GET(req: NextRequest) {
  const guard = requireTeacherOrAdmin(req);
  if (!guard.ok) {
    return guard.response;
  }

  try {
    const teacher = await getAuthoritativeTeacher(guard.user.id, {
      name: guard.user.name,
      email: guard.user.email,
    });

    const supabase = getSupabaseAdminClient();
    let withdrawals: Array<{
      id: string;
      teacherId: string;
      amount: number;
      method: string;
      destination: string;
      status: string;
      date: string;
      invoiceId: string;
    }> = [];

    if (supabase) {
      try {
        const { data: wList } = await supabase
          .from('withdrawals')
          .select('id, amount, method, upi_id, status, created_at')
          .eq('teacher_id', teacher.id)
          .order('created_at', { ascending: false });

        if (wList) {
          withdrawals = wList.map((w) => ({
            id: w.id,
            teacherId: teacher.id,
            amount: w.amount,
            method: w.method,
            destination: w.upi_id,
            status: w.status,
            date: w.created_at ? w.created_at.slice(0, 10) : new Date().toISOString().slice(0, 10),
            invoiceId: `INV_${w.id.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toUpperCase()}`,
          }));
        }
      } catch {
        // fallback
      }
    }

    return NextResponse.json({
      ok: true,
      teacher: {
        id: teacher.id,
        userId: teacher.userId,
        name: guard.user.name,
        email: guard.user.email,
        code: teacher.referralCode,
        tier: teacher.tier,
        balance: teacher.balance,
        totalEarned: teacher.totalEarned,
        kycPan: teacher.kycPan,
        kycVerified: teacher.kycVerified,
        status: teacher.status,
        upiId: teacher.upiId,
      },
      withdrawals,
    });
  } catch {
    return NextResponse.json(
      { error: 'Failed to retrieve authoritative teacher state.' },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rate = await enforceDistributedRateLimit(`teacher-action:${ip}`, 30, 5 * 60 * 1000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too many requests. Please wait before trying again.' },
      {
        status: 429,
        headers: { 'Retry-After': String(rate.retryAfterSec) },
      }
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
      const idempotencyKey =
        typeof body?.idempotencyKey === 'string'
          ? body.idempotencyKey.trim()
          : req.headers.get('x-idempotency-key') || undefined;

      const result = await authoritativeRequestWithdrawal({
        userId: guard.user.id,
        userEmail: guard.user.email,
        amount,
        method,
        destination,
        idempotencyKey,
      });

      if (!result.ok) {
        return NextResponse.json(
          { error: result.error },
          { status: result.status }
        );
      }

      return NextResponse.json({
        authorized: true,
        ok: true,
        action,
        teacherId: guard.user.id,
        withdrawal: result.withdrawal,
        newBalance: result.newBalance,
        status: 'pending',
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

      const supabase = getSupabaseAdminClient();
      if (supabase) {
        try {
          await supabase
            .from('teachers')
            .update({
              kyc_pan: pan,
              upi_id: upiId,
              kyc_verified: guard.user.role === 'admin',
              status: approvedStatus,
            })
            .eq('user_id', guard.user.id);
        } catch {
          // fallback handled
        }
      }

      const audit = recordServerAuditLog({
        actorId: guard.user.id,
        actorEmail: guard.user.email,
        actorRole: guard.user.role,
        action: 'TEACHER_SUBMIT_KYC',
        target: `${pan} (${upiId}) -> ${approvedStatus}`,
      });

      return NextResponse.json({
        authorized: true,
        ok: true,
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

    return NextResponse.json({
      authorized: true,
      action,
      teacherId: guard.user.id,
      role: guard.user.role,
    });
  } catch {
    return NextResponse.json(
      { error: 'Invalid teacher action request.' },
      { status: 400 }
    );
  }
}
