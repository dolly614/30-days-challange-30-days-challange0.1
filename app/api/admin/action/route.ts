import { NextRequest, NextResponse } from 'next/server';
import {
  assignUserRoleServer,
  enforceRateLimit,
  findUserById,
  getClientIp,
  getServerAuditLogs,
  recordServerAuditLog,
  requireAuthenticatedUser,
  requireAuthoritativeAdmin,
  setUserBanStatusServer,
  UserRole,
} from '@/lib/server-auth';
import {
  appendImmutableAdminAuditEvent,
  attemptModifyOrDeleteAdminAuditRecord,
  AUTHORITATIVE_ADMIN_ACTION_POLICIES,
  authorizeAdminControlPlaneOperation,
  CanonicalActorRole,
  createControlledAdminApprovalRequest,
  executeAuthorizedAdminDataExport,
  executeControlledAdminBulkOperation,
  executeControlledAdminPermissionChange,
  executeControlledLeaderboardAdminAction,
  executeControlledRoleChange,
  executeControlledTeacherFinancialAdjustment,
  executeControlledWithdrawalTransition,
  getImmutableAdminAuditTrail,
  reconcileAdminDashboardAndSystemData,
  registerOrSyncAdminAccount,
  reviewAndApproveControlledAdminRequest,
  transitionStudentVerificationState,
  VerificationWorkflowStatus,
} from '@/lib/admin-control-plane-governance';
import {
  authoritativeBroadcastNotification,
  authoritativeExportAdminData,
  authoritativeResetBrandLogo,
  authoritativeSetBrandLogo,
  bulkSaveAuthoritativeChapters,
  deleteClassAuthoritativeChapters,
  recordAuthoritativeAuditEvent,
  resetAllAuthoritativeChapters,
  saveAuthoritativeChapter,
} from '@/lib/admin-authoritative-service';
import {
  authoritativeMarkPrizePaid,
  authoritativeProcessWithdrawal,
  authoritativeRefundPayment,
} from '@/lib/financial-authoritative-service';
import {
  authoritativeHandleVerification,
  authoritativeToggleBanStudent,
  getAuthoritativeAuditLogs,
  getAuthoritativeVerificationSubmissions,
} from '@/lib/admin-verification-authoritative-service';

const EXTRA_LEGACY_ACTIONS = new Set([
  'REQUEST_APPROVAL',
  'REVIEW_APPROVAL',
  'MODIFY_AUDIT_LOG',
  'SAVE_CHAPTER',
  'BULK_SAVE_CHAPTERS',
  'DELETE_CLASS_CHAPTERS',
  'RESET_ALL_CHAPTERS',
  'BROADCAST_NOTIFICATION',
  'SET_BRAND_LOGO',
  'RESET_BRAND_LOGO',
  'UPDATE_TEACHER_STATUS',
  'ADD_EXAM_QUESTION',
  'BULK_IMPORT_EXAM_QUESTIONS',
  'DELETE_EXAM_QUESTION',
]);

export async function GET(req: NextRequest) {
  const auth = await requireAuthoritativeAdmin(req);
  if (!auth.ok) {
    return auth.response;
  }

  // Register/sync authoritative admin account if role === 'admin'
  if (auth.user.role === 'admin') {
    registerOrSyncAdminAccount({
      userId: auth.user.id,
      email: auth.user.email,
      role: 'ADMIN',
    });
  }

  const authz = authorizeAdminControlPlaneOperation({
    actorId: auth.user.id,
    sessionRole: auth.user.role,
    action: 'VIEW_ADMIN_DASHBOARD',
    resourceType: 'ADMIN_DASHBOARD',
    resourceId: 'DASHBOARD_MAIN',
    requestId: req.headers.get('x-request-id') || undefined,
  });

  if (!authz.authorized) {
    return NextResponse.json(
      { error: authz.reason, errorCode: authz.errorCode },
      { status: authz.httpStatus }
    );
  }

  const reconciliation = reconcileAdminDashboardAndSystemData();
  const [auditLogs, verifications] = await Promise.all([
    getAuthoritativeAuditLogs(100),
    getAuthoritativeVerificationSubmissions(50),
  ]);

  return NextResponse.json(
    {
      authorized: true,
      role: auth.user.role,
      permissions: Array.from(authz.adminAccount.permissions),
      auditLogs,
      verifications,
      immutableAuditTrailCount: getImmutableAdminAuditTrail().length,
      reconciliation,
    },
    {
      status: 200,
      headers: { 'Cache-Control': 'private, no-store' },
    }
  );
}

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rate = enforceRateLimit(`admin-action:${ip}`, 60, 5 * 60 * 1000);
  if (!rate.allowed) {
    return NextResponse.json(
      {
        error: 'Too many admin requests. Please wait.',
        errorCode: 'ADMIN_RATE_LIMIT_EXCEEDED',
      },
      { status: 429 }
    );
  }

  const auth = await requireAuthoritativeAdmin(req);
  if (!auth.ok) {
    return auth.response;
  }

  registerOrSyncAdminAccount({
    userId: auth.user.id,
    email: auth.user.email,
    role: 'ADMIN',
  });

  try {
    const body = (await req.json()) as Record<string, unknown>;
    const action = typeof body?.action === 'string' ? body.action.trim() : '';

    if (
      !action ||
      (!(action in AUTHORITATIVE_ADMIN_ACTION_POLICIES) &&
        !EXTRA_LEGACY_ACTIONS.has(action))
    ) {
      return NextResponse.json(
        {
          error: 'Invalid or unsupported admin action.',
          errorCode: 'UNSUPPORTED_ADMIN_ACTION',
        },
        { status: 400 }
      );
    }

    const requestId = req.headers.get('x-request-id') || undefined;
    const idempotencyKey =
      req.headers.get('idempotency-key') ||
      req.headers.get('x-idempotency-key') ||
      (typeof body?.idempotencyKey === 'string'
        ? body.idempotencyKey
        : undefined);

    const target =
      typeof body?.target === 'string' && body.target.trim()
        ? body.target.trim().slice(0, 128)
        : typeof body?.targetUserId === 'string' && body.targetUserId.trim()
        ? body.targetUserId.trim().slice(0, 128)
        : 'admin_resource';

    // 1. Audit Log Immutability Protection (Item 17, 31, 32)
    if (action === 'MODIFY_AUDIT_LOG') {
      const blocked = attemptModifyOrDeleteAdminAuditRecord({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        targetAuditEventId: target,
        operation: body?.operation === 'UPDATE' ? 'UPDATE' : 'DELETE',
        requestId,
      });
      return NextResponse.json(
        { error: blocked.reason, errorCode: blocked.errorCode },
        { status: blocked.httpStatus }
      );
    }

    // 2. Controlled Approval Creation & Four-Eyes Review (Item 18)
    if (action === 'REQUEST_APPROVAL') {
      const created = createControlledAdminApprovalRequest({
        requesterId: auth.user.id,
        action: String(body?.requestedAction || 'FINANCIAL_ADJUSTMENT'),
        resourceType: String(body?.resourceType || 'ADMIN_RESOURCE'),
        resourceId: target,
        reason: String(body?.reason || ''),
        payload:
          body?.payload && typeof body.payload === 'object'
            ? (body.payload as Record<string, unknown>)
            : undefined,
        requestId,
      });
      if (!created.ok) {
        return NextResponse.json(
          { error: created.reason, errorCode: created.errorCode },
          { status: created.httpStatus }
        );
      }
      return NextResponse.json(created, { status: 201 });
    }

    if (action === 'REVIEW_APPROVAL') {
      const reviewed = reviewAndApproveControlledAdminRequest({
        approverId: auth.user.id,
        approvalId: String(body?.approvalId || ''),
        decision:
          body?.decision === 'APPROVED'
            ? 'APPROVED'
            : body?.decision === 'REJECTED'
            ? 'REJECTED'
            : 'UNDER_REVIEW',
        notes: typeof body?.notes === 'string' ? body.notes : undefined,
        requestId,
      });
      if (!reviewed.ok) {
        return NextResponse.json(
          { error: reviewed.reason, errorCode: reviewed.errorCode },
          { status: reviewed.httpStatus }
        );
      }
      return NextResponse.json(reviewed, { status: 200 });
    }

    // 3. Central Server-Side Admin Authorization Gate
    if (action in AUTHORITATIVE_ADMIN_ACTION_POLICIES) {
      const authz = authorizeAdminControlPlaneOperation({
        actorId: auth.user.id,
        sessionRole: auth.user.role,
        action,
        resourceType: String(body?.resourceType || 'ADMIN_RESOURCE'),
        resourceId: target,
        clientPayload: body,
        approvalId:
          typeof body?.approvalId === 'string' ? body.approvalId : undefined,
        enforceFourEyesApproval: Boolean(body?.enforceFourEyesApproval),
        requestId,
      });

      if (!authz.authorized) {
        return NextResponse.json(
          { error: authz.reason, errorCode: authz.errorCode },
          { status: authz.httpStatus }
        );
      }
    }

    // 4. Role Assignment with Self-Escalation Protection & Database Role Lookup (Item 19 & 20)
    if (action === 'ASSIGN_USER_ROLE') {
      const targetUserId =
        typeof body?.targetUserId === 'string' ? body.targetUserId.trim() : '';
      const newRole = body?.newRole as UserRole;
      if (!targetUserId || !newRole) {
        return NextResponse.json(
          { error: 'Missing targetUserId or valid newRole.', errorCode: 'INVALID_INPUT' },
          { status: 400 }
        );
      }

      // Self-escalation / self-modification protection
      if (targetUserId === auth.user.id) {
        return NextResponse.json(
          { error: 'Self-modification of administrative role is strictly prohibited.', errorCode: 'SELF_ESCALATION_BLOCKED' },
          { status: 403 }
        );
      }

      // Look up target's ACTUAL current role from authoritative database (NEVER TRUST CLIENT)
      const targetUserRec = findUserById(targetUserId);
      const actualCurrentRole = (targetUserRec?.profile?.role?.toUpperCase() as CanonicalActorRole) || 'STUDENT';

      const controlledRole = executeControlledRoleChange({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        targetUserId,
        currentRole: actualCurrentRole,
        newRole,
        reason:
          typeof body?.reason === 'string' && body.reason.trim().length >= 5
            ? body.reason
            : `Admin role update for ${targetUserId}`,
        approvalId:
          typeof body?.approvalId === 'string' ? body.approvalId : undefined,
        enforceFourEyesApproval: Boolean(body?.enforceFourEyesApproval),
        requestId,
      });

      if (!controlledRole.ok) {
        return NextResponse.json(
          { error: controlledRole.reason, errorCode: controlledRole.errorCode },
          { status: controlledRole.httpStatus }
        );
      }

      const roleRes = assignUserRoleServer(auth.user, targetUserId, newRole);
      if (!roleRes.ok) {
        return NextResponse.json(
          { error: roleRes.error },
          { status: roleRes.status }
        );
      }

      recordAuthoritativeAuditEvent({
        actorId: auth.user.id,
        actorRole: 'ADMIN',
        action: 'ASSIGN_USER_ROLE',
        resourceType: 'USER_ROLE',
        resourceId: targetUserId,
        previousState: { role: actualCurrentRole },
        newState: { role: newRole },
        reason: `Changed role from ${actualCurrentRole} to ${newRole}`,
        requestId,
      });

      return NextResponse.json({
        authorized: true,
        action,
        userId: roleRes.userId,
        role: roleRes.role,
        actor: auth.user.email,
        auditEventId: controlledRole.auditEvent.event_id,
        timestamp: controlledRole.auditEvent.timestamp,
      });
    }

    // 5. Student Suspension / Restoration (Item 2 & 25)
    if (action === 'TOGGLE_BAN_STUDENT') {
      const targetUserId =
        typeof body?.targetUserId === 'string'
          ? body.targetUserId.trim()
          : target;

      if (typeof body?.banned !== 'boolean') {
        return NextResponse.json(
          { error: 'Explicit boolean "banned" field is required (truthy coercion rejected).', errorCode: 'INVALID_BOOLEAN' },
          { status: 400 }
        );
      }

      const result = await authoritativeToggleBanStudent({
        studentId: targetUserId,
        banned: body.banned,
        actorEmail: auth.user.email,
        actorId: auth.user.id,
        reason: typeof body?.reason === 'string' ? body.reason : undefined,
      });

      setUserBanStatusServer(auth.user, targetUserId, body.banned);

      return NextResponse.json({
        authorized: true,
        ok: true,
        action,
        userId: targetUserId,
        banned: result.banned,
        status: result.status,
        actor: auth.user.email,
        timestamp: new Date().toISOString(),
      });
    }

    // 6. Real Payment Refund (Item 10)
    if (action === 'REFUND_PAYMENT') {
      const paymentId = String(body?.paymentId || target);
      const refundResult = await authoritativeRefundPayment({
        paymentId,
        actorEmail: auth.user.email,
        reason: typeof body?.reason === 'string' ? body.reason : undefined,
        idempotencyKey,
      });

      return NextResponse.json({
        authorized: true,
        ...refundResult,
      });
    }

    // 7. Prize Payment Status (Item 14)
    if (action === 'MARK_PRIZE_PAID') {
      const studentId = String(body?.studentId || target);
      const targetStatus = (body?.targetStatus as 'PAID' | 'PENDING' | 'CANCELLED') || 'PAID';
      const amount = typeof body?.amount === 'number' ? body.amount : 1000;

      const prizeResult = await authoritativeMarkPrizePaid({
        studentId,
        targetStatus,
        actorEmail: auth.user.email,
        amount,
        referenceId: typeof body?.referenceId === 'string' ? body.referenceId : undefined,
        idempotencyKey,
      });

      return NextResponse.json({
        authorized: true,
        ...prizeResult,
      });
    }

    // 8. Withdrawal Workflow (Item 11)
    if (
      action === 'APPROVE_WITHDRAWAL' ||
      action === 'PROCESS_WITHDRAWAL' ||
      action === 'REJECT_WITHDRAWAL'
    ) {
      const withdrawalId = String(body?.withdrawalId || target);
      const targetWithdrawalStatus =
        action === 'APPROVE_WITHDRAWAL'
          ? 'APPROVED'
          : action === 'REJECT_WITHDRAWAL'
          ? 'REJECTED'
          : 'PAID';

      const wResult = await authoritativeProcessWithdrawal({
        withdrawalId,
        targetStatus: targetWithdrawalStatus,
        actorEmail: auth.user.email,
        reason: typeof body?.reason === 'string' ? body.reason : undefined,
        providerPayoutRef: typeof body?.providerPayoutRef === 'string' ? body.providerPayoutRef : undefined,
        expectedVersion: typeof body?.expectedVersion === 'number' ? body.expectedVersion : undefined,
        idempotencyKey,
      });

      return NextResponse.json({
        authorized: true,
        ...wResult,
      });
    }

    // 9. Student Verification State Machine (Item 12)
    if (action === 'HANDLE_VERIFICATION') {
      const verificationId = target;
      const studentId = String(body?.studentId || target);
      const targetStatus = body?.targetStatus === 'approved' || body?.targetStatus === 'verified' ? 'verified' : 'rejected';
      const reason = typeof body?.reason === 'string' ? body.reason : undefined;

      const vResult = await authoritativeHandleVerification({
        verificationId,
        studentId,
        targetStatus,
        actorEmail: auth.user.email,
        actorId: auth.user.id,
        reason,
        expectedVersion: typeof body?.expectedVersion === 'number' ? body.expectedVersion : undefined,
      });

      return NextResponse.json({
        authorized: true,
        ...vResult,
      });
    }

    // 10. Broadcast Push Notification (Item 29)
    if (action === 'BROADCAST_NOTIFICATION') {
      const title = typeof body?.title === 'string' ? body.title.trim() : '';
      const messageBody = typeof body?.body === 'string' ? body.body.trim() : '';

      if (!title || !messageBody) {
        return NextResponse.json(
          { error: 'Title and body are required for broadcast notifications.', errorCode: 'INVALID_INPUT' },
          { status: 400 }
        );
      }

      const notifResult = await authoritativeBroadcastNotification({
        title,
        body: messageBody,
        actorEmail: auth.user.email,
        targetScope: typeof body?.targetScope === 'string' ? body.targetScope : undefined,
      });

      return NextResponse.json({
        authorized: true,
        ...notifResult,
      });
    }

    // 11. Brand Logo Server Storage (Item 30)
    if (action === 'SET_BRAND_LOGO') {
      const logoUrl = typeof body?.logoUrl === 'string' ? body.logoUrl.trim() : '';
      if (!logoUrl) {
        return NextResponse.json(
          { error: 'Missing logoUrl.', errorCode: 'INVALID_INPUT' },
          { status: 400 }
        );
      }
      const logoResult = await authoritativeSetBrandLogo(logoUrl, auth.user.email);
      return NextResponse.json({ authorized: true, ...logoResult });
    }

    if (action === 'RESET_BRAND_LOGO') {
      const resetResult = await authoritativeResetBrandLogo(auth.user.email);
      return NextResponse.json({ authorized: true, ...resetResult });
    }

    // 12. Chapters Database Actions (Item 5)
    if (action === 'SAVE_CHAPTER') {
      const chapter = await saveAuthoritativeChapter({
        classNum: Number(body?.classNum),
        day: Number(body?.day),
        title: String(body?.title || ''),
        content: String(body?.content || ''),
        actorEmail: auth.user.email,
      });
      return NextResponse.json({ authorized: true, ok: true, chapter });
    }

    if (action === 'BULK_SAVE_CHAPTERS') {
      const result = await bulkSaveAuthoritativeChapters({
        classNum: Number(body?.classNum),
        items: Array.isArray(body?.items) ? (body.items as any) : [],
        overwrite: Boolean(body?.overwrite),
        actorEmail: auth.user.email,
      });
      return NextResponse.json({ authorized: true, ok: true, ...result });
    }

    if (action === 'DELETE_CLASS_CHAPTERS') {
      const result = await deleteClassAuthoritativeChapters(Number(body?.classNum), auth.user.email);
      return NextResponse.json({ authorized: true, ok: true, ...result });
    }

    if (action === 'RESET_ALL_CHAPTERS') {
      const result = await resetAllAuthoritativeChapters(auth.user.email);
      return NextResponse.json({ authorized: true, ok: true, ...result });
    }

    // 13. Server-Generated Export (Item 16)
    if (action === 'EXPORT_ADMIN_DATA') {
      const exp = await authoritativeExportAdminData({
        exportType: (body?.exportType as any) || 'LEADERBOARD',
        requestedColumns: Array.isArray(body?.requestedColumns)
          ? (body.requestedColumns as string[])
          : ['rank', 'name', 'classNum', 'city', 'score'],
        actorEmail: auth.user.email,
        limit: typeof body?.limit === 'number' ? body.limit : 500,
      });
      return NextResponse.json({ authorized: true, ok: true, ...exp });
    }

    // 14. Financial Adjustments & Other Governance Operations
    if (action === 'FINANCIAL_ADJUSTMENT') {
      const adj = executeControlledTeacherFinancialAdjustment({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        teacherId: target,
        deltaMinor: Number(body?.deltaMinor || 0),
        reason: String(body?.reason || ''),
        approvalId: String(body?.approvalId || ''),
        requestId,
      });
      if (!adj.ok) {
        return NextResponse.json(
          { error: adj.reason, errorCode: adj.errorCode },
          { status: adj.httpStatus }
        );
      }
      return NextResponse.json(adj, { status: 200 });
    }

    if (action === 'FINALIZE_LEADERBOARD') {
      const lb = executeControlledLeaderboardAdminAction({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        operation:
          body?.operation === 'FREEZE' ||
          body?.operation === 'REOPEN' ||
          body?.operation === 'RECALCULATE'
            ? body.operation
            : 'FINALIZE',
        arbitraryManualRankOverride:
          typeof body?.arbitraryManualRankOverride === 'number'
            ? body.arbitraryManualRankOverride
            : undefined,
        reason: String(body?.reason || 'Finalized leaderboard'),
        requestId,
      });
      if (!lb.ok) {
        return NextResponse.json(
          { error: lb.reason, errorCode: lb.errorCode },
          { status: lb.httpStatus }
        );
      }
      return NextResponse.json(lb, { status: 200 });
    }

    // Record audit event
    const auditEntry = recordAuthoritativeAuditEvent({
      actorId: auth.user.email,
      actorRole: 'ADMIN',
      action,
      resourceType: 'ADMIN_RESOURCE',
      resourceId: target,
      reason: `${action} executed by ${auth.user.email}`,
      requestId,
    });

    return NextResponse.json({
      authorized: true,
      ok: true,
      action,
      actor: auth.user.email,
      auditEntry,
      timestamp: auditEntry.timestamp,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Invalid admin action payload.';
    return NextResponse.json(
      {
        error: message,
        errorCode: 'ADMIN_ACTION_FAILED',
      },
      { status: 400 }
    );
  }
}
