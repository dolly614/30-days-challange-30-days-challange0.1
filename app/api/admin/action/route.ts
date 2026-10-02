import { NextRequest, NextResponse } from 'next/server';
import {
  assignUserRoleServer,
  enforceRateLimit,
  getClientIp,
  getServerAuditLogs,
  recordServerAuditLog,
  requireAuthenticatedUser,
  setUserBanStatusServer,
  UserRole,
} from '@/lib/server-auth';
import {
  appendImmutableAdminAuditEvent,
  attemptModifyOrDeleteAdminAuditRecord,
  AUTHORITATIVE_ADMIN_ACTION_POLICIES,
  authorizeAdminControlPlaneOperation,
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

const EXTRA_LEGACY_ACTIONS = new Set([
  'REQUEST_APPROVAL',
  'REVIEW_APPROVAL',
  'MODIFY_AUDIT_LOG',
]);

export async function GET(req: NextRequest) {
  const auth = requireAuthenticatedUser(req);
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

  return NextResponse.json(
    {
      authorized: true,
      role: auth.user.role,
      permissions: Array.from(authz.adminAccount.permissions),
      auditLogs: getServerAuditLogs(),
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

  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  if (auth.user.role === 'admin') {
    registerOrSyncAdminAccount({
      userId: auth.user.id,
      email: auth.user.email,
      role: 'ADMIN',
    });
  }

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
      (typeof body?.idempotencyKey === 'string'
        ? body.idempotencyKey
        : undefined);

    const target =
      typeof body?.target === 'string' && body.target.trim()
        ? body.target.trim().slice(0, 128)
        : typeof body?.targetUserId === 'string' && body.targetUserId.trim()
        ? body.targetUserId.trim().slice(0, 128)
        : 'admin_resource';

    // 1. Audit Log Immutability Protection (Section 43)
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

    // 2. Controlled Approval Creation & Four-Eyes Review (Sections 16 & 17)
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

    // 3. Central Server-Side Admin Authorization Gate (Sections 4, 5, 8, 9, 10, 11)
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

    // 4. Role Assignment with Self-Escalation Protection (Sections 18 & 19)
    if (action === 'ASSIGN_USER_ROLE') {
      const targetUserId =
        typeof body?.targetUserId === 'string' ? body.targetUserId.trim() : '';
      const newRole = body?.newRole as UserRole;
      if (!targetUserId) {
        return NextResponse.json(
          { error: 'Missing targetUserId.', errorCode: 'INVALID_INPUT' },
          { status: 400 }
        );
      }

      const controlledRole = executeControlledRoleChange({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        targetUserId,
        currentRole: 'STUDENT',
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

    // 5. Permission Modification with Allowlist & Self-Escalation Guard (Section 20)
    if (action === 'UPDATE_ADMIN_PERMISSIONS') {
      const permRes = executeControlledAdminPermissionChange({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        targetAdminUserId: target,
        requestedPermissions: Array.isArray(body?.requestedPermissions)
          ? (body.requestedPermissions as string[])
          : [],
        reason: String(body?.reason || 'Updated admin permissions'),
        approvalId:
          typeof body?.approvalId === 'string' ? body.approvalId : undefined,
        enforceFourEyesApproval: Boolean(body?.enforceFourEyesApproval),
        requestId,
      });
      if (!permRes.ok) {
        return NextResponse.json(
          { error: permRes.reason, errorCode: permRes.errorCode },
          { status: permRes.httpStatus }
        );
      }
      return NextResponse.json(permRes, { status: 200 });
    }

    // 6. Student Suspension / Restoration (Section 21)
    if (action === 'TOGGLE_BAN_STUDENT') {
      const targetUserId =
        typeof body?.targetUserId === 'string'
          ? body.targetUserId.trim()
          : target;
      const banned = Boolean(body?.banned);
      const banRes = setUserBanStatusServer(auth.user, targetUserId, banned);
      if (!banRes.ok) {
        return NextResponse.json(
          { error: banRes.error },
          { status: banRes.status }
        );
      }
      appendImmutableAdminAuditEvent({
        actorId: auth.user.id,
        actorRole: 'ADMIN',
        action,
        resourceType: 'STUDENT_ACCOUNT',
        resourceId: targetUserId,
        newState: { status: banRes.status },
        reason: banned ? 'Suspended student account' : 'Restored student account',
        requestId,
        result: 'ALLOW',
      });
      return NextResponse.json({
        authorized: true,
        action,
        userId: banRes.userId,
        status: banRes.status,
        actor: auth.user.email,
        timestamp: new Date().toISOString(),
      });
    }

    // 7. Verification State Machine (Section 23)
    if (action === 'HANDLE_VERIFICATION' && body?.targetStatus) {
      const verRes = transitionStudentVerificationState({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        verificationId: target,
        studentId: String(body?.studentId || target),
        targetStatus: String(
          body.targetStatus
        ).toUpperCase() as VerificationWorkflowStatus,
        expectedVersion:
          typeof body?.expectedVersion === 'number'
            ? body.expectedVersion
            : undefined,
        reason: typeof body?.reason === 'string' ? body.reason : undefined,
        requestId,
      });
      if (!verRes.ok) {
        return NextResponse.json(
          { error: verRes.reason, errorCode: verRes.errorCode },
          { status: verRes.httpStatus }
        );
      }
    }

    // 8. Withdrawal Controls (Section 30)
    if (
      (action === 'APPROVE_WITHDRAWAL' ||
        action === 'PROCESS_WITHDRAWAL' ||
        action === 'REJECT_WITHDRAWAL') &&
      body?.withdrawalId
    ) {
      const targetWithdrawalStatus =
        action === 'APPROVE_WITHDRAWAL'
          ? 'APPROVED'
          : action === 'REJECT_WITHDRAWAL'
          ? 'REJECTED'
          : 'PAID';
      const wRes = executeControlledWithdrawalTransition({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        withdrawalId: String(body.withdrawalId),
        teacherId: String(body?.teacherId || 't_default'),
        amountInr: Number(body?.amountInr || 500),
        targetStatus: targetWithdrawalStatus,
        providerPayoutRef:
          typeof body?.providerPayoutRef === 'string'
            ? body.providerPayoutRef
            : undefined,
        expectedVersion:
          typeof body?.expectedVersion === 'number'
            ? body.expectedVersion
            : undefined,
        idempotencyKey,
        reason: typeof body?.reason === 'string' ? body.reason : undefined,
        requestId,
      });
      if (!wRes.ok) {
        return NextResponse.json(
          { error: wRes.reason, errorCode: wRes.errorCode },
          { status: wRes.httpStatus }
        );
      }
      return NextResponse.json(wRes, { status: 200 });
    }

    // 9. Controlled Financial Wallet Adjustment (Section 31)
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

    // 10. Leaderboard Controls (Section 27)
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

    // 11. Authorized Export Controls (Section 34)
    if (action === 'EXPORT_ADMIN_DATA') {
      const exp = executeAuthorizedAdminDataExport({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        exportType:
          body?.exportType === 'STUDENTS' ||
          body?.exportType === 'PAYMENTS' ||
          body?.exportType === 'AUDIT_LOGS'
            ? body.exportType
            : 'LEADERBOARD',
        requestedColumns: Array.isArray(body?.requestedColumns)
          ? (body.requestedColumns as string[])
          : ['rank', 'name', 'classNum', 'city', 'score'],
        rows: Array.isArray(body?.rows)
          ? (body.rows as Record<string, unknown>[])
          : [],
        filterQuery:
          typeof body?.filterQuery === 'string' ? body.filterQuery : undefined,
        requestId,
      });
      if (!exp.ok) {
        return NextResponse.json(
          { error: exp.reason, errorCode: exp.errorCode },
          { status: exp.httpStatus }
        );
      }
      return NextResponse.json(exp, { status: 200 });
    }

    // 12. Controlled Bulk Operations & Bulk Delete Guard (Sections 35 & 36)
    if (action === 'BULK_DELETE_RESOURCES') {
      const bulkRes = executeControlledAdminBulkOperation({
        actorId: auth.user.id,
        actorRole: auth.user.role,
        operationType: 'BULK_DELETE_CHAPTERS',
        resourceIds: Array.isArray(body?.resourceIds)
          ? (body.resourceIds as string[])
          : [],
        unrestrictedDeleteAllAttempt: Boolean(
          body?.unrestrictedDeleteAllAttempt
        ),
        approvalId:
          typeof body?.approvalId === 'string' ? body.approvalId : undefined,
        enforceFourEyesApproval: Boolean(body?.enforceFourEyesApproval),
        reason: String(body?.reason || 'Controlled bulk deletion'),
        requestId,
      });
      if (!bulkRes.ok) {
        return NextResponse.json(
          { error: bulkRes.reason, errorCode: bulkRes.errorCode },
          { status: bulkRes.httpStatus }
        );
      }
      return NextResponse.json(bulkRes, { status: 200 });
    }

    // Record both legacy server audit log and immutable hash-chained admin audit event
    const auditEntry = recordServerAuditLog({
      actorId: auth.user.id,
      actorEmail: auth.user.email,
      actorRole: auth.user.role,
      action,
      target,
    });

    const immutableAudit = appendImmutableAdminAuditEvent({
      actorId: auth.user.id,
      actorRole: 'ADMIN',
      action,
      resourceType: 'ADMIN_RESOURCE',
      resourceId: target,
      reason: `${action} on ${target}`,
      requestId,
      result: 'ALLOW',
    });

    return NextResponse.json({
      authorized: true,
      action,
      actor: auth.user.email,
      role: auth.user.role,
      auditEntry,
      immutableAuditId: immutableAudit.event_id,
      timestamp: auditEntry.timestamp,
    });
  } catch {
    return NextResponse.json(
      {
        error: 'Invalid admin action payload.',
        errorCode: 'MALFORMED_ADMIN_PAYLOAD',
      },
      { status: 400 }
    );
  }
}
