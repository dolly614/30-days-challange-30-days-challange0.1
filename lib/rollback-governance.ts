import {
  createAuthDatabaseBackup,
  emergencyRevokeCompromisedSessions,
  restoreAuthDatabaseFromBackup,
  recordServerAuditLog,
  verifyAuthEnvironmentConfig,
} from '@/lib/server-auth';

export type VerificationStatus = 'PASS' | 'FAIL' | 'BLOCKED';
export type BlockedRiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type OverallRollbackStatus = 'ROLLBACK SUCCESSFUL' | 'ROLLBACK INCOMPLETE';

export interface RollbackOwnerRecord {
  responsibility:
    | 'Primary Rollback'
    | 'Database Recovery'
    | 'Authentication Security'
    | 'Deployment'
    | 'Incident Communication';
  primaryOwner: string;
  backupOwner: string;
  productionAuthorityConfirmed: true;
}

export const ROLLBACK_OWNERSHIP_MATRIX: readonly RollbackOwnerRecord[] = [
  {
    responsibility: 'Primary Rollback',
    primaryOwner: 'Dolly Singh (Lead Platform & Release Authority — dollysingh1268@gmail.com)',
    backupOwner: 'Vikramaditya Rathore (Principal SRE & Release Deputy)',
    productionAuthorityConfirmed: true,
  },
  {
    responsibility: 'Database Recovery',
    primaryOwner: 'Ananya Deshmukh (Lead Database Reliability Engineer)',
    backupOwner: 'Rohan Kulkarni (Senior Data Infrastructure Engineer)',
    productionAuthorityConfirmed: true,
  },
  {
    responsibility: 'Authentication Security',
    primaryOwner: 'Siddharth Verma (Lead Application Security & IAM Architect)',
    backupOwner: 'Meera Krishnan (Senior Security Operations Engineer)',
    productionAuthorityConfirmed: true,
  },
  {
    responsibility: 'Deployment',
    primaryOwner: 'Vikramaditya Rathore (Principal SRE & Release Deputy)',
    backupOwner: 'Arjun Nair (Senior Cloud Platform Engineer)',
    productionAuthorityConfirmed: true,
  },
  {
    responsibility: 'Incident Communication',
    primaryOwner: 'Priya Sharma (Engineering Incident Commander)',
    backupOwner: 'Karan Malhotra (Technical Operations Lead)',
    productionAuthorityConfirmed: true,
  },
] as const;

export type VerificationAreaId =
  | 'Application Version'
  | 'Authentication Health'
  | 'Session Health'
  | 'Logout'
  | 'Authorization'
  | 'Password Recovery'
  | 'OTP'
  | 'Database Integrity'
  | 'API Health'
  | 'Security Integrity'
  | 'Client-State Manipulation'
  | 'Production Error Health'
  | 'Credential/Session Exposure'
  | 'UI Regression'
  | 'Incident Documentation'
  | 'Final Recovery Sign-off';

export const CRITICAL_VERIFICATION_AREAS: ReadonlySet<VerificationAreaId> = new Set([
  'Authentication Health',
  'Session Health',
  'Logout',
  'Authorization',
  'Database Integrity',
  'API Health',
  'Security Integrity',
  'Credential/Session Exposure',
  'Client-State Manipulation',
]);

export interface VerificationAttemptHistory {
  attemptNumber: number;
  status: VerificationStatus;
  timestamp: string;
  evidenceSummary: string;
  remediationApplied?: string;
}

export interface AreaVerificationRecord {
  area: VerificationAreaId;
  critical: boolean;
  primaryOwner: string;
  backupOwner: string;
  independentReviewer?: string;
  status: VerificationStatus;
  environment: 'development' | 'staging' | 'production' | 'test';
  timestamp: string;
  evidence: string;
  blockingReasonOrFailure: string;
  retestPerformed: boolean;
  history: VerificationAttemptHistory[];
}

export interface BlockedExceptionRecord {
  id: string; // e.g. BR-001
  area: VerificationAreaId;
  riskLevel: BlockedRiskLevel;
  primaryOwner: string;
  backupOwner: string;
  blockedReason: string;
  missingDependency: string;
  dateTimeBlocked: string;
  requiredResolution: string;
  deadline: string; // Strictly YYYY-MM-DD HH:MM TIMEZONE
  containmentMeasure: string;
  hasReliableContainment: boolean;
  extensionCount: number;
  maxExtensionsAllowed: 2;
  approver?: string;
  escalationOwner: string;
  status: 'BLOCKED' | 'RESOLVED_PASS';
  history: string[];
}

export interface FourEyesAuthorization {
  action:
    | 'PRODUCTION_DATABASE_RESTORATION'
    | 'MASS_SESSION_REVOCATION'
    | 'AUTH_SECRET_ROTATION'
    | 'DESTRUCTIVE_MIGRATION_REVERSAL'
    | 'EMERGENCY_CREDENTIAL_ROTATION';
  initiatorOwner: string;
  secondAuthorizedReviewer: string;
  timestamp: string;
  reason: string;
}

export interface RollbackHandoffRecord {
  currentProductionVersion: string;
  lastKnownGoodVersion: string;
  currentDeploymentStatus: string;
  rollbackStarted: boolean;
  databaseMigrationStatus: string;
  authSessionImpact: string;
  testsAlreadyPerformed: string[];
  remainingActions: string[];
  knownSecurityExposure: string;
  previousOwner: string;
  newOwner: string;
  acknowledgedByNewOwner: boolean;
  timestamp: string;
}

const ABSOLUTE_DEADLINE_REGEX =
  /^\d{4}-\d{2}-\d{2} \d{2}:\d{2} (IST|UTC|[A-Z]{2,5}|[+-]\d{2}:\d{2})$/;

/**
 * Validates that an absolute deadline follows YYYY-MM-DD HH:MM TIMEZONE format
 * and rejects vague deadlines such as "ASAP", "Later today", or "Tomorrow".
 */
export function validateAbsoluteDeadlineFormat(deadline: string): boolean {
  if (!deadline || typeof deadline !== 'string') return false;
  return ABSOLUTE_DEADLINE_REGEX.test(deadline.trim());
}

/**
 * Enforces the Four-Eyes Rule before executing any high-risk irreversible rollback action.
 * Requires two distinct, named authorized owners.
 */
export function verifyFourEyesApproval(auth: FourEyesAuthorization): {
  ok: boolean;
  error?: string;
} {
  const initiator = (auth.initiatorOwner || '').trim();
  const reviewer = (auth.secondAuthorizedReviewer || '').trim();

  if (!initiator || !reviewer) {
    return {
      ok: false,
      error: 'Four-Eyes Rule violation: Both initiator and second authorized reviewer are required.',
    };
  }

  if (initiator.toLowerCase() === reviewer.toLowerCase()) {
    return {
      ok: false,
      error:
        'Four-Eyes Rule violation: Initiator and second authorized reviewer must be two distinct authorized individuals.',
    };
  }

  recordServerAuditLog({
    actorId: initiator,
    actorEmail: 'governance@uyanix.in',
    actorRole: 'admin',
    action: `FOUR_EYES_APPROVED_${auth.action}`,
    target: `reviewer:${reviewer} | reason:${auth.reason}`,
  });

  return { ok: true };
}

/**
 * Executes a Four-Eyes-verified non-destructive database rollback restore.
 */
export function executeAuthorizedDatabaseRollback(params: {
  fourEyes: FourEyesAuthorization;
  backupPath?: string;
}):
  | { ok: true; restoredUsers: number; preservedNewUsers: number }
  | { ok: false; error: string } {
  const approval = verifyFourEyesApproval(params.fourEyes);
  if (!approval.ok) {
    return { ok: false, error: approval.error! };
  }
  const res = restoreAuthDatabaseFromBackup(params.backupPath);
  if (!res.ok) {
    return { ok: false, error: 'Backup file unavailable or invalid.' };
  }
  return {
    ok: true,
    restoredUsers: res.restoredUsers,
    preservedNewUsers: res.preservedNewUsers,
  };
}

/**
 * Executes a Four-Eyes-verified emergency mass session revocation.
 */
export function executeAuthorizedEmergencySessionRevocation(params: {
  fourEyes: FourEyesAuthorization;
  userId?: string;
  familyId?: string;
}): { ok: true; revokedCount: number } | { ok: false; error: string } {
  const approval = verifyFourEyesApproval(params.fourEyes);
  if (!approval.ok) {
    return { ok: false, error: approval.error! };
  }
  const res = emergencyRevokeCompromisedSessions({
    userId: params.userId,
    familyId: params.familyId,
    reason: params.fourEyes.reason,
  });
  return { ok: true, revokedCount: res.revokedCount };
}

/**
 * Evaluates a Blocked Exception extension request under the Maximum Extension Rule (max 2 extensions)
 * and Critical Blocked Item Rule (CRITICAL items cannot be deferred for final sign-off).
 */
export function requestBlockedDeadlineExtension(params: {
  record: BlockedExceptionRecord;
  newDeadline: string;
  reasonForExtension: string;
  approver: string;
}):
  | { ok: true; updated: BlockedExceptionRecord; escalatedToIncidentOwner: boolean }
  | { ok: false; error: string; escalatedToIncidentOwner: boolean } {
  if (!validateAbsoluteDeadlineFormat(params.newDeadline)) {
    return {
      ok: false,
      error: 'Deadline must use exact YYYY-MM-DD HH:MM TIMEZONE format.',
      escalatedToIncidentOwner: false,
    };
  }

  if (params.record.riskLevel === 'CRITICAL') {
    return {
      ok: false,
      error:
        'CRITICAL security or database blocked items cannot receive multi-hour/multi-day exception extensions for sign-off.',
      escalatedToIncidentOwner: true,
    };
  }

  if (params.record.extensionCount >= params.record.maxExtensionsAllowed) {
    return {
      ok: false,
      error:
        'Maximum Extension Rule exceeded (>2 extensions): Item must be escalated to the Engineering Incident Owner.',
      escalatedToIncidentOwner: true,
    };
  }

  const nextCount = params.record.extensionCount + 1;
  const updated: BlockedExceptionRecord = {
    ...params.record,
    deadline: params.newDeadline,
    extensionCount: nextCount,
    approver: params.approver,
    history: [
      ...params.record.history,
      `Extension #${nextCount} approved by ${params.approver} -> ${params.newDeadline} (${params.reasonForExtension})`,
    ],
  };

  return {
    ok: true,
    updated,
    escalatedToIncidentOwner: false,
  };
}

/**
 * Calculates the authoritative Overall Rollback Status according to Section 10, 11, 12, 13, 19, and 21.
 * Absence of evidence (BLOCKED) or any critical/required FAIL always yields ROLLBACK INCOMPLETE.
 */
export function evaluateOverallRollbackStatus(params: {
  verifications: readonly AreaVerificationRecord[];
  blockedRegister: readonly BlockedExceptionRecord[];
  unresolvedSecurityExposure: boolean;
  databaseIntegrityConfirmed: boolean;
  productionMonitoringAvailable: boolean;
  allRequiredOwnersSignedOff: boolean;
}): {
  overallStatus: OverallRollbackStatus;
  reasons: string[];
} {
  const reasons: string[] = [];

  if (params.unresolvedSecurityExposure) {
    reasons.push('Security Override: Unresolved critical credential/session security exposure.');
  }

  if (!params.databaseIntegrityConfirmed) {
    reasons.push('Database Override: Database integrity is not confirmed.');
  }

  if (!params.productionMonitoringAvailable) {
    reasons.push('Production Monitoring Override: Required production error monitoring is unavailable.');
  }

  if (!params.allRequiredOwnersSignedOff) {
    reasons.push('Owner Sign-off Rule: One or more required verification owners have not signed off.');
  }

  for (const v of params.verifications) {
    if (v.status === 'FAIL') {
      reasons.push(
        `${v.critical ? 'Critical' : 'Required'} Area FAIL: ${v.area} (${v.blockingReasonOrFailure})`
      );
    } else if (v.status === 'BLOCKED') {
      reasons.push(
        `${v.critical ? 'Critical' : 'Required'} Area BLOCKED: ${v.area} (${v.blockingReasonOrFailure})`
      );
    }
  }

  for (const b of params.blockedRegister) {
    if (b.status === 'BLOCKED') {
      if (b.riskLevel === 'CRITICAL' || b.riskLevel === 'HIGH') {
        reasons.push(
          `Open ${b.riskLevel} Blocked Item (${b.id} - ${b.area}): Cannot declare ROLLBACK SUCCESSFUL.`
        );
      } else if (!b.hasReliableContainment || !validateAbsoluteDeadlineFormat(b.deadline)) {
        reasons.push(
          `Open ${b.riskLevel} Blocked Item (${b.id} - ${b.area}) lacks verified containment or valid absolute deadline.`
        );
      }
    }
  }

  return {
    overallStatus: reasons.length === 0 ? 'ROLLBACK SUCCESSFUL' : 'ROLLBACK INCOMPLETE',
    reasons,
  };
}

/**
 * Helper to verify preflight & rollback readiness programmatic state.
 */
export function getRollbackReadinessSummary(commitSha: string) {
  const env = verifyAuthEnvironmentConfig();
  const backup = createAuthDatabaseBackup();
  return {
    ownershipMatrixComplete: ROLLBACK_OWNERSHIP_MATRIX.every(
      (r) =>
        Boolean(r.primaryOwner) &&
        Boolean(r.backupOwner) &&
        r.primaryOwner !== r.backupOwner &&
        r.productionAuthorityConfirmed === true
    ),
    rollbackCommitSha: commitSha,
    environmentConfigOk: env.ok,
    databaseBackupVerified: backup.ok,
    backupPath: backup.backupPath,
  };
}

// ============================================================================
// ROLLBACK VS. RECOVERY SIGN-OFF LIFECYCLE STATE MACHINE (SECTIONS 1–20)
// ============================================================================

export type RollbackMacroStage =
  | 'STATE_1_ROLLBACK_ACTION'
  | 'STATE_2_RECOVERY_VERIFICATION'
  | 'STATE_3_RECOVERY_SIGN_OFF';

export type RollbackLifecycleState =
  | 'INCIDENT_DETECTED'
  | 'ROLLBACK_INITIATED'
  | 'ROLLBACK_ACTION_COMPLETE'
  | 'ROLLBACK_ACTION_FAILED'
  | 'RECOVERY_VERIFICATION_IN_PROGRESS'
  | 'RECOVERY_VERIFICATION_FAILED'
  | 'RECOVERY_VERIFICATION_BLOCKED'
  | 'RECOVERY_VERIFIED'
  | 'RECOVERY_SIGN_OFF_COMPLETE'
  | 'NORMAL_OPERATIONS';

export interface TechnicalRollbackEvidence {
  intendedKnownGoodCommitActivated: boolean;
  restoredCommitSha: string;
  failedDeploymentRemoved: boolean;
  deploymentReportsHealthy: boolean;
  allInstancesOnIntendedVersion: boolean;
  requiredConfigurationRestored: boolean;
  requiredDatabaseActionCompleted: boolean;
  noUnfinishedDeploymentOperation: boolean;
}

export interface IncidentStatusTimeline {
  incidentDetectedAt: string | null;
  rollbackStartedAt: string | null;
  rollbackActionCompletedAt: string | null;
  recoveryVerificationStartedAt: string | null;
  recoveryVerificationCompletedAt: string | null;
  recoveryVerifiedAt: string | null;
  recoverySignOffCompletedAt: string | null;
  incidentClosedAt: string | null;
}

export interface SpecialistDomainSignOff {
  domain:
    | 'Deployment/Rollback'
    | 'Database Recovery'
    | 'Authentication'
    | 'Authentication Security'
    | 'Backend/API'
    | 'Frontend/QA'
    | 'Observability'
    | 'Incident Communication'
    | 'Primary Rollback Coordination'
    | 'Final Recovery Acceptance';
  ownerName: string;
  status: VerificationStatus;
  signedOffAt: string | null;
  evidenceReviewed: boolean;
}

/**
 * Section 14: Enforces that the Primary Rollback Owner cannot silently override
 * a specialist owner's FAIL or BLOCKED into PASS without remediation, retest,
 * and the specialist owner's explicit sign-off.
 */
export function validateSpecialistStatusTransition(params: {
  area: VerificationAreaId;
  previousStatus: VerificationStatus;
  requestedNewStatus: VerificationStatus;
  actorName: string;
  areaPrimaryOwner: string;
  remediationDocumented: boolean;
  retestExecutedAndPassed: boolean;
  specialistOwnerApproved: boolean;
}): { ok: boolean; error?: string } {
  if (
    (params.previousStatus === 'FAIL' || params.previousStatus === 'BLOCKED') &&
    params.requestedNewStatus === 'PASS'
  ) {
    if (!params.remediationDocumented || !params.retestExecutedAndPassed) {
      return {
        ok: false,
        error: `Cannot convert ${params.area} from ${params.previousStatus} to PASS without documented remediation and a passing retest.`,
      };
    }
    if (!params.specialistOwnerApproved) {
      return {
        ok: false,
        error: `Primary Rollback Owner or coordinator (${params.actorName}) cannot override specialist owner (${params.areaPrimaryOwner}) ${params.previousStatus} without specialist sign-off.`,
      };
    }
  }
  return { ok: true };
}

/**
 * Evaluates the exact stage in the Rollback vs. Recovery Sign-Off State Machine (Sections 5–19).
 * Strictly separates:
 *   Rollback Action Complete ≠ Recovery Verified ≠ Recovery Sign-off Complete ≠ Incident Closed
 */
export function evaluateRollbackRecoveryLifecycle(params: {
  technicalRollback: TechnicalRollbackEvidence;
  verificationStarted: boolean;
  verifications: readonly AreaVerificationRecord[];
  blockedRegister: readonly BlockedExceptionRecord[];
  specialistSignOffs: readonly SpecialistDomainSignOff[];
  unresolvedSecurityExposure: boolean;
  databaseIntegrityConfirmed: boolean;
  productionMonitoringAvailable: boolean;
  incidentEvidenceComplete: boolean;
  remainingNonCriticalFollowUpDocumented: boolean;
  timeline: IncidentStatusTimeline;
}): {
  macroStage: RollbackMacroStage;
  lifecycleState: RollbackLifecycleState;
  rollbackActionComplete: boolean;
  recoveryVerified: boolean;
  recoverySignOffComplete: boolean;
  incidentResolved: boolean;
  verificationClassification: 'VERIFIED PASS' | 'APPROVED TEMPORARY EXCEPTION' | 'INCOMPLETE';
  summaryStatement: string;
  sanitizedTimeline: IncidentStatusTimeline;
  blockingReasons: string[];
} {
  const blockingReasons: string[] = [];

  const rollbackActionComplete =
    params.technicalRollback.intendedKnownGoodCommitActivated &&
    params.technicalRollback.failedDeploymentRemoved &&
    params.technicalRollback.deploymentReportsHealthy &&
    params.technicalRollback.allInstancesOnIntendedVersion &&
    params.technicalRollback.requiredConfigurationRestored &&
    params.technicalRollback.requiredDatabaseActionCompleted &&
    params.technicalRollback.noUnfinishedDeploymentOperation;

  // Section 18: Never populate future timeline stages if they have not genuinely completed
  const sanitizedTimeline: IncidentStatusTimeline = {
    incidentDetectedAt: params.timeline.incidentDetectedAt,
    rollbackStartedAt: params.timeline.rollbackStartedAt,
    rollbackActionCompletedAt: rollbackActionComplete
      ? params.timeline.rollbackActionCompletedAt
      : null,
    recoveryVerificationStartedAt:
      rollbackActionComplete && params.verificationStarted
        ? params.timeline.recoveryVerificationStartedAt
        : null,
    recoveryVerificationCompletedAt: null,
    recoveryVerifiedAt: null,
    recoverySignOffCompletedAt: null,
    incidentClosedAt: null,
  };

  if (!rollbackActionComplete) {
    blockingReasons.push(
      'Technical rollback action is incomplete or failed to restore all instances to the known-good commit.'
    );
    return {
      macroStage: 'STATE_1_ROLLBACK_ACTION',
      lifecycleState: 'ROLLBACK_ACTION_FAILED',
      rollbackActionComplete: false,
      recoveryVerified: false,
      recoverySignOffComplete: false,
      incidentResolved: false,
      verificationClassification: 'INCOMPLETE',
      summaryStatement:
        'ROLLBACK ACTION FAILED: Technical restoration of the known-good deployment is not complete.',
      sanitizedTimeline,
      blockingReasons,
    };
  }

  if (!params.verificationStarted || params.verifications.length === 0) {
    return {
      macroStage: 'STATE_1_ROLLBACK_ACTION',
      lifecycleState: 'ROLLBACK_ACTION_COMPLETE',
      rollbackActionComplete: true,
      recoveryVerified: false,
      recoverySignOffComplete: false,
      incidentResolved: false,
      verificationClassification: 'INCOMPLETE',
      summaryStatement:
        'ROLLBACK ACTION COMPLETE: Known-good version is active, but recovery verification has not yet completed.',
      sanitizedTimeline,
      blockingReasons: ['Recovery verification has not yet been executed.'],
    };
  }

  const hasFail = params.verifications.some((v) => v.status === 'FAIL');
  const hasCriticalBlocked =
    params.verifications.some((v) => v.critical && v.status === 'BLOCKED') ||
    params.blockedRegister.some(
      (b) =>
        b.status === 'BLOCKED' &&
        (b.riskLevel === 'CRITICAL' || b.riskLevel === 'HIGH')
    );
  const hasAnyUncontainedBlocked = params.blockedRegister.some(
    (b) =>
      b.status === 'BLOCKED' &&
      (!b.hasReliableContainment || !validateAbsoluteDeadlineFormat(b.deadline))
  );

  if (hasFail || params.unresolvedSecurityExposure || !params.databaseIntegrityConfirmed) {
    if (hasFail) {
      for (const f of params.verifications.filter((v) => v.status === 'FAIL')) {
        blockingReasons.push(`Area FAIL: ${f.area} (${f.blockingReasonOrFailure})`);
      }
    }
    if (params.unresolvedSecurityExposure) {
      blockingReasons.push('Unresolved critical credential/session security exposure.');
    }
    if (!params.databaseIntegrityConfirmed) {
      blockingReasons.push('Database integrity is not confirmed.');
    }
    return {
      macroStage: 'STATE_2_RECOVERY_VERIFICATION',
      lifecycleState: 'RECOVERY_VERIFICATION_FAILED',
      rollbackActionComplete: true,
      recoveryVerified: false,
      recoverySignOffComplete: false,
      incidentResolved: false,
      verificationClassification: 'INCOMPLETE',
      summaryStatement:
        'RECOVERY VERIFICATION FAILED: One or more required recovery verification checks failed.',
      sanitizedTimeline,
      blockingReasons,
    };
  }

  if (
    hasCriticalBlocked ||
    hasAnyUncontainedBlocked ||
    !params.productionMonitoringAvailable
  ) {
    if (hasCriticalBlocked) {
      blockingReasons.push('One or more critical/high verification areas remain BLOCKED.');
    }
    if (hasAnyUncontainedBlocked) {
      blockingReasons.push('Blocked item lacks verified containment or absolute deadline.');
    }
    if (!params.productionMonitoringAvailable) {
      blockingReasons.push('Required production error monitoring is unavailable.');
    }
    return {
      macroStage: 'STATE_2_RECOVERY_VERIFICATION',
      lifecycleState: 'RECOVERY_VERIFICATION_BLOCKED',
      rollbackActionComplete: true,
      recoveryVerified: false,
      recoverySignOffComplete: false,
      incidentResolved: false,
      verificationClassification: 'INCOMPLETE',
      summaryStatement:
        'RECOVERY VERIFICATION BLOCKED: Required verification evidence or monitoring is unavailable.',
      sanitizedTimeline,
      blockingReasons,
    };
  }

  // All required & critical areas passed!
  sanitizedTimeline.recoveryVerificationCompletedAt =
    params.timeline.recoveryVerificationCompletedAt;
  sanitizedTimeline.recoveryVerifiedAt = params.timeline.recoveryVerifiedAt;

  const openLowOrMediumExceptions = params.blockedRegister.filter(
    (b) =>
      b.status === 'BLOCKED' &&
      (b.riskLevel === 'LOW' || b.riskLevel === 'MEDIUM') &&
      b.hasReliableContainment &&
      validateAbsoluteDeadlineFormat(b.deadline)
  );

  const verificationClassification: 'VERIFIED PASS' | 'APPROVED TEMPORARY EXCEPTION' =
    openLowOrMediumExceptions.length === 0
      ? 'VERIFIED PASS'
      : 'APPROVED TEMPORARY EXCEPTION';

  const allSpecialistsSignedOff =
    params.specialistSignOffs.length > 0 &&
    params.specialistSignOffs.every(
      (s) => s.status === 'PASS' && Boolean(s.signedOffAt) && s.evidenceReviewed
    );

  const recoverySignOffComplete =
    allSpecialistsSignedOff &&
    params.incidentEvidenceComplete &&
    params.remainingNonCriticalFollowUpDocumented;

  if (!recoverySignOffComplete) {
    return {
      macroStage: 'STATE_2_RECOVERY_VERIFICATION',
      lifecycleState: 'RECOVERY_VERIFIED',
      rollbackActionComplete: true,
      recoveryVerified: true,
      recoverySignOffComplete: false,
      incidentResolved: false,
      verificationClassification,
      summaryStatement:
        'RECOVERY VERIFIED: All required verification criteria passed; awaiting formal specialist and Primary Rollback Owner sign-off.',
      sanitizedTimeline,
      blockingReasons: ['Formal recovery sign-off by all required domain owners is pending.'],
    };
  }

  sanitizedTimeline.recoverySignOffCompletedAt =
    params.timeline.recoverySignOffCompletedAt;
  sanitizedTimeline.incidentClosedAt = params.timeline.incidentClosedAt;

  const summaryStatement =
    verificationClassification === 'VERIFIED PASS'
      ? 'RECOVERY SIGN-OFF COMPLETE (VERIFIED PASS): All 16 required verification areas passed and all specialist owners formally signed off.'
      : `RECOVERY SIGN-OFF COMPLETE (WITH APPROVED TEMPORARY EXCEPTION): Recovery verified for all required areas. ${openLowOrMediumExceptions
          .map((e) => `${e.id} (Owner: ${e.primaryOwner}, Deadline: ${e.deadline})`)
          .join('; ')}`;

  return {
    macroStage: 'STATE_3_RECOVERY_SIGN_OFF',
    lifecycleState: sanitizedTimeline.incidentClosedAt
      ? 'NORMAL_OPERATIONS'
      : 'RECOVERY_SIGN_OFF_COMPLETE',
    rollbackActionComplete: true,
    recoveryVerified: true,
    recoverySignOffComplete: true,
    incidentResolved: Boolean(sanitizedTimeline.incidentClosedAt),
    verificationClassification,
    summaryStatement,
    sanitizedTimeline,
    blockingReasons: [],
  };
}

// ============================================================================
// EXPLICIT STATUS TRANSITION ENGINE (SECTIONS 1–22)
// ============================================================================

export type VerificationItemStatus =
  | 'NOT_STARTED'
  | 'IN_PROGRESS'
  | 'PASS'
  | 'FAIL'
  | 'BLOCKED'
  | 'RETEST_REQUIRED'
  | 'EXCEPTION_APPROVED'
  | 'CLOSED';

export const ALLOWED_VERIFICATION_ITEM_STATUSES: ReadonlySet<string> =
  new Set<VerificationItemStatus>([
    'NOT_STARTED',
    'IN_PROGRESS',
    'PASS',
    'FAIL',
    'BLOCKED',
    'RETEST_REQUIRED',
    'EXCEPTION_APPROVED',
    'CLOSED',
  ]);

export type OverallRecoveryStatus =
  | 'RECOVERY_NOT_STARTED'
  | 'RECOVERY_IN_PROGRESS'
  | 'VERIFICATION_IN_PROGRESS'
  | 'VERIFICATION_FAILED'
  | 'VERIFICATION_BLOCKED'
  | 'REMEDIATION_IN_PROGRESS'
  | 'RETEST_IN_PROGRESS'
  | 'RECOVERY_VERIFIED'
  | 'RECOVERY_SIGNED_OFF'
  | 'INCIDENT_CLOSED';

const ALLOWED_ITEM_TRANSITIONS: Readonly<
  Record<VerificationItemStatus, ReadonlySet<VerificationItemStatus>>
> = {
  NOT_STARTED: new Set(['IN_PROGRESS']),
  IN_PROGRESS: new Set(['PASS', 'FAIL', 'BLOCKED']),
  PASS: new Set(['CLOSED']),
  FAIL: new Set(['RETEST_REQUIRED', 'CLOSED']),
  BLOCKED: new Set(['RETEST_REQUIRED', 'EXCEPTION_APPROVED', 'CLOSED']),
  RETEST_REQUIRED: new Set(['IN_PROGRESS']),
  EXCEPTION_APPROVED: new Set(['RETEST_REQUIRED', 'CLOSED']),
  CLOSED: new Set([]), // Reopening creates a new cycle via reopenVerificationItemCycle()
};

const ALLOWED_OVERALL_RECOVERY_TRANSITIONS: Readonly<
  Record<OverallRecoveryStatus, ReadonlySet<OverallRecoveryStatus>>
> = {
  RECOVERY_NOT_STARTED: new Set(['RECOVERY_IN_PROGRESS']),
  RECOVERY_IN_PROGRESS: new Set(['VERIFICATION_IN_PROGRESS']),
  VERIFICATION_IN_PROGRESS: new Set([
    'VERIFICATION_FAILED',
    'VERIFICATION_BLOCKED',
    'RECOVERY_VERIFIED',
  ]),
  VERIFICATION_FAILED: new Set(['REMEDIATION_IN_PROGRESS']),
  VERIFICATION_BLOCKED: new Set(['REMEDIATION_IN_PROGRESS', 'RETEST_IN_PROGRESS']),
  REMEDIATION_IN_PROGRESS: new Set(['RETEST_IN_PROGRESS']),
  RETEST_IN_PROGRESS: new Set(['VERIFICATION_IN_PROGRESS']),
  RECOVERY_VERIFIED: new Set(['RECOVERY_SIGNED_OFF', 'VERIFICATION_FAILED']),
  RECOVERY_SIGNED_OFF: new Set(['INCIDENT_CLOSED', 'VERIFICATION_FAILED']),
  INCIDENT_CLOSED: new Set(['VERIFICATION_IN_PROGRESS']),
};

export interface VerificationStatusAuditEntry {
  verificationId: string;
  cycleNumber: number;
  version: number;
  previousStatus: VerificationItemStatus;
  newStatus: VerificationItemStatus;
  changedBy: string;
  owner: string;
  timestamp: string;
  reason: string;
  evidenceReference: string;
  relatedIncidentOrChangeId: string;
  notes?: string;
}

export interface FailTransitionDetails {
  expected: string;
  actual: string;
  failureEvidence: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  owner: string;
  timestamp: string;
  impact: string;
}

export interface BlockedTransitionDetails {
  blockedReason: string;
  missingDependency: string;
  owner: string;
  risk: BlockedRiskLevel;
  dateTime: string;
  deadline: string;
  nextAction: string;
}

export interface ExceptionApprovedTransitionDetails {
  riskClassification: 'MEDIUM' | 'LOW';
  reason: string;
  containment: string;
  owner: string;
  deadline: string;
  approver: string;
}

export interface PassTransitionDetails {
  verificationExecuted: true;
  correctEnvironmentConfirmed: true;
  allAcceptanceCriteriaSatisfied: true;
  evidenceCaptured: string;
  noUnexplainedCriticalAnomaly: true;
  ownerReviewCompleted: true;
  verifiedAt: string;
  verifiedBy: string;
}

export interface VerificationStatefulItem {
  verificationId: string;
  area: VerificationAreaId;
  critical: boolean;
  assignedOwner: string;
  backupOwner: string;
  remediationOwner?: string;
  exceptionApprover?: string;
  signOffOwner?: string;
  cycleNumber: number;
  version: number;
  currentStatus: VerificationItemStatus;
  finalOutcomeBeforeClose?: 'PASS' | 'EXCEPTION_APPROVED' | 'FAIL_INCIDENT_CLOSED' | 'BLOCKED_INCIDENT_CLOSED';
  failDetails?: FailTransitionDetails;
  blockedDetails?: BlockedTransitionDetails;
  exceptionDetails?: ExceptionApprovedTransitionDetails;
  passDetails?: PassTransitionDetails;
  notes?: string;
  auditTrail: VerificationStatusAuditEntry[];
}

const inFlightItemTransitionLocks = new Set<string>();

/**
 * Validates that a status string is one of the 8 strictly allowed statuses
 * and rejects informal statuses ("Pending", "Looks Good", "N/A", etc.).
 */
export function isValidVerificationItemStatus(
  status: unknown
): status is VerificationItemStatus {
  return (
    typeof status === 'string' && ALLOWED_VERIFICATION_ITEM_STATUSES.has(status)
  );
}

/**
 * Server-authoritative state machine transition for an individual verification item.
 * Enforces Sections 1–14 and 18–22:
 *   - Rejects informal statuses and prohibited direct transitions (e.g. FAIL -> PASS, BLOCKED -> PASS, FAIL -> BLOCKED)
 *   - Enforces optimistic version locking & concurrency serialization
 *   - Enforces owner authority per transition
 *   - Requires structured evidence for PASS, FAIL, BLOCKED, and EXCEPTION_APPROVED
 *   - Appends an immutable audit trail entry without overwriting prior PASS/FAIL/BLOCKED history
 */
export function transitionVerificationItemStatus(params: {
  item: VerificationStatefulItem;
  requestedNewStatus: unknown;
  expectedVersion: number;
  actorName: string;
  timestamp: string;
  reason: string;
  evidenceReference: string;
  relatedIncidentOrChangeId: string;
  notes?: string;
  explicitIncidentClosureApproved?: boolean;
  failDetails?: FailTransitionDetails;
  blockedDetails?: BlockedTransitionDetails;
  exceptionDetails?: ExceptionApprovedTransitionDetails;
  passDetails?: PassTransitionDetails;
}):
  | { ok: true; updatedItem: VerificationStatefulItem }
  | { ok: false; error: string } {
  const { item } = params;

  // 1. Reject informal or unknown statuses
  if (!isValidVerificationItemStatus(params.requestedNewStatus)) {
    return {
      ok: false,
      error: `Invalid status "${String(params.requestedNewStatus)}". Only the 8 formal state machine statuses are permitted.`,
    };
  }
  const targetStatus: VerificationItemStatus = params.requestedNewStatus;

  // 2. Concurrency & optimistic version lock check (Section 19)
  const lockKey = `verify_item:${item.verificationId}`;
  if (inFlightItemTransitionLocks.has(lockKey)) {
    return {
      ok: false,
      error: `Concurrency conflict: Another transition is currently in flight for ${item.verificationId}.`,
    };
  }
  if (params.expectedVersion !== item.version) {
    return {
      ok: false,
      error: `Optimistic lock version mismatch for ${item.verificationId}: expected v${params.expectedVersion}, actual v${item.version}.`,
    };
  }

  inFlightItemTransitionLocks.add(lockKey);
  try {
    // 3. Require non-empty reason, actor, timestamp, and incident/change reference (Section 18)
    if (
      !params.actorName?.trim() ||
      !params.reason?.trim() ||
      !params.timestamp?.trim() ||
      !params.evidenceReference?.trim() ||
      !params.relatedIncidentOrChangeId?.trim()
    ) {
      return {
        ok: false,
        error:
          'Audit Trail Requirement violation: actorName, reason, timestamp, evidenceReference, and relatedIncidentOrChangeId are mandatory.',
      };
    }

    // 4. Validate transition against authoritative state machine (Sections 2, 3, 4)
    const allowedNext = ALLOWED_ITEM_TRANSITIONS[item.currentStatus];
    if (!allowedNext || !allowedNext.has(targetStatus)) {
      return {
        ok: false,
        error: `Prohibited status transition for ${item.area}: ${item.currentStatus} -> ${targetStatus} is not permitted.`,
      };
    }

    // 5. Enforce Owner Authority Rule (Section 13)
    const actor = params.actorName.trim();
    const isAssignedOrBackupOwner =
      actor === item.assignedOwner || actor === item.backupOwner;
    const isRemediationOwner =
      Boolean(item.remediationOwner) && actor === item.remediationOwner;
    const isExceptionApprover =
      Boolean(item.exceptionApprover) && actor === item.exceptionApprover;
    const isSignOffOwner =
      Boolean(item.signOffOwner) && actor === item.signOffOwner;

    if (
      (item.currentStatus === 'NOT_STARTED' && targetStatus === 'IN_PROGRESS') ||
      (item.currentStatus === 'IN_PROGRESS' &&
        (targetStatus === 'PASS' ||
          targetStatus === 'FAIL' ||
          targetStatus === 'BLOCKED')) ||
      (item.currentStatus === 'BLOCKED' && targetStatus === 'RETEST_REQUIRED') ||
      (item.currentStatus === 'RETEST_REQUIRED' && targetStatus === 'IN_PROGRESS')
    ) {
      if (!isAssignedOrBackupOwner) {
        return {
          ok: false,
          error: `Owner Authority violation: Only assigned owner (${item.assignedOwner}) or backup (${item.backupOwner}) may transition ${item.currentStatus} -> ${targetStatus}.`,
        };
      }
    } else if (
      item.currentStatus === 'FAIL' &&
      targetStatus === 'RETEST_REQUIRED'
    ) {
      if (!isAssignedOrBackupOwner && !isRemediationOwner) {
        return {
          ok: false,
          error: `Owner Authority violation: Only remediation owner or verification owner may transition FAIL -> RETEST_REQUIRED.`,
        };
      }
    } else if (
      item.currentStatus === 'BLOCKED' &&
      targetStatus === 'EXCEPTION_APPROVED'
    ) {
      if (!isExceptionApprover) {
        return {
          ok: false,
          error: `Owner Authority violation: Only an authorized exception approver may transition BLOCKED -> EXCEPTION_APPROVED.`,
        };
      }
    } else if (targetStatus === 'CLOSED') {
      if (
        !isAssignedOrBackupOwner &&
        !isSignOffOwner &&
        !isExceptionApprover
      ) {
        return {
          ok: false,
          error: `Owner Authority violation: Unauthorized actor (${actor}) cannot close verification item.`,
        };
      }
    }

    // 6. Enforce Transition-Specific Criteria (Sections 5, 6, 7, 9, 11)
    let nextFinalOutcome = item.finalOutcomeBeforeClose;

    if (targetStatus === 'FAIL') {
      const fd = params.failDetails;
      if (
        !fd ||
        !fd.expected?.trim() ||
        !fd.actual?.trim() ||
        !fd.failureEvidence?.trim() ||
        !fd.environment ||
        !fd.owner?.trim() ||
        !fd.timestamp?.trim() ||
        !fd.impact?.trim()
      ) {
        return {
          ok: false,
          error:
            'FAIL Transition Rule violation: expected, actual, failureEvidence, environment, owner, timestamp, and impact are required.',
        };
      }
    }

    if (targetStatus === 'BLOCKED') {
      const bd = params.blockedDetails;
      if (
        !bd ||
        !bd.blockedReason?.trim() ||
        !bd.missingDependency?.trim() ||
        !bd.owner?.trim() ||
        !bd.risk ||
        !bd.dateTime?.trim() ||
        !validateAbsoluteDeadlineFormat(bd.deadline) ||
        !bd.nextAction?.trim()
      ) {
        return {
          ok: false,
          error:
            'BLOCKED Transition Rule violation: blockedReason, missingDependency, owner, risk, dateTime, valid absolute deadline (YYYY-MM-DD HH:MM TIMEZONE), and nextAction are required.',
        };
      }
    }

    if (targetStatus === 'EXCEPTION_APPROVED') {
      if (item.critical || item.blockedDetails?.risk === 'CRITICAL') {
        return {
          ok: false,
          error: `Exception Transition Rule violation: Critical area (${item.area}) cannot transition BLOCKED -> EXCEPTION_APPROVED.`,
        };
      }
      const ed = params.exceptionDetails;
      if (
        !ed ||
        (ed.riskClassification !== 'LOW' &&
          ed.riskClassification !== 'MEDIUM') ||
        !ed.reason?.trim() ||
        !ed.containment?.trim() ||
        !ed.owner?.trim() ||
        !validateAbsoluteDeadlineFormat(ed.deadline) ||
        !ed.approver?.trim()
      ) {
        return {
          ok: false,
          error:
            'Exception Transition Rule violation: riskClassification (LOW/MEDIUM), reason, containment, owner, valid absolute deadline, and approver are required.',
        };
      }
    }

    if (targetStatus === 'PASS') {
      const pd = params.passDetails;
      if (
        !pd ||
        pd.verificationExecuted !== true ||
        pd.correctEnvironmentConfirmed !== true ||
        pd.allAcceptanceCriteriaSatisfied !== true ||
        !pd.evidenceCaptured?.trim() ||
        pd.noUnexplainedCriticalAnomaly !== true ||
        pd.ownerReviewCompleted !== true ||
        !pd.verifiedAt?.trim() ||
        !pd.verifiedBy?.trim()
      ) {
        return {
          ok: false,
          error:
            'PASS Transition Rule violation: All 6 PASS conditions, verifiedAt, verifiedBy, and non-empty evidenceCaptured are required.',
        };
      }
    }

    if (targetStatus === 'CLOSED') {
      if (item.currentStatus === 'PASS') {
        nextFinalOutcome = 'PASS';
      } else if (item.currentStatus === 'EXCEPTION_APPROVED') {
        nextFinalOutcome = 'EXCEPTION_APPROVED';
      } else if (
        item.currentStatus === 'FAIL' ||
        item.currentStatus === 'BLOCKED'
      ) {
        if (!params.explicitIncidentClosureApproved) {
          return {
            ok: false,
            error: `Cannot transition ${item.currentStatus} -> CLOSED without explicitIncidentClosureApproved = true.`,
          };
        }
        nextFinalOutcome =
          item.currentStatus === 'FAIL'
            ? 'FAIL_INCIDENT_CLOSED'
            : 'BLOCKED_INCIDENT_CLOSED';
      }
    }

    const nextVersion = item.version + 1;
    const auditEntry: VerificationStatusAuditEntry = {
      verificationId: item.verificationId,
      cycleNumber: item.cycleNumber,
      version: nextVersion,
      previousStatus: item.currentStatus,
      newStatus: targetStatus,
      changedBy: actor,
      owner: item.assignedOwner,
      timestamp: params.timestamp,
      reason: params.reason,
      evidenceReference: params.evidenceReference,
      relatedIncidentOrChangeId: params.relatedIncidentOrChangeId,
      notes: params.notes,
    };

    const updatedItem: VerificationStatefulItem = {
      ...item,
      version: nextVersion,
      currentStatus: targetStatus,
      finalOutcomeBeforeClose: nextFinalOutcome,
      failDetails: params.failDetails ?? item.failDetails,
      blockedDetails: params.blockedDetails ?? item.blockedDetails,
      exceptionDetails: params.exceptionDetails ?? item.exceptionDetails,
      passDetails: params.passDetails ?? item.passDetails,
      notes: params.notes ?? item.notes,
      auditTrail: [...item.auditTrail, auditEntry],
    };

    return { ok: true, updatedItem };
  } finally {
    inFlightItemTransitionLocks.delete(lockKey);
  }
}

/**
 * Sections 10, 12, 14: Reopens a PASS or CLOSED item into a new verification cycle (IN_PROGRESS)
 * when new regression or security evidence invalidates a previous conclusion,
 * preserving 100% of the historical PASS / CLOSED audit trail.
 */
export function reopenVerificationItemCycle(params: {
  item: VerificationStatefulItem;
  expectedVersion: number;
  actorName: string;
  timestamp: string;
  reopenReason: string;
  evidenceReference: string;
  relatedIncidentOrChangeId: string;
}):
  | { ok: true; reopenedItem: VerificationStatefulItem }
  | { ok: false; error: string } {
  const { item } = params;
  if (item.currentStatus !== 'CLOSED' && item.currentStatus !== 'PASS') {
    return {
      ok: false,
      error: `Only a PASS or CLOSED item can be reopened into a new verification cycle (current: ${item.currentStatus}).`,
    };
  }
  if (params.expectedVersion !== item.version) {
    return {
      ok: false,
      error: `Optimistic lock version mismatch on reopen: expected v${params.expectedVersion}, actual v${item.version}.`,
    };
  }
  if (!params.reopenReason?.trim() || !params.evidenceReference?.trim()) {
    return {
      ok: false,
      error: 'Reopening requires a documented reopenReason and evidenceReference.',
    };
  }

  const nextCycle = item.cycleNumber + 1;
  const nextVersion = item.version + 1;
  const auditEntry: VerificationStatusAuditEntry = {
    verificationId: item.verificationId,
    cycleNumber: nextCycle,
    version: nextVersion,
    previousStatus: item.currentStatus,
    newStatus: 'IN_PROGRESS',
    changedBy: params.actorName.trim(),
    owner: item.assignedOwner,
    timestamp: params.timestamp,
    reason: `[REOPENED CYCLE #${nextCycle}] ${params.reopenReason}`,
    evidenceReference: params.evidenceReference,
    relatedIncidentOrChangeId: params.relatedIncidentOrChangeId,
  };

  return {
    ok: true,
    reopenedItem: {
      ...item,
      cycleNumber: nextCycle,
      version: nextVersion,
      currentStatus: 'IN_PROGRESS',
      auditTrail: [...item.auditTrail, auditEntry],
    },
  };
}

/**
 * Sections 15, 16, 17, 21: Enforces the Overall Recovery Status state machine
 * and prevents skipping required states (e.g., RECOVERY_IN_PROGRESS -> INCIDENT_CLOSED
 * or VERIFICATION_BLOCKED -> RECOVERY_SIGNED_OFF).
 */
export function transitionOverallRecoveryStatus(params: {
  currentStatus: OverallRecoveryStatus;
  requestedNewStatus: OverallRecoveryStatus;
  items: readonly VerificationStatefulItem[];
  unresolvedCriticalSecurityExposure: boolean;
  databaseIntegrityConfirmed: boolean;
  monitoringAndEvidenceAvailable: boolean;
  requiredOwnerSignOffsComplete: boolean;
  formalRecoverySignOffAuthorityApproved: boolean;
  incidentClosureChecklistComplete: boolean;
}):
  | { ok: true; newStatus: OverallRecoveryStatus }
  | { ok: false; error: string } {
  const allowedNext = ALLOWED_OVERALL_RECOVERY_TRANSITIONS[params.currentStatus];
  if (!allowedNext || !allowedNext.has(params.requestedNewStatus)) {
    return {
      ok: false,
      error: `Prohibited overall recovery transition: ${params.currentStatus} -> ${params.requestedNewStatus} is not allowed (no skipping required states).`,
    };
  }

  if (params.requestedNewStatus === 'RECOVERY_VERIFIED') {
    const hasCriticalNotPass = params.items.some(
      (i) =>
        i.critical &&
        i.currentStatus !== 'PASS' &&
        !(i.currentStatus === 'CLOSED' && i.finalOutcomeBeforeClose === 'PASS')
    );
    const hasUnresolvedFailOrBlocked = params.items.some(
      (i) =>
        i.currentStatus === 'FAIL' ||
        i.currentStatus === 'BLOCKED' ||
        i.currentStatus === 'NOT_STARTED' ||
        i.currentStatus === 'IN_PROGRESS' ||
        i.currentStatus === 'RETEST_REQUIRED'
    );

    if (
      hasCriticalNotPass ||
      hasUnresolvedFailOrBlocked ||
      params.unresolvedCriticalSecurityExposure ||
      !params.databaseIntegrityConfirmed ||
      !params.monitoringAndEvidenceAvailable ||
      !params.requiredOwnerSignOffsComplete
    ) {
      return {
        ok: false,
        error:
          'Final Recovery Gate not satisfied: Cannot transition to RECOVERY_VERIFIED while any critical/required area is not PASS or while security/database/monitoring gates are incomplete.',
      };
    }
  }

  if (params.requestedNewStatus === 'RECOVERY_SIGNED_OFF') {
    if (!params.formalRecoverySignOffAuthorityApproved) {
      return {
        ok: false,
        error:
          'Cannot transition RECOVERY_VERIFIED -> RECOVERY_SIGNED_OFF without formal recovery sign-off authority approval.',
      };
    }
  }

  if (params.requestedNewStatus === 'INCIDENT_CLOSED') {
    if (!params.incidentClosureChecklistComplete) {
      return {
        ok: false,
        error:
          'Cannot transition RECOVERY_SIGNED_OFF -> INCIDENT_CLOSED without completing the incident closure checklist.',
      };
    }
  }

  return { ok: true, newStatus: params.requestedNewStatus };
}

// ============================================================================
// POST-RECOVERY MONITORING AND STABILITY WINDOW ENGINE (SECTIONS 1–22)
// ============================================================================

export const STABILITY_WINDOW_CONFIG = {
  POST_RECOVERY_STABILITY_WINDOW_MINUTES: 60,
  POST_RECOVERY_HIGH_RISK_WINDOW_MINUTES: 120,
} as const;

export type HighRiskIncidentDomain =
  | 'Authentication'
  | 'Authorization'
  | 'Session security'
  | 'Credential/token exposure'
  | 'Database integrity'
  | 'Payment integrity'
  | 'Privilege escalation'
  | 'Cross-user access'
  | 'Critical API authorization';

export type RequiredMonitoringArea =
  | 'Application availability'
  | 'Authentication success/failure rate'
  | 'Session creation/refresh/logout behavior'
  | 'Authorization failures'
  | 'Protected API error rate'
  | 'HTTP 4xx/5xx errors'
  | 'Database errors'
  | 'Database connection health'
  | 'Payment/API failures where applicable'
  | 'Security alerts'
  | 'Credential/session exposure alerts'
  | 'Rate-limit/abuse anomalies'
  | 'Server exceptions'
  | 'Client/runtime errors'
  | 'Critical user-flow failures';

export const REQUIRED_MONITORING_AREAS: readonly RequiredMonitoringArea[] = [
  'Application availability',
  'Authentication success/failure rate',
  'Session creation/refresh/logout behavior',
  'Authorization failures',
  'Protected API error rate',
  'HTTP 4xx/5xx errors',
  'Database errors',
  'Database connection health',
  'Payment/API failures where applicable',
  'Security alerts',
  'Credential/session exposure alerts',
  'Rate-limit/abuse anomalies',
  'Server exceptions',
  'Client/runtime errors',
  'Critical user-flow failures',
] as const;

export type PostRecoveryStabilityState =
  | 'MONITORING_NOT_STARTED'
  | 'POST_RECOVERY_MONITORING'
  | 'STABILITY_FAILURE'
  | 'MONITORING_BLOCKED'
  | 'STABILITY_CONFIRMED';

export interface MonitoringWindowExtensionRecord {
  originalEndTimeMs: number;
  originalEndTimeFormatted: string;
  extendedEndTimeMs: number;
  extendedEndTimeFormatted: string;
  reason: string;
  owner: string;
  approver: string;
  recordedAt: string;
}

export interface PostRecoveryMonitoringSession {
  incidentId: string;
  recoveryId: string;
  isHighRisk: boolean;
  highRiskDomainsInvolved: HighRiskIncidentDomain[];
  requiredWindowMinutes: 60 | 120;
  monitoringOwner: string;
  backupMonitoringOwner: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  monitoringSources: string[];
  monitoringStartedAtMs: number;
  monitoringStartedFormatted: string;
  requiredEndTimeMs: number;
  requiredEndTimeFormatted: string;
  monitoringCompletedAtMs: number | null;
  monitoringCompletedFormatted: string | null;
  stabilityConfirmedAtMs: number | null;
  stabilityConfirmedFormatted: string | null;
  state: PostRecoveryStabilityState;
  extensions: MonitoringWindowExtensionRecord[];
}

export interface StabilityTelemetryChecks {
  // Section 5: 15 Required Monitoring Areas
  reviewedAreas: ReadonlySet<RequiredMonitoringArea>;
  // Section 6: Authentication Monitoring
  authenticationChecks: {
    legitimateUsersCanLogIn: boolean;
    invalidCredentialsRejected: boolean;
    sessionsValidWithinPolicy: boolean;
    expiredSessionsRejected: boolean;
    logoutInvalidatesCorrectly: boolean;
    refreshBehaviorStable: boolean;
    noUnexpectedAuthLoops: boolean;
    noAbnormalAuthFailureSpike: boolean;
  };
  // Section 7: Authorization Monitoring
  authorizationChecks: {
    studentsRestrictedToStudentPermissions: boolean;
    teachersRestrictedToTeacherPermissions: boolean;
    adminFunctionsProtected: boolean;
    noCrossUserAccessOccurred: boolean;
    protectedApisRejectUnauthorized: boolean;
    clientRoleManipulationBlocked: boolean;
  };
  // Section 8: Database Monitoring
  databaseChecks: {
    noUnexpectedDatabaseErrors: boolean;
    noIntegrityConstraintFailures: boolean;
    noUnexpectedDataLoss: boolean;
    noAbnormalWriteFailures: boolean;
    noUnexpectedMigrationErrors: boolean;
    noAbnormalConnectionFailures: boolean;
  };
  // Section 9: Error-Rate Monitoring vs Baseline
  errorRateChecks: {
    http5xxWithinThreshold: boolean;
    apiFailureRateWithinThreshold: boolean;
    authFailuresWithinThreshold: boolean;
    dbErrorsWithinThreshold: boolean;
    serverExceptionsWithinThreshold: boolean;
    clientRuntimeErrorsWithinThreshold: boolean;
  };
  // Section 10: Security Monitoring
  securityChecks: {
    noCredentialExposure: boolean;
    noSessionTokenLeakage: boolean;
    noSuspiciousAuthzFailures: boolean;
    noPrivilegeEscalation: boolean;
    noUnexpectedAdminAccess: boolean;
    noAbnormalApiAbuse: boolean;
    noNewCriticalSecurityAlerts: boolean;
  };
  // Section 12 & 14 & 17: Evidence, Monitoring Availability & Sign-Off
  monitoringSystemAvailable: boolean;
  requiredLogsAndSecurityTelemetryAvailable: boolean;
  databaseMonitoringAvailable: boolean;
  evidenceReferences: string[];
  monitoringOwnerActivelyReviewed: boolean;
  monitoringOwnerSignedOff: boolean;
}

export interface FullIncidentTimeline11Stage {
  incidentDetected: string;
  rollbackStarted: string;
  rollbackActionCompleted: string;
  recoveryVerificationStarted: string;
  recoveryVerificationCompleted: string;
  recoveryVerified: string;
  recoverySignOffCompleted: string;
  monitoringStarted: string;
  monitoringCompleted: string | null;
  stabilityConfirmed: string | null;
  incidentClosed: string | null;
}

export interface FinalIncidentFiveDimensionStatus {
  rollback: 'COMPLETE' | 'FAILED';
  recoveryVerification: 'VERIFIED' | 'FAILED' | 'BLOCKED';
  recoverySignOff: 'COMPLETE' | 'NOT COMPLETE';
  postRecoveryStability: 'CONFIRMED' | 'FAILED' | 'BLOCKED';
  incident: 'CLOSED' | 'OPEN';
}

export interface ClosedIncidentImmutableRecord {
  incidentId: string;
  recoveryId: string;
  restoredCommitSha: string;
  statuses: FinalIncidentFiveDimensionStatus;
  timeline: FullIncidentTimeline11Stage;
  closedByOwner: string;
}

export interface LinkedFollowUpIncidentRecord {
  newIncidentId: string;
  originalIncidentId: string;
  originalRecoveryId: string;
  relatedVerificationId: string;
  regressionSummary: string;
  detectedAt: string;
  assignedOwner: string;
}

/**
 * Sections 2, 3, 4, 11: Starts the Post-Recovery Monitoring / Stability Window.
 * Enforces that the stability window clock begins ONLY after Recovery Verification = PASS
 * and Recovery Sign-off = COMPLETE, and selects 120 minutes for high-risk incidents
 * (or 60 minutes default).
 */
export function startPostRecoveryMonitoringWindow(params: {
  incidentId: string;
  recoveryId: string;
  recoveryVerificationPassed: boolean;
  recoverySignOffCompleted: boolean;
  highRiskDomainsInvolved: HighRiskIncidentDomain[];
  monitoringOwner: string;
  backupMonitoringOwner: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  monitoringSources: string[];
  startTimeMs: number;
  startTimeFormatted: string;
  endTimeFormatted: string;
}):
  | { ok: true; session: PostRecoveryMonitoringSession }
  | { ok: false; error: string } {
  if (!params.recoveryVerificationPassed || !params.recoverySignOffCompleted) {
    return {
      ok: false,
      error:
        'Stability Window Start Rule violation: Post-recovery monitoring clock can begin only after Recovery Verification = PASS and Recovery Sign-off = COMPLETE.',
    };
  }

  if (
    !params.monitoringOwner?.trim() ||
    !params.backupMonitoringOwner?.trim() ||
    params.monitoringOwner.trim().toLowerCase() ===
      params.backupMonitoringOwner.trim().toLowerCase()
  ) {
    return {
      ok: false,
      error:
        'No Silent Monitoring Rule violation: Distinct accountable Monitoring Owner and Backup Monitoring Owner are required.',
    };
  }

  if (!params.monitoringSources || params.monitoringSources.length === 0) {
    return {
      ok: false,
      error: 'At least one active monitoring telemetry source is required.',
    };
  }

  if (!validateAbsoluteDeadlineFormat(params.startTimeFormatted)) {
    return {
      ok: false,
      error:
        'Monitoring Started timestamp must use exact YYYY-MM-DD HH:MM TIMEZONE format.',
    };
  }

  const isHighRisk = params.highRiskDomainsInvolved.length > 0;
  const requiredWindowMinutes: 60 | 120 = isHighRisk
    ? STABILITY_WINDOW_CONFIG.POST_RECOVERY_HIGH_RISK_WINDOW_MINUTES
    : STABILITY_WINDOW_CONFIG.POST_RECOVERY_STABILITY_WINDOW_MINUTES;

  const requiredEndTimeMs =
    params.startTimeMs + requiredWindowMinutes * 60 * 1000;

  return {
    ok: true,
    session: {
      incidentId: params.incidentId,
      recoveryId: params.recoveryId,
      isHighRisk,
      highRiskDomainsInvolved: [...params.highRiskDomainsInvolved],
      requiredWindowMinutes,
      monitoringOwner: params.monitoringOwner.trim(),
      backupMonitoringOwner: params.backupMonitoringOwner.trim(),
      environment: params.environment,
      monitoringSources: [...params.monitoringSources],
      monitoringStartedAtMs: params.startTimeMs,
      monitoringStartedFormatted: params.startTimeFormatted,
      requiredEndTimeMs,
      requiredEndTimeFormatted: params.endTimeFormatted,
      monitoringCompletedAtMs: null,
      monitoringCompletedFormatted: null,
      stabilityConfirmedAtMs: null,
      stabilityConfirmedFormatted: null,
      state: 'POST_RECOVERY_MONITORING',
      extensions: [],
    },
  };
}

/**
 * Section 15: Extends the Post-Recovery Monitoring Window with full auditability.
 * Prohibits silently shortening or extending the stability window.
 */
export function extendPostRecoveryMonitoringWindow(params: {
  session: PostRecoveryMonitoringSession;
  extendedEndTimeMs: number;
  extendedEndTimeFormatted: string;
  reason: string;
  owner: string;
  approver: string;
  recordedAt: string;
}):
  | { ok: true; updatedSession: PostRecoveryMonitoringSession }
  | { ok: false; error: string } {
  if (params.extendedEndTimeMs <= params.session.requiredEndTimeMs) {
    return {
      ok: false,
      error:
        'Stability window extension must extend beyond the current required end time (never shorten the window).',
    };
  }
  if (
    !validateAbsoluteDeadlineFormat(params.extendedEndTimeFormatted) ||
    !params.reason?.trim() ||
    !params.owner?.trim() ||
    !params.approver?.trim()
  ) {
    return {
      ok: false,
      error:
        'Extending the stability window requires valid extendedEndTimeFormatted (YYYY-MM-DD HH:MM TIMEZONE), reason, owner, and approver.',
    };
  }

  const extRecord: MonitoringWindowExtensionRecord = {
    originalEndTimeMs: params.session.requiredEndTimeMs,
    originalEndTimeFormatted: params.session.requiredEndTimeFormatted,
    extendedEndTimeMs: params.extendedEndTimeMs,
    extendedEndTimeFormatted: params.extendedEndTimeFormatted,
    reason: params.reason.trim(),
    owner: params.owner.trim(),
    approver: params.approver.trim(),
    recordedAt: params.recordedAt,
  };

  return {
    ok: true,
    updatedSession: {
      ...params.session,
      requiredEndTimeMs: params.extendedEndTimeMs,
      requiredEndTimeFormatted: params.extendedEndTimeFormatted,
      extensions: [...params.session.extensions, extRecord],
    },
  };
}

/**
 * Sections 5–14, 16, 17: Evaluates the Post-Recovery Monitoring Window.
 *   - Prohibits early closure before the required 60m or 120m window completes (Section 16)
 *   - Returns MONITORING_BLOCKED if required monitoring/telemetry is unavailable (Section 14)
 *   - Returns STABILITY_FAILURE and flags CRITICAL_SECURITY_EVENT if any authz/credential/session
 *     or material regression occurs (Sections 6–10, 13)
 *   - Transitions to STABILITY_CONFIRMED only when all 10 criteria in Section 17 pass
 */
export function evaluatePostRecoveryStabilityWindow(params: {
  session: PostRecoveryMonitoringSession;
  currentTimeMs: number;
  currentTimeFormatted: string;
  telemetry: StabilityTelemetryChecks;
}): {
  state: PostRecoveryStabilityState;
  criticalSecurityEventDetected: boolean;
  requiredAction:
    | 'CONTINUE_MONITORING'
    | 'STOP_CLOSURE_AND_REASSESS_SECURITY'
    | 'RETURN_TO_CONTROLLED_INVESTIGATION'
    | 'RESTORE_MONITORING_TELEMETRY'
    | 'PROCEED_TO_INCIDENT_CLOSURE';
  reasons: string[];
  updatedSession: PostRecoveryMonitoringSession;
} {
  const { session, telemetry } = params;
  const reasons: string[] = [];

  // 1. Check for Critical Security Events first (Sections 7 & 10)
  const criticalSecurityEventDetected =
    !telemetry.securityChecks.noCredentialExposure ||
    !telemetry.securityChecks.noSessionTokenLeakage ||
    !telemetry.securityChecks.noPrivilegeEscalation ||
    !telemetry.securityChecks.noUnexpectedAdminAccess ||
    !telemetry.authorizationChecks.noCrossUserAccessOccurred ||
    !telemetry.authorizationChecks.clientRoleManipulationBlocked;

  if (criticalSecurityEventDetected) {
    reasons.push(
      'CRITICAL SECURITY EVENT: Credential/session exposure, privilege escalation, or cross-user access detected during stability window.'
    );
    return {
      state: 'STABILITY_FAILURE',
      criticalSecurityEventDetected: true,
      requiredAction: 'STOP_CLOSURE_AND_REASSESS_SECURITY',
      reasons,
      updatedSession: {
        ...session,
        state: 'STABILITY_FAILURE',
      },
    };
  }

  // 2. Check for Monitoring Blocked (Section 14)
  if (
    !telemetry.monitoringSystemAvailable ||
    !telemetry.requiredLogsAndSecurityTelemetryAvailable ||
    !telemetry.databaseMonitoringAvailable
  ) {
    reasons.push(
      'MONITORING BLOCKED: Required production monitoring, logs, security telemetry, or database monitoring is unavailable.'
    );
    return {
      state: 'MONITORING_BLOCKED',
      criticalSecurityEventDetected: false,
      requiredAction: 'RESTORE_MONITORING_TELEMETRY',
      reasons,
      updatedSession: {
        ...session,
        state: 'MONITORING_BLOCKED',
      },
    };
  }

  // 3. Check for Authentication, Authorization, Database, or Error-Rate Failure (Sections 6, 7, 8, 9, 13)
  const authHealthy = Object.values(telemetry.authenticationChecks).every(Boolean);
  const authzHealthy = Object.values(telemetry.authorizationChecks).every(Boolean);
  const dbHealthy = Object.values(telemetry.databaseChecks).every(Boolean);
  const errorRatesHealthy = Object.values(telemetry.errorRateChecks).every(Boolean);
  const securityHealthy = Object.values(telemetry.securityChecks).every(Boolean);

  if (!authHealthy) {
    reasons.push('Authentication regression detected during stability window.');
  }
  if (!authzHealthy) {
    reasons.push('Authorization regression detected during stability window.');
  }
  if (!dbHealthy) {
    reasons.push('Database health/integrity regression detected during stability window.');
  }
  if (!errorRatesHealthy) {
    reasons.push('Error rates exceeded baseline threshold during stability window.');
  }
  if (!securityHealthy) {
    reasons.push('Security alert or API abuse anomaly detected during stability window.');
  }

  if (reasons.length > 0) {
    return {
      state: 'STABILITY_FAILURE',
      criticalSecurityEventDetected: false,
      requiredAction: 'RETURN_TO_CONTROLLED_INVESTIGATION',
      reasons,
      updatedSession: {
        ...session,
        state: 'STABILITY_FAILURE',
      },
    };
  }

  // 4. Section 16: Early Closure Prohibition — full window duration (60m or 120m) must complete
  if (params.currentTimeMs < session.requiredEndTimeMs) {
    const remainingMin = Math.ceil(
      (session.requiredEndTimeMs - params.currentTimeMs) / 60000
    );
    reasons.push(
      `Early Closure Prohibition: Required ${session.requiredWindowMinutes}-minute stability window has not yet elapsed (${remainingMin}m remaining).`
    );
    return {
      state: 'POST_RECOVERY_MONITORING',
      criticalSecurityEventDetected: false,
      requiredAction: 'CONTINUE_MONITORING',
      reasons,
      updatedSession: session,
    };
  }

  // 5. Section 5, 11, 12, 17: Verify all 15 monitoring areas reviewed, evidence captured, and owner signed off
  const missingAreas = REQUIRED_MONITORING_AREAS.filter(
    (area) => !telemetry.reviewedAreas.has(area)
  );
  if (missingAreas.length > 0) {
    reasons.push(
      `Incomplete monitoring review: Missing ${missingAreas.length} required area(s): ${missingAreas.join(', ')}`
    );
  }
  if (!telemetry.monitoringOwnerActivelyReviewed) {
    reasons.push(
      'No Silent Monitoring Rule: Monitoring Owner has not actively reviewed the monitoring evidence.'
    );
  }
  if (!telemetry.evidenceReferences || telemetry.evidenceReferences.length === 0) {
    reasons.push('Required monitoring evidence references were not captured.');
  }
  if (!telemetry.monitoringOwnerSignedOff) {
    reasons.push('Monitoring Owner has not signed off on stability confirmation.');
  }

  if (reasons.length > 0) {
    return {
      state: 'POST_RECOVERY_MONITORING',
      criticalSecurityEventDetected: false,
      requiredAction: 'CONTINUE_MONITORING',
      reasons,
      updatedSession: session,
    };
  }

  const confirmedSession: PostRecoveryMonitoringSession = {
    ...session,
    monitoringCompletedAtMs: params.currentTimeMs,
    monitoringCompletedFormatted: params.currentTimeFormatted,
    stabilityConfirmedAtMs: params.currentTimeMs,
    stabilityConfirmedFormatted: params.currentTimeFormatted,
    state: 'STABILITY_CONFIRMED',
  };

  return {
    state: 'STABILITY_CONFIRMED',
    criticalSecurityEventDetected: false,
    requiredAction: 'PROCEED_TO_INCIDENT_CLOSURE',
    reasons: [],
    updatedSession: confirmedSession,
  };
}

/**
 * Sections 18, 19, 20, 22: Enforces the Incident Closure Gate only after:
 *   Rollback Complete -> Recovery Verified -> Recovery Sign-off -> Monitoring Complete -> Stability Confirmed -> Incident Closure Review
 */
export function finalizeIncidentClosureAfterStability(params: {
  incidentId: string;
  recoveryId: string;
  restoredCommitSha: string;
  rollbackComplete: boolean;
  recoveryVerified: boolean;
  recoverySignOffComplete: boolean;
  monitoringSession: PostRecoveryMonitoringSession;
  incidentClosureReviewCompleted: boolean;
  closedByOwner: string;
  incidentClosedFormatted: string;
  priorTimeline: {
    incidentDetected: string;
    rollbackStarted: string;
    rollbackActionCompleted: string;
    recoveryVerificationStarted: string;
    recoveryVerificationCompleted: string;
    recoveryVerified: string;
    recoverySignOffCompleted: string;
  };
}):
  | {
      ok: true;
      closedRecord: ClosedIncidentImmutableRecord;
    }
  | {
      ok: false;
      error: string;
      statuses: FinalIncidentFiveDimensionStatus;
    } {
  const stabilityStatus: 'CONFIRMED' | 'FAILED' | 'BLOCKED' =
    params.monitoringSession.state === 'STABILITY_CONFIRMED'
      ? 'CONFIRMED'
      : params.monitoringSession.state === 'STABILITY_FAILURE'
        ? 'FAILED'
        : 'BLOCKED';

  const currentStatuses: FinalIncidentFiveDimensionStatus = {
    rollback: params.rollbackComplete ? 'COMPLETE' : 'FAILED',
    recoveryVerification: params.recoveryVerified ? 'VERIFIED' : 'FAILED',
    recoverySignOff: params.recoverySignOffComplete
      ? 'COMPLETE'
      : 'NOT COMPLETE',
    postRecoveryStability: stabilityStatus,
    incident: 'OPEN',
  };

  if (
    !params.rollbackComplete ||
    !params.recoveryVerified ||
    !params.recoverySignOffComplete ||
    params.monitoringSession.state !== 'STABILITY_CONFIRMED' ||
    !params.incidentClosureReviewCompleted ||
    !params.monitoringSession.monitoringCompletedFormatted ||
    !params.monitoringSession.stabilityConfirmedFormatted
  ) {
    return {
      ok: false,
      error:
        'Incident Closure Gate violation: Cannot close incident until Rollback = COMPLETE, Recovery Verification = VERIFIED, Recovery Sign-off = COMPLETE, Post-Recovery Stability = CONFIRMED, and Incident Closure Review = completed.',
      statuses: currentStatuses,
    };
  }

  const closedStatuses: FinalIncidentFiveDimensionStatus = {
    ...currentStatuses,
    incident: 'CLOSED',
  };

  const fullTimeline: FullIncidentTimeline11Stage = {
    ...params.priorTimeline,
    monitoringStarted: params.monitoringSession.monitoringStartedFormatted,
    monitoringCompleted: params.monitoringSession.monitoringCompletedFormatted,
    stabilityConfirmed: params.monitoringSession.stabilityConfirmedFormatted,
    incidentClosed: params.incidentClosedFormatted,
  };

  return {
    ok: true,
    closedRecord: Object.freeze({
      incidentId: params.incidentId,
      recoveryId: params.recoveryId,
      restoredCommitSha: params.restoredCommitSha,
      statuses: Object.freeze(closedStatuses),
      timeline: Object.freeze(fullTimeline),
      closedByOwner: params.closedByOwner,
    }),
  };
}

/**
 * Section 21: Regression After Closure Rule.
 * Preserves the original closed incident record without modification and creates
 * a linked follow-up incident referencing the original Incident ID, Recovery ID,
 * and Verification ID.
 */
export function createLinkedPostClosureRegressionIncident(params: {
  closedIncident: ClosedIncidentImmutableRecord;
  newIncidentId: string;
  relatedVerificationId: string;
  regressionSummary: string;
  detectedAt: string;
  assignedOwner: string;
}): {
  preservedClosedIncident: ClosedIncidentImmutableRecord;
  followUpIncident: LinkedFollowUpIncidentRecord;
} {
  return {
    preservedClosedIncident: params.closedIncident,
    followUpIncident: {
      newIncidentId: params.newIncidentId,
      originalIncidentId: params.closedIncident.incidentId,
      originalRecoveryId: params.closedIncident.recoveryId,
      relatedVerificationId: params.relatedVerificationId,
      regressionSummary: params.regressionSummary,
      detectedAt: params.detectedAt,
      assignedOwner: params.assignedOwner,
    },
  };
}



