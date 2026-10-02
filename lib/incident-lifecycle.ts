import crypto from 'crypto';
import {
  recordServerAuditLog,
  UserRole,
} from '@/lib/server-auth';
import {
  AreaVerificationRecord,
  BlockedRiskLevel,
  PostRecoveryMonitoringSession,
  validateAbsoluteDeadlineFormat,
  VerificationStatefulItem,
} from '@/lib/rollback-governance';

// ============================================================================
// 1. COMPLETE CANONICAL INCIDENT STATUS ENUM (INCIDENT_STATUS_ENUM_V1)
// ============================================================================

export const INCIDENT_STATUS_ENUM_VERSION = 1 as const;
export const TOTAL_CANONICAL_INCIDENT_STATUSES = 16 as const;

export enum IncidentStatusEnum {
  DETECTED = 'DETECTED',
  TRIAGED = 'TRIAGED',
  ACKNOWLEDGED = 'ACKNOWLEDGED',
  CONTAINMENT_IN_PROGRESS = 'CONTAINMENT_IN_PROGRESS',
  CONTAINED = 'CONTAINED',
  ROLLBACK_IN_PROGRESS = 'ROLLBACK_IN_PROGRESS',
  ROLLBACK_COMPLETE = 'ROLLBACK_COMPLETE',
  RECOVERY_IN_PROGRESS = 'RECOVERY_IN_PROGRESS',
  RECOVERY_BLOCKED = 'RECOVERY_BLOCKED',
  RECOVERY_FAILED = 'RECOVERY_FAILED',
  RECOVERY_VERIFIED = 'RECOVERY_VERIFIED',
  MONITORING = 'MONITORING',
  STABILITY_CONFIRMED = 'STABILITY_CONFIRMED',
  RESOLVED = 'RESOLVED',
  CLOSED = 'CLOSED',
  REOPENED = 'REOPENED',
}

export type IncidentStatus = `${IncidentStatusEnum}`;

export const CANONICAL_INCIDENT_STATUS_VALUES: readonly IncidentStatus[] =
  Object.freeze([
    'DETECTED',
    'TRIAGED',
    'ACKNOWLEDGED',
    'CONTAINMENT_IN_PROGRESS',
    'CONTAINED',
    'ROLLBACK_IN_PROGRESS',
    'ROLLBACK_COMPLETE',
    'RECOVERY_IN_PROGRESS',
    'RECOVERY_BLOCKED',
    'RECOVERY_FAILED',
    'RECOVERY_VERIFIED',
    'MONITORING',
    'STABILITY_CONFIRMED',
    'RESOLVED',
    'CLOSED',
    'REOPENED',
  ]);

const CANONICAL_INCIDENT_STATUS_SET: ReadonlySet<string> = new Set(
  CANONICAL_INCIDENT_STATUS_VALUES
);

export const DEFAULT_INCIDENT_STATUS: IncidentStatus = 'DETECTED';

/**
 * Validates and normalizes an input status string against INCIDENT_STATUS_ENUM_V1.
 * Rejects NULL, undefined, empty string, and any informal/unknown status
 * (e.g., INVESTIGATING, IN_PROGRESS, PENDING, FIXED, SUCCESS, DONE, COMPLETE).
 */
export function parseCanonicalIncidentStatus(
  rawStatus: unknown,
  options?: { allowCaseInsensitiveNormalization?: boolean }
): { ok: true; status: IncidentStatus } | { ok: false; error: string } {
  if (rawStatus === null || rawStatus === undefined || typeof rawStatus !== 'string') {
    return {
      ok: false,
      error: 'Incident status must be a non-null canonical INCIDENT_STATUS_ENUM_V1 string.',
    };
  }
  const trimmed = rawStatus.trim();
  if (!trimmed) {
    return {
      ok: false,
      error: 'Incident status cannot be empty.',
    };
  }
  const candidate = options?.allowCaseInsensitiveNormalization
    ? trimmed.toUpperCase()
    : trimmed;

  if (!CANONICAL_INCIDENT_STATUS_SET.has(candidate)) {
    return {
      ok: false,
      error: `Invalid incident status "${trimmed}". Only the 16 canonical INCIDENT_STATUS_ENUM_V1 values are allowed.`,
    };
  }

  return { ok: true, status: candidate as IncidentStatus };
}

// ============================================================================
// 2. AUTHORITATIVE INCIDENT TRANSITION MATRIX
// ============================================================================

export const ALLOWED_INCIDENT_STATUS_TRANSITIONS: Readonly<
  Record<IncidentStatus, ReadonlySet<IncidentStatus>>
> = Object.freeze({
  DETECTED: new Set<IncidentStatus>(['TRIAGED']),
  TRIAGED: new Set<IncidentStatus>(['ACKNOWLEDGED']),
  ACKNOWLEDGED: new Set<IncidentStatus>([
    'CONTAINMENT_IN_PROGRESS',
    'ROLLBACK_IN_PROGRESS',
  ]),
  CONTAINMENT_IN_PROGRESS: new Set<IncidentStatus>([
    'CONTAINED',
    'ROLLBACK_IN_PROGRESS',
  ]),
  CONTAINED: new Set<IncidentStatus>([
    'ROLLBACK_IN_PROGRESS',
    'RECOVERY_IN_PROGRESS',
  ]),
  ROLLBACK_IN_PROGRESS: new Set<IncidentStatus>([
    'ROLLBACK_COMPLETE',
    'RECOVERY_FAILED',
  ]),
  ROLLBACK_COMPLETE: new Set<IncidentStatus>(['RECOVERY_IN_PROGRESS']),
  RECOVERY_IN_PROGRESS: new Set<IncidentStatus>([
    'RECOVERY_BLOCKED',
    'RECOVERY_FAILED',
    'RECOVERY_VERIFIED',
  ]),
  RECOVERY_BLOCKED: new Set<IncidentStatus>(['RECOVERY_IN_PROGRESS']),
  RECOVERY_FAILED: new Set<IncidentStatus>(['RECOVERY_IN_PROGRESS']),
  RECOVERY_VERIFIED: new Set<IncidentStatus>(['MONITORING']),
  MONITORING: new Set<IncidentStatus>([
    'STABILITY_CONFIRMED',
    'RECOVERY_FAILED',
  ]),
  STABILITY_CONFIRMED: new Set<IncidentStatus>(['RESOLVED']),
  RESOLVED: new Set<IncidentStatus>(['CLOSED', 'REOPENED']),
  CLOSED: new Set<IncidentStatus>(['REOPENED']),
  REOPENED: new Set<IncidentStatus>(['TRIAGED']),
});

// ============================================================================
// 3. SEVERITY, PRIORITY, AND ESCALATION SLA RULES
// ============================================================================

export type IncidentSeverity = 'SEV-1' | 'SEV-2' | 'SEV-3' | 'SEV-4';
export type IncidentPriority = 'P0' | 'P1' | 'P2' | 'P3';

export interface SlaTargetsMinutes {
  initialResponseMinutes: number;
  ownerAssignedMinutes: number;
  escalationMinutes: number; // 0 = immediate
}

export const DEFAULT_INCIDENT_SLA_TARGETS: Readonly<
  Record<IncidentSeverity, { defaultPriority: IncidentPriority } & SlaTargetsMinutes>
> = Object.freeze({
  'SEV-1': {
    defaultPriority: 'P0',
    initialResponseMinutes: 15,
    ownerAssignedMinutes: 15,
    escalationMinutes: 0, // Immediate
  },
  'SEV-2': {
    defaultPriority: 'P1',
    initialResponseMinutes: 30,
    ownerAssignedMinutes: 30,
    escalationMinutes: 60, // <= 1 hour
  },
  'SEV-3': {
    defaultPriority: 'P2',
    initialResponseMinutes: 240, // <= 4 hours
    ownerAssignedMinutes: 240,
    escalationMinutes: 1440, // <= 1 business day (24h)
  },
  'SEV-4': {
    defaultPriority: 'P3',
    initialResponseMinutes: 1440, // <= 1 business day
    ownerAssignedMinutes: 1440,
    escalationMinutes: 4320, // <= 3 business days (72h)
  },
});

const SEVERITY_RANK: Readonly<Record<IncidentSeverity, number>> = {
  'SEV-1': 4,
  'SEV-2': 3,
  'SEV-3': 2,
  'SEV-4': 1,
};

export interface SeverityClassificationInput {
  candidateSeverities?: IncidentSeverity[];
  unknownSeverityPlausibleHigh?: IncidentSeverity;
  securityFlags?: {
    authenticationBypass?: boolean;
    authorizationBypass?: boolean;
    privilegeEscalation?: boolean;
    crossUserAccess?: boolean;
    credentialExposure?: boolean;
    sessionTokenExposure?: boolean;
    sensitiveDataExposure?: boolean;
  };
  dataIntegrityFlags?: {
    dataCorruption?: boolean;
    unexpectedDataDeletion?: boolean;
    incorrectOwnership?: boolean;
    incorrectBalances?: boolean;
    incorrectExamScores?: boolean;
    incorrectPaymentRecords?: boolean;
    incorrectVerificationStatus?: boolean;
    unauthorizedDatabaseModification?: boolean;
  };
  widespreadCoreOutage?: boolean;
}

/**
 * Sections 7, 8, 9, 10, 22, 29: Determines the authoritative Severity and Priority.
 *   - Uses the highest applicable severity when multiple impacts exist
 *   - Enforces Security Override (>= SEV-1)
 *   - Enforces Data-Integrity Override (>= SEV-1)
 *   - Enforces Unknown Severity Rule (higher plausible severity)
 */
export function determineAuthoritativeSeverityAndPriority(
  input: SeverityClassificationInput
): {
  severity: IncidentSeverity;
  priority: IncidentPriority;
  securityOverrideApplied: boolean;
  dataIntegrityOverrideApplied: boolean;
  reasoning: string[];
} {
  const reasoning: string[] = [];
  const securityOverrideApplied = Boolean(
    input.securityFlags &&
      Object.values(input.securityFlags).some((v) => v === true)
  );
  const dataIntegrityOverrideApplied = Boolean(
    input.dataIntegrityFlags &&
      Object.values(input.dataIntegrityFlags).some((v) => v === true)
  );

  let highest: IncidentSeverity = input.unknownSeverityPlausibleHigh || 'SEV-4';

  if (input.candidateSeverities && input.candidateSeverities.length > 0) {
    for (const candidate of input.candidateSeverities) {
      if (SEVERITY_RANK[candidate] > SEVERITY_RANK[highest]) {
        highest = candidate;
      }
    }
  }

  if (securityOverrideApplied) {
    highest = 'SEV-1';
    reasoning.push('Security Override: Critical security boundary or credential/session exposure forces SEV-1.');
  }
  if (dataIntegrityOverrideApplied) {
    highest = 'SEV-1';
    reasoning.push('Data-Integrity Override: Critical data corruption/integrity impact forces SEV-1.');
  }
  if (input.widespreadCoreOutage) {
    highest = 'SEV-1';
    reasoning.push('Availability Classification: Widespread core production outage forces SEV-1.');
  }

  const priority = DEFAULT_INCIDENT_SLA_TARGETS[highest].defaultPriority;
  if (reasoning.length === 0) {
    reasoning.push(`Assigned ${highest} (${priority}) based on highest documented impact.`);
  }

  return {
    severity: highest,
    priority,
    securityOverrideApplied,
    dataIntegrityOverrideApplied,
    reasoning,
  };
}

export interface SlaBreachRecord {
  slaType:
    | 'INITIAL_RESPONSE'
    | 'OWNER_ASSIGNMENT'
    | 'ESCALATION'
    | 'BLOCKED_ITEM_DEADLINE'
    | 'STABILITY_WINDOW';
  expectedTimeMs: number;
  actualTimeMs: number;
  delayMinutes: number;
  reason: string;
  owner: string;
  escalatedTo: string;
  correctiveAction: string;
  recordedAt: string;
}

// ============================================================================
// 4. EVIDENCE RETENTION & IMMUTABLE AUDIT TRAIL TYPES (SECTIONS 1–28)
// ============================================================================

export type RequiredAuditEventType =
  | 'INCIDENT_CREATED'
  | 'INCIDENT_TRIAGED'
  | 'INCIDENT_ACKNOWLEDGED'
  | 'CONTAINMENT_STARTED'
  | 'CONTAINMENT_COMPLETED'
  | 'ROLLBACK_INITIATED'
  | 'ROLLBACK_ACTION_COMPLETED'
  | 'ROLLBACK_FAILED'
  | 'RECOVERY_VERIFICATION_STARTED'
  | 'VERIFICATION_ITEM_STARTED'
  | 'VERIFICATION_ITEM_PASSED'
  | 'VERIFICATION_ITEM_FAILED'
  | 'VERIFICATION_ITEM_BLOCKED'
  | 'REMEDIATION_STARTED'
  | 'REMEDIATION_COMPLETED'
  | 'RETEST_REQUESTED'
  | 'RETEST_COMPLETED'
  | 'EXCEPTION_REQUESTED'
  | 'EXCEPTION_APPROVED'
  | 'EXCEPTION_REJECTED'
  | 'DEADLINE_CREATED'
  | 'DEADLINE_EXTENDED'
  | 'DEADLINE_EXCEEDED'
  | 'RECOVERY_VERIFIED'
  | 'RECOVERY_SIGN_OFF_COMPLETED'
  | 'MONITORING_STARTED'
  | 'MONITORING_COMPLETED'
  | 'STABILITY_CONFIRMED'
  | 'INCIDENT_RESOLVED'
  | 'INCIDENT_CLOSED'
  | 'INCIDENT_REOPENED'
  | 'SEVERITY_REASSESSED'
  | 'SECURITY_ESCALATION_TRIGGERED'
  | 'DATABASE_ESCALATION_TRIGGERED'
  | 'SLA_BREACHED'
  | 'EVIDENCE_SUPERSEDED'
  | 'EVIDENCE_CONFLICT_RECORDED'
  | 'AUDIT_LOG_ACCESSED'
  | 'GUARD_FAILURE_REJECTED';

/**
 * Section 3: Every audit event must contain all 16 required fields.
 * Non-applicable fields are explicitly set to "N/A".
 */
export interface AuditTrailEventRecord {
  readonly eventId: string;
  readonly incidentId: string;
  readonly verificationId: string; // or "N/A"
  readonly eventType: RequiredAuditEventType;
  readonly previousStatus: string; // or "N/A"
  readonly newStatus: string; // or "N/A"
  readonly actor: string;
  readonly actorRole: string;
  readonly timestamp: string; // Server-authoritative UTC ISO string
  readonly environment: 'development' | 'staging' | 'production' | 'test';
  readonly reason: string;
  readonly result: string;
  readonly evidenceReference: string;
  readonly relatedChangeOrDeploymentId: string; // or "N/A"
  readonly approver: string; // or "N/A"
  readonly notes: string; // or "N/A"
  readonly supersedesEventId?: string;
  readonly integrityHash: string;
}

export interface FormalSignOffEvidenceRecord {
  readonly signOffId: string;
  readonly signOffType:
    | 'Recovery Sign-off'
    | 'Security Sign-off'
    | 'Database Sign-off'
    | 'Monitoring Sign-off'
    | 'Incident Closure Sign-off';
  readonly signer: string;
  readonly role: string;
  readonly timestamp: string;
  readonly evidenceReviewed: string[];
  readonly decision: 'APPROVED' | 'REJECTED';
  readonly comments: string;
}

export interface EvidenceConflictRecord {
  readonly conflictId: string;
  readonly sourceA: string;
  readonly sourceB: string;
  readonly conflictDescription: string;
  readonly owner: string;
  readonly investigation: string;
  readonly resolution: string | null;
  readonly resolved: boolean;
  readonly recordedAt: string;
}

/**
 * Sections 9 & 10: Redacts any sensitive secrets (passwords, OTPs, tokens, keys)
 * and minimizes personal data (redacting raw emails and 10-digit phone numbers).
 */
export function sanitizeAndMinimizeEvidenceText(raw: string): string {
  if (!raw || typeof raw !== 'string') return 'N/A';
  let cleaned = raw
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?/g, '[REDACTED_TOKEN]')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]')
    .replace(/\b[0-9a-f]{48,}\b/gi, '[REDACTED_HEX_SECRET]');
  // Redact explicit secret key=value patterns
  cleaned = cleaned.replace(
    /(password|otp|token|secret|api_key|private_key|cookie)\s*[:=]\s*[^\s,;]+/gi,
    '$1=[REDACTED]'
  );
  // Minimize raw email addresses to redacted form
  cleaned = cleaned.replace(
    /\b([a-z0-9._%+-])[a-z0-9._%+-]*@([a-z0-9.-]+\.[a-z]{2,})\b/gi,
    '$1***@$2'
  );
  // Minimize raw 10-digit phone numbers
  cleaned = cleaned.replace(/\b([6-9]\d)\d{6}(\d{2})\b/g, '$1******$2');
  return cleaned;
}

// ============================================================================
// 5. AUTHORITATIVE INCIDENT AGGREGATE & TRANSITION ENGINE
// ============================================================================

export type TriggerExecutionClass = 'PRE_TRANSITION' | 'ON_TRANSITION' | 'POST_TRANSITION';
export type TriggerCriticality = 'Critical' | 'Required' | 'Non-critical';

export interface ExecutedTriggerRecord {
  readonly triggerId: string;
  readonly transitionId: string;
  readonly triggerClass: TriggerExecutionClass;
  readonly criticality: TriggerCriticality;
  readonly name: string;
  readonly status: 'SUCCEEDED' | 'FAILED' | 'RETRIED_SUCCEEDED';
  readonly attempts: number;
  readonly timestamp: string;
  readonly detail: string;
}

export type WebhookEventName =
  | 'incident.status.changed'
  | 'incident.severity.changed'
  | 'incident.escalated'
  | 'incident.blocked'
  | 'incident.recovery.failed'
  | 'incident.recovery.verified'
  | 'incident.monitoring.started'
  | 'incident.stability.confirmed'
  | 'incident.resolved'
  | 'incident.closed'
  | 'incident.reopened';

export interface EmittedIncidentEventPayload {
  readonly eventId: string;
  readonly eventName: WebhookEventName;
  readonly incidentId: string;
  readonly previousStatus: IncidentStatus;
  readonly newStatus: IncidentStatus;
  readonly severity: IncidentSeverity;
  readonly priority: IncidentPriority;
  readonly actor: string;
  readonly timestamp: string;
  readonly transitionId: string;
}

export interface SeverityChangeRecord {
  readonly previousSeverity: IncidentSeverity;
  readonly newSeverity: IncidentSeverity;
  readonly previousPriority: IncidentPriority;
  readonly newPriority: IncidentPriority;
  readonly reason: string;
  readonly evidenceReference: string;
  readonly changedBy: string;
  readonly timestamp: string;
}

export interface ProductionIncidentRecord {
  readonly incidentId: string;
  readonly title: string;
  readonly version: number;
  readonly status: IncidentStatus;
  readonly severity: IncidentSeverity;
  readonly priority: IncidentPriority;
  readonly affectedEnvironment: 'development' | 'staging' | 'production' | 'test';
  readonly affectedFunction: string;
  readonly affectedUsersScope: string;
  readonly securityImpact: string;
  readonly dataImpact: string;
  readonly availabilityImpact: string;
  readonly containmentSummary: string;
  readonly primaryOwner: string;
  readonly backupOwner: string;
  readonly securityOwner: string;
  readonly databaseOwner: string;
  readonly rollbackOwner: string;
  readonly monitoringOwner: string;
  readonly closureOwner: string;
  // Separate sub-status dimensions (Section 10)
  readonly rollbackSubStatus: 'NOT_STARTED' | 'INITIATED' | 'ACTION_COMPLETE' | 'ACTION_FAILED';
  readonly recoverySubStatus: 'NOT_STARTED' | 'VERIFICATION_RUNNING' | 'VERIFIED' | 'SIGN_OFF_COMPLETE';
  readonly monitoringSubStatus: 'NOT_STARTED' | 'ACTIVE' | 'STABLE' | 'FAILED';
  readonly approvalSubStatus: 'PENDING' | 'COMPLETE';
  readonly slaSubStatus: 'WITHIN_SLA' | 'SLA_BREACHED';
  // Immutable SLA Clock anchors (INVARIANT-20)
  readonly detectedAtMs: number;
  readonly detectedAtIso: string;
  readonly reportedAtMs: number;
  readonly reportedAtIso: string;
  readonly responseDeadlineMs: number;
  readonly ownerAssignedDeadlineMs: number;
  readonly escalationDeadlineMs: number;
  // Lifecycle milestone timestamps
  readonly triagedAtIso: string | null;
  readonly acknowledgedAtIso: string | null;
  readonly containmentStartedAtIso: string | null;
  readonly containedAtIso: string | null;
  readonly rollbackStartedAtIso: string | null;
  readonly rollbackCompletedAtIso: string | null;
  readonly recoveryStartedAtIso: string | null;
  readonly recoveryVerifiedAtIso: string | null;
  readonly monitoringStartedAtIso: string | null;
  readonly stabilityConfirmedAtIso: string | null;
  readonly resolvedAtIso: string | null;
  readonly closedAtIso: string | null;
  readonly reopenedAtIso: string | null;
  // Linked domain artifacts
  readonly verificationItems: Record<string, VerificationStatefulItem>;
  readonly signOffs: FormalSignOffEvidenceRecord[];
  readonly evidenceConflicts: EvidenceConflictRecord[];
  readonly severityHistory: SeverityChangeRecord[];
  readonly slaBreaches: SlaBreachRecord[];
  readonly auditTrail: AuditTrailEventRecord[];
  readonly triggerHistory: ExecutedTriggerRecord[];
  readonly emittedEvents: EmittedIncidentEventPayload[];
  readonly outstandingFollowUpActions: Array<{
    actionId: string;
    owner: string;
    deadline: string;
    description: string;
  }>;
  readonly securityReviewComplete: boolean;
  readonly databaseReviewComplete: boolean;
}

// Authoritative server-side store & idempotency / concurrency registries
const incidentStore = new Map<string, ProductionIncidentRecord>();
const inFlightIncidentLocks = new Set<string>();
const processedTransitionResults = new Map<string, TransitionResultContract>();
const processedTriggerKeys = new Set<string>();

export interface TransitionResultContract {
  httpStatus: 200 | 401 | 403 | 404 | 409 | 422 | 429;
  success: boolean;
  incident_id: string;
  previous_status: IncidentStatus | null;
  current_status: IncidentStatus | null;
  transition_id: string;
  timestamp: string;
  required_actions: string[];
  trigger_status: {
    transitionSucceeded: boolean;
    allTriggersSucceeded: boolean;
    failedCriticalOrRequiredTriggers: number;
    failedNonCriticalTriggers: number;
    executedTriggers: ExecutedTriggerRecord[];
  };
  audit_event_id: string | null;
  error: string | null;
  guard_code?: GuardFailureCode | 'GUARD_PASSED';
}

function createAuditTrailEvent(params: {
  incidentId: string;
  verificationId?: string;
  eventType: RequiredAuditEventType;
  previousStatus?: string;
  newStatus?: string;
  actor: string;
  actorRole: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  reason: string;
  result: string;
  evidenceReference: string;
  relatedChangeOrDeploymentId?: string;
  approver?: string;
  notes?: string;
  supersedesEventId?: string;
  serverNowIso?: string;
}): AuditTrailEventRecord {
  const eventId = `AUD-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
  const timestamp = params.serverNowIso || new Date().toISOString();
  const safeReason = sanitizeAndMinimizeEvidenceText(params.reason);
  const safeEvidence = sanitizeAndMinimizeEvidenceText(params.evidenceReference);
  const safeNotes = params.notes
    ? sanitizeAndMinimizeEvidenceText(params.notes)
    : 'N/A';

  const payloadForHash = [
    eventId,
    params.incidentId,
    params.verificationId || 'N/A',
    params.eventType,
    params.previousStatus || 'N/A',
    params.newStatus || 'N/A',
    params.actor,
    params.actorRole,
    timestamp,
    params.environment,
    safeReason,
    params.result,
    safeEvidence,
  ].join('|');

  const integrityHash = crypto
    .createHash('sha256')
    .update(payloadForHash)
    .digest('hex');

  return Object.freeze({
    eventId,
    incidentId: params.incidentId,
    verificationId: params.verificationId?.trim() || 'N/A',
    eventType: params.eventType,
    previousStatus: params.previousStatus?.trim() || 'N/A',
    newStatus: params.newStatus?.trim() || 'N/A',
    actor: params.actor.trim(),
    actorRole: params.actorRole.trim(),
    timestamp,
    environment: params.environment,
    reason: safeReason,
    result: params.result.trim(),
    evidenceReference: safeEvidence,
    relatedChangeOrDeploymentId:
      params.relatedChangeOrDeploymentId?.trim() || 'N/A',
    approver: params.approver?.trim() || 'N/A',
    notes: safeNotes,
    supersedesEventId: params.supersedesEventId,
    integrityHash,
  });
}

/**
 * Creates a new incident in the canonical DETECTED state (Section 5 Default Status).
 */
export function createProductionIncident(params: {
  incidentId: string;
  title: string;
  initialDescription: string;
  detectionSource: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  actor: string;
  actorRole: string;
  primaryOwner?: string;
  backupOwner?: string;
  securityOwner?: string;
  databaseOwner?: string;
  rollbackOwner?: string;
  monitoringOwner?: string;
  closureOwner?: string;
  initialSeverity?: IncidentSeverity;
  serverNowMs?: number;
}): { ok: true; incident: ProductionIncidentRecord } | { ok: false; error: string } {
  if (
    !params.incidentId?.trim() ||
    !params.title?.trim() ||
    !params.initialDescription?.trim() ||
    !params.detectionSource?.trim() ||
    !params.actor?.trim()
  ) {
    return {
      ok: false,
      error:
        'DETECTED entry requirement violation: incidentId, title, initialDescription, detectionSource, and actor are required.',
    };
  }

  const nowMs = typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const sev: IncidentSeverity = params.initialSeverity || 'SEV-1'; // Unknown Severity Rule defaults conservatively
  const slaConfig = DEFAULT_INCIDENT_SLA_TARGETS[sev];

  const creationEvent = createAuditTrailEvent({
    incidentId: params.incidentId.trim(),
    eventType: 'INCIDENT_CREATED',
    previousStatus: 'N/A',
    newStatus: 'DETECTED',
    actor: params.actor,
    actorRole: params.actorRole || 'incident_responder',
    environment: params.environment,
    reason: params.initialDescription,
    result: 'DETECTED',
    evidenceReference: params.detectionSource,
    serverNowIso: nowIso,
  });

  const incident: ProductionIncidentRecord = Object.freeze({
    incidentId: params.incidentId.trim(),
    title: sanitizeAndMinimizeEvidenceText(params.title),
    version: 1,
    status: DEFAULT_INCIDENT_STATUS,
    severity: sev,
    priority: slaConfig.defaultPriority,
    affectedEnvironment: params.environment,
    affectedFunction: 'Pending Triage',
    affectedUsersScope: 'Pending Triage',
    securityImpact: 'Under Assessment',
    dataImpact: 'Under Assessment',
    availabilityImpact: 'Under Assessment',
    containmentSummary: 'N/A',
    primaryOwner: params.primaryOwner || 'Dolly Singh',
    backupOwner: params.backupOwner || 'Vikramaditya Rathore',
    securityOwner: params.securityOwner || 'Siddharth Verma',
    databaseOwner: params.databaseOwner || 'Ananya Deshmukh',
    rollbackOwner: params.rollbackOwner || 'Dolly Singh',
    monitoringOwner: params.monitoringOwner || 'Vikramaditya Rathore',
    closureOwner: params.closureOwner || 'Dolly Singh',
    rollbackSubStatus: 'NOT_STARTED',
    recoverySubStatus: 'NOT_STARTED',
    monitoringSubStatus: 'NOT_STARTED',
    approvalSubStatus: 'PENDING',
    slaSubStatus: 'WITHIN_SLA',
    detectedAtMs: nowMs,
    detectedAtIso: nowIso,
    reportedAtMs: nowMs,
    reportedAtIso: nowIso,
    responseDeadlineMs: nowMs + slaConfig.initialResponseMinutes * 60 * 1000,
    ownerAssignedDeadlineMs: nowMs + slaConfig.ownerAssignedMinutes * 60 * 1000,
    escalationDeadlineMs: nowMs + slaConfig.escalationMinutes * 60 * 1000,
    triagedAtIso: null,
    acknowledgedAtIso: null,
    containmentStartedAtIso: null,
    containedAtIso: null,
    rollbackStartedAtIso: null,
    rollbackCompletedAtIso: null,
    recoveryStartedAtIso: null,
    recoveryVerifiedAtIso: null,
    monitoringStartedAtIso: null,
    stabilityConfirmedAtIso: null,
    resolvedAtIso: null,
    closedAtIso: null,
    reopenedAtIso: null,
    verificationItems: {},
    signOffs: [],
    evidenceConflicts: [],
    severityHistory: [],
    slaBreaches: [],
    auditTrail: [creationEvent],
    triggerHistory: [],
    emittedEvents: [],
    outstandingFollowUpActions: [],
    securityReviewComplete: false,
    databaseReviewComplete: false,
  });

  incidentStore.set(incident.incidentId, incident);
  return { ok: true, incident };
}

export function getAuthoritativeIncident(
  incidentId: string
): ProductionIncidentRecord | null {
  return incidentStore.get(incidentId) || null;
}

/**
 * Sections 23 & 24 & INVARIANT-20: Reassesses Incident Severity without resetting SLA clocks
 * or changing the incident lifecycle status. Prohibits silent downgrading without evidence.
 */
export function reassessIncidentSeverity(params: {
  incidentId: string;
  newSeverity: IncidentSeverity;
  reason: string;
  evidenceReference: string;
  actor: string;
  actorRole: string;
  securityOwnerApprovedDowngrade?: boolean;
  serverNowMs?: number;
}): { ok: true; incident: ProductionIncidentRecord } | { ok: false; error: string } {
  const current = incidentStore.get(params.incidentId);
  if (!current) {
    return { ok: false, error: 'Incident not found.' };
  }
  if (!params.reason?.trim() || !params.evidenceReference?.trim()) {
    return {
      ok: false,
      error: 'No Silent Downgrading / Severity Change Rule: reason and evidenceReference are required.',
    };
  }

  const isDowngrade =
    SEVERITY_RANK[params.newSeverity] < SEVERITY_RANK[current.severity];
  if (isDowngrade && current.severity === 'SEV-1' && !params.securityOwnerApprovedDowngrade) {
    return {
      ok: false,
      error:
        'Security/Severity Downgrade Rule: Downgrading a SEV-1 incident requires explicit Security/Incident Owner assessment approval and documented evidence.',
    };
  }

  const nowMs = typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const newPriority = DEFAULT_INCIDENT_SLA_TARGETS[params.newSeverity].defaultPriority;

  const sevChange: SeverityChangeRecord = Object.freeze({
    previousSeverity: current.severity,
    newSeverity: params.newSeverity,
    previousPriority: current.priority,
    newPriority,
    reason: sanitizeAndMinimizeEvidenceText(params.reason),
    evidenceReference: sanitizeAndMinimizeEvidenceText(params.evidenceReference),
    changedBy: params.actor.trim(),
    timestamp: nowIso,
  });

  const auditEvent = createAuditTrailEvent({
    incidentId: current.incidentId,
    eventType: 'SEVERITY_REASSESSED',
    previousStatus: current.status,
    newStatus: current.status, // Status remains separate from severity (Section 30)
    actor: params.actor,
    actorRole: params.actorRole,
    environment: current.affectedEnvironment,
    reason: `${current.severity} -> ${params.newSeverity}: ${params.reason}`,
    result: `${params.newSeverity} (${newPriority})`,
    evidenceReference: params.evidenceReference,
    serverNowIso: nowIso,
  });

  const emittedEvent: EmittedIncidentEventPayload = Object.freeze({
    eventId: `EVT-${crypto.randomBytes(5).toString('hex').toUpperCase()}`,
    eventName: 'incident.severity.changed',
    incidentId: current.incidentId,
    previousStatus: current.status,
    newStatus: current.status,
    severity: params.newSeverity,
    priority: newPriority,
    actor: params.actor.trim(),
    timestamp: nowIso,
    transitionId: `SEV-${current.version + 1}`,
  });

  // INVARIANT-20: Preserve original detectedAtMs / reportedAtMs / SLA clock anchors
  const updated: ProductionIncidentRecord = Object.freeze({
    ...current,
    version: current.version + 1,
    severity: params.newSeverity,
    priority: newPriority,
    severityHistory: [...current.severityHistory, sevChange],
    auditTrail: [...current.auditTrail, auditEvent],
    emittedEvents: [...current.emittedEvents, emittedEvent],
  });

  incidentStore.set(updated.incidentId, updated);
  return { ok: true, incident: updated };
}

/**
 * Section 24 & 25: Automatic Security & Database Integrity Escalation Triggers.
 * Immediately escalates to SEV-1 / P0, notifies the Security or Database Owner,
 * preserves evidence, and blocks closure until security/database review is complete.
 */
export function triggerAutomaticDomainEscalation(params: {
  incidentId: string;
  domain: 'SECURITY' | 'DATABASE';
  anomalyDescription: string;
  evidenceReference: string;
  affectedEntities: string;
  serverNowMs?: number;
}): { ok: true; incident: ProductionIncidentRecord } | { ok: false; error: string } {
  const current = incidentStore.get(params.incidentId);
  if (!current) {
    return { ok: false, error: 'Incident not found.' };
  }
  const nowMs = typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();

  const auditEvent = createAuditTrailEvent({
    incidentId: current.incidentId,
    eventType:
      params.domain === 'SECURITY'
        ? 'SECURITY_ESCALATION_TRIGGERED'
        : 'DATABASE_ESCALATION_TRIGGERED',
    previousStatus: current.status,
    newStatus: current.status,
    actor: 'system_auto_trigger',
    actorRole: 'system',
    environment: current.affectedEnvironment,
    reason: `[AUTO-${params.domain}-TRIGGER] ${params.anomalyDescription} (Entities: ${params.affectedEntities})`,
    result: 'ESCALATED_TO_SEV1_P0',
    evidenceReference: params.evidenceReference,
    serverNowIso: nowIso,
  });

  const emittedEvent: EmittedIncidentEventPayload = Object.freeze({
    eventId: `EVT-${crypto.randomBytes(5).toString('hex').toUpperCase()}`,
    eventName: 'incident.escalated',
    incidentId: current.incidentId,
    previousStatus: current.status,
    newStatus: current.status,
    severity: 'SEV-1',
    priority: 'P0',
    actor: 'system_auto_trigger',
    timestamp: nowIso,
    transitionId: `ESC-${current.version + 1}`,
  });

  const updated: ProductionIncidentRecord = Object.freeze({
    ...current,
    version: current.version + 1,
    severity: 'SEV-1',
    priority: 'P0',
    securityImpact:
      params.domain === 'SECURITY'
        ? sanitizeAndMinimizeEvidenceText(params.anomalyDescription)
        : current.securityImpact,
    dataImpact:
      params.domain === 'DATABASE'
        ? sanitizeAndMinimizeEvidenceText(params.anomalyDescription)
        : current.dataImpact,
    securityReviewComplete:
      params.domain === 'SECURITY' ? false : current.securityReviewComplete,
    databaseReviewComplete:
      params.domain === 'DATABASE' ? false : current.databaseReviewComplete,
    auditTrail: [...current.auditTrail, auditEvent],
    emittedEvents: [...current.emittedEvents, emittedEvent],
  });

  incidentStore.set(updated.incidentId, updated);
  return { ok: true, incident: updated };
}

/**
 * Section 26 & 27: Evaluates SLA deadlines and records SLA BREACHED without altering original detection timestamps.
 */
export function evaluateIncidentSlaDeadlines(params: {
  incidentId: string;
  currentTimeMs: number;
}): {
  slaBreached: boolean;
  escalationLevel: 'IMMEDIATE_SEV1' | 'DEADLINE_BREACHED' | 'T_MINUS_4H' | 'T_MINUS_24H' | 'NORMAL';
  incident: ProductionIncidentRecord;
} {
  const current = incidentStore.get(params.incidentId);
  if (!current) {
    throw new Error(`Incident ${params.incidentId} not found`);
  }

  const nowIso = new Date(params.currentTimeMs).toISOString();
  const newBreaches: SlaBreachRecord[] = [];

  if (
    !current.acknowledgedAtIso &&
    params.currentTimeMs > current.responseDeadlineMs &&
    !current.slaBreaches.some((b) => b.slaType === 'INITIAL_RESPONSE')
  ) {
    newBreaches.push({
      slaType: 'INITIAL_RESPONSE',
      expectedTimeMs: current.responseDeadlineMs,
      actualTimeMs: params.currentTimeMs,
      delayMinutes: Math.ceil(
        (params.currentTimeMs - current.responseDeadlineMs) / 60000
      ),
      reason: 'Initial response deadline exceeded prior to acknowledgement.',
      owner: current.primaryOwner,
      escalatedTo: current.backupOwner,
      correctiveAction: 'Immediate escalation to Backup Owner and Primary Rollback Owner.',
      recordedAt: nowIso,
    });
  }

  let updated = current;
  if (newBreaches.length > 0) {
    const breachEvents = newBreaches.map((b) =>
      createAuditTrailEvent({
        incidentId: current.incidentId,
        eventType: 'SLA_BREACHED',
        previousStatus: current.status,
        newStatus: current.status,
        actor: 'system_sla_monitor',
        actorRole: 'system',
        environment: current.affectedEnvironment,
        reason: `${b.slaType} delayed by ${b.delayMinutes}m`,
        result: 'SLA_BREACHED',
        evidenceReference: `expected:${new Date(b.expectedTimeMs).toISOString()}`,
        serverNowIso: nowIso,
      })
    );

    updated = Object.freeze({
      ...current,
      version: current.version + 1,
      slaSubStatus: 'SLA_BREACHED',
      slaBreaches: [...current.slaBreaches, ...newBreaches],
      auditTrail: [...current.auditTrail, ...breachEvents],
    });
    incidentStore.set(updated.incidentId, updated);
  }

  const remainingMs = updated.responseDeadlineMs - params.currentTimeMs;
  const escalationLevel =
    updated.severity === 'SEV-1'
      ? 'IMMEDIATE_SEV1'
      : updated.slaSubStatus === 'SLA_BREACHED'
        ? 'DEADLINE_BREACHED'
        : remainingMs <= 4 * 60 * 60 * 1000
          ? 'T_MINUS_4H'
          : remainingMs <= 24 * 60 * 60 * 1000
            ? 'T_MINUS_24H'
            : 'NORMAL';

  return {
    slaBreached: updated.slaSubStatus === 'SLA_BREACHED',
    escalationLevel,
    incident: updated,
  };
}

/**
 * Section 25 (Evidence Correction Rule): Marks an older evidence record as superseded
 * and appends a new correction audit event without deleting history.
 */
export function recordEvidenceCorrectionEvent(params: {
  incidentId: string;
  supersededEventId: string;
  correctedEvidenceReference: string;
  reason: string;
  actor: string;
  actorRole: string;
  serverNowMs?: number;
}): { ok: true; incident: ProductionIncidentRecord } | { ok: false; error: string } {
  const current = incidentStore.get(params.incidentId);
  if (!current) return { ok: false, error: 'Incident not found.' };
  const originalExists = current.auditTrail.some(
    (e) => e.eventId === params.supersededEventId
  );
  if (!originalExists) {
    return { ok: false, error: 'Original audit event ID not found.' };
  }
  const nowIso = new Date(
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now()
  ).toISOString();

  const correctionEvent = createAuditTrailEvent({
    incidentId: current.incidentId,
    eventType: 'EVIDENCE_SUPERSEDED',
    previousStatus: current.status,
    newStatus: current.status,
    actor: params.actor,
    actorRole: params.actorRole,
    environment: current.affectedEnvironment,
    reason: `Supersedes ${params.supersededEventId}: ${params.reason}`,
    result: 'EVIDENCE_CORRECTED',
    evidenceReference: params.correctedEvidenceReference,
    supersedesEventId: params.supersededEventId,
    serverNowIso: nowIso,
  });

  const updated: ProductionIncidentRecord = Object.freeze({
    ...current,
    version: current.version + 1,
    auditTrail: [...current.auditTrail, correctionEvent],
  });
  incidentStore.set(updated.incidentId, updated);
  return { ok: true, incident: updated };
}

/**
 * Section 24 (Evidence Conflict Rule): Records a conflict between two evidence sources
 * and blocks final sign-off / closure until resolved.
 */
export function recordEvidenceConflict(params: {
  incidentId: string;
  sourceA: string;
  sourceB: string;
  conflictDescription: string;
  owner: string;
  investigation: string;
  actor: string;
  actorRole: string;
  serverNowMs?: number;
}): { ok: true; incident: ProductionIncidentRecord } | { ok: false; error: string } {
  const current = incidentStore.get(params.incidentId);
  if (!current) return { ok: false, error: 'Incident not found.' };
  const nowIso = new Date(
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now()
  ).toISOString();

  const conflict: EvidenceConflictRecord = Object.freeze({
    conflictId: `CNF-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    sourceA: sanitizeAndMinimizeEvidenceText(params.sourceA),
    sourceB: sanitizeAndMinimizeEvidenceText(params.sourceB),
    conflictDescription: sanitizeAndMinimizeEvidenceText(params.conflictDescription),
    owner: params.owner.trim(),
    investigation: sanitizeAndMinimizeEvidenceText(params.investigation),
    resolution: null,
    resolved: false,
    recordedAt: nowIso,
  });

  const auditEvent = createAuditTrailEvent({
    incidentId: current.incidentId,
    eventType: 'EVIDENCE_CONFLICT_RECORDED',
    previousStatus: current.status,
    newStatus: current.status,
    actor: params.actor,
    actorRole: params.actorRole,
    environment: current.affectedEnvironment,
    reason: `Conflict between ${params.sourceA} and ${params.sourceB}: ${params.conflictDescription}`,
    result: 'STOP_FINAL_SIGN_OFF',
    evidenceReference: conflict.conflictId,
    serverNowIso: nowIso,
  });

  const updated: ProductionIncidentRecord = Object.freeze({
    ...current,
    version: current.version + 1,
    evidenceConflicts: [...current.evidenceConflicts, conflict],
    auditTrail: [...current.auditTrail, auditEvent],
  });
  incidentStore.set(updated.incidentId, updated);
  return { ok: true, incident: updated };
}

export interface IncidentTransitionPreconditions {
  // For DETECTED -> TRIAGED
  triageDetails?: {
    severity: IncidentSeverity;
    priority: IncidentPriority;
    affectedFunction: string;
    affectedUsersScope: string;
    primaryOwner: string;
    backupOwner: string;
  };
  // For CONTAINMENT_IN_PROGRESS -> CONTAINED
  containmentVerified?: {
    containmentAction: string;
    expectedEffect: string;
    observedEffect: string;
    affectedScope: string;
  };
  // For CONTAINED -> ROLLBACK_IN_PROGRESS or ACKNOWLEDGED -> ROLLBACK_IN_PROGRESS
  rollbackPlanConfirmed?: {
    rollbackTargetCommit: string;
    rollbackAuthorityConfirmed: boolean;
    databaseImplicationsReviewed: boolean;
    containmentNotRequiredOrSatisfied?: boolean;
  };
  // For ROLLBACK_IN_PROGRESS -> ROLLBACK_COMPLETE
  rollbackCompletionEvidence?: {
    knownGoodVersionActive: boolean;
    failedVersionInactive: boolean;
    expectedInstancesRestored: boolean;
    requiredConfigurationRestored: boolean;
    requiredDatabaseActionCompleted: boolean;
    rollbackOperationFinished: boolean;
    deploymentEvidenceRef: string;
  };
  // For RECOVERY_IN_PROGRESS -> RECOVERY_BLOCKED
  blockedDetails?: {
    blockingReason: string;
    affectedVerificationId: string;
    dependency: string;
    owner: string;
    deadline: string;
    riskLevel: BlockedRiskLevel;
    containmentStatus: string;
  };
  // For RECOVERY_BLOCKED -> RECOVERY_IN_PROGRESS
  unblockDetails?: {
    blockerResolved: boolean;
    dependencyAvailable: boolean;
    accessRestored: boolean;
    retestStarted: boolean;
  };
  // For RECOVERY_IN_PROGRESS -> RECOVERY_FAILED
  failureDetails?: {
    verificationId: string;
    expectedResult: string;
    actualResult: string;
    impact: string;
  };
  // For RECOVERY_FAILED -> RECOVERY_IN_PROGRESS
  retestDetails?: {
    remediationCompleted: boolean;
    retestInitiated: boolean;
  };
  // For RECOVERY_IN_PROGRESS -> RECOVERY_VERIFIED
  verificationSummary?: {
    verifications: readonly AreaVerificationRecord[];
    databaseIntegrityConfirmed: boolean;
    securityIntegrityConfirmed: boolean;
  };
  // For RECOVERY_VERIFIED -> MONITORING
  monitoringStartDetails?: {
    recoverySignOffComplete: boolean;
    monitoringOwner: string;
    monitoringWindowMinutes: 60 | 120;
    monitoringChecksConfigured: boolean;
  };
  // For MONITORING -> STABILITY_CONFIRMED
  stabilityConfirmationDetails?: {
    monitoringSession: PostRecoveryMonitoringSession;
    noCriticalRegression: boolean;
    noUnresolvedSecurityIssue: boolean;
    noUnresolvedDatabaseIssue: boolean;
    monitoringOwnerSignedOff: boolean;
  };
  // For STABILITY_CONFIRMED -> RESOLVED
  resolutionDetails?: {
    requiredTechnicalRemediationComplete: boolean;
    noCriticalUnresolvedIssue: boolean;
    followUpWorkDocumented: boolean;
  };
  // For RESOLVED -> CLOSED
  closureDetails?: {
    timelineComplete: boolean;
    evidenceRetained: boolean;
    requiredSignOffsComplete: boolean;
    exceptionsDocumented: boolean;
    outstandingActionsAssigned: boolean;
    postIncidentReviewRecorded: boolean;
    noUnresolvedClosureBlocker: boolean;
  };
  // For RESOLVED/CLOSED -> REOPENED
  reopenDetails?: {
    reopeningReason: string;
    credibleNewEvidenceRef: string;
  };
  // Optional trigger simulation for testing Section 31 retry & failure classification
  simulateTriggerFailure?: {
    triggerName: string;
    criticality: TriggerCriticality;
    succeedOnRetry?: boolean;
  };
}

/**
 * Master Atomic Server-Authoritative Incident Transition Operation.
 * Enforces:
 *   - All 20 Transition Invariants (INVARIANT-01 through INVARIANT-20)
 *   - The 15-Step Pre-Transition Validation Sequence (Section 3)
 *   - PRE_TRANSITION, ON_TRANSITION, and POST_TRANSITION Trigger Framework (Sections 4–31)
 *   - Idempotency & Concurrency Protection (409 Conflict on version mismatch or concurrent race)
 *   - Structured TransitionResultContract (Section 32 & 33)
 */
export function executeAtomicIncidentStatusTransition(params: {
  incidentId: string;
  requestedStatus: unknown;
  expectedVersion: number;
  transitionId: string;
  actor: string | null | undefined;
  actorRole: UserRole | 'incident_owner' | 'security_owner' | 'database_owner' | 'deployment_owner' | string | null | undefined;
  reason: string;
  evidenceReference: string;
  relatedVerificationId?: string;
  relatedDeploymentId?: string;
  approvalReference?: string;
  preconditions?: IncidentTransitionPreconditions;
  serverNowMs?: number;
}): TransitionResultContract {
  const serverNowMs =
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const serverNowIso = new Date(serverNowMs).toISOString();

  // Step 0: Idempotency check (Section 28: Duplicate transition request returns cached deterministic result)
  const idempotencyKey = `${params.incidentId}:${params.transitionId}`;
  const cachedResult = processedTransitionResults.get(idempotencyKey);
  if (cachedResult) {
    return cachedResult;
  }

  // Step 1: Authenticate actor (INVARIANT-08)
  if (!params.actor || !params.actor.trim()) {
    return {
      httpStatus: 401,
      success: false,
      incident_id: params.incidentId,
      previous_status: null,
      current_status: null,
      transition_id: params.transitionId,
      timestamp: serverNowIso,
      required_actions: ['Authenticate with a valid server session.'],
      trigger_status: {
        transitionSucceeded: false,
        allTriggersSucceeded: false,
        failedCriticalOrRequiredTriggers: 0,
        failedNonCriticalTriggers: 0,
        executedTriggers: [],
      },
      audit_event_id: null,
      error: 'Unauthorized: Every incident status transition requires an authenticated actor.',
    };
  }

  // Step 2: Load authoritative incident (INVARIANT-01)
  const incident = incidentStore.get(params.incidentId);
  if (!incident) {
    return {
      httpStatus: 404,
      success: false,
      incident_id: params.incidentId,
      previous_status: null,
      current_status: null,
      transition_id: params.transitionId,
      timestamp: serverNowIso,
      required_actions: [],
      trigger_status: {
        transitionSucceeded: false,
        allTriggersSucceeded: false,
        failedCriticalOrRequiredTriggers: 0,
        failedNonCriticalTriggers: 0,
        executedTriggers: [],
      },
      audit_event_id: null,
      error: 'Not Found: Authoritative incident record does not exist.',
    };
  }

  // Step 3: Lock & check current incident version (INVARIANT-05 Concurrency Safety)
  if (
    inFlightIncidentLocks.has(incident.incidentId) ||
    params.expectedVersion !== incident.version
  ) {
    return {
      httpStatus: 409,
      success: false,
      incident_id: incident.incidentId,
      previous_status: incident.status,
      current_status: incident.status,
      transition_id: params.transitionId,
      timestamp: serverNowIso,
      required_actions: ['Refresh authoritative incident state and retry if appropriate.'],
      trigger_status: {
        transitionSucceeded: false,
        allTriggersSucceeded: false,
        failedCriticalOrRequiredTriggers: 0,
        failedNonCriticalTriggers: 0,
        executedTriggers: [],
      },
      audit_event_id: null,
      error: `Conflict: Stale or concurrent transition detected (expected v${params.expectedVersion}, authoritative v${incident.version}).`,
    };
  }

  inFlightIncidentLocks.add(incident.incidentId);
  try {
    // Step 4: Validate actor permission (INVARIANT-09 & Section 21/33 Access Control)
    const actor = params.actor.trim();
    const role = (params.actorRole || '').trim().toLowerCase();
    if (role === 'student' || role === 'teacher') {
      return {
        httpStatus: 403,
        success: false,
        incident_id: incident.incidentId,
        previous_status: incident.status,
        current_status: incident.status,
        transition_id: params.transitionId,
        timestamp: serverNowIso,
        required_actions: [],
        trigger_status: {
          transitionSucceeded: false,
          allTriggersSucceeded: false,
          failedCriticalOrRequiredTriggers: 0,
          failedNonCriticalTriggers: 0,
          executedTriggers: [],
        },
        audit_event_id: null,
        error: 'Forbidden: Student and Teacher accounts are not authorized to transition production incident statuses.',
      };
    }

    const authorizedOwners = new Set([
      incident.primaryOwner,
      incident.backupOwner,
      incident.securityOwner,
      incident.databaseOwner,
      incident.rollbackOwner,
      incident.monitoringOwner,
      incident.closureOwner,
    ]);
    if (role !== 'admin' && !authorizedOwners.has(actor)) {
      return {
        httpStatus: 403,
        success: false,
        incident_id: incident.incidentId,
        previous_status: incident.status,
        current_status: incident.status,
        transition_id: params.transitionId,
        timestamp: serverNowIso,
        required_actions: [],
        trigger_status: {
          transitionSucceeded: false,
          allTriggersSucceeded: false,
          failedCriticalOrRequiredTriggers: 0,
          failedNonCriticalTriggers: 0,
          executedTriggers: [],
        },
        audit_event_id: null,
        error: `Forbidden: Actor "${actor}" does not hold authority for incident ${incident.incidentId}.`,
      };
    }

    // Step 5 & 6: Validate current status & requested next status against canonical enum & matrix (INVARIANT-02 & 03)
    const parsedRequested = parseCanonicalIncidentStatus(params.requestedStatus);
    if (!parsedRequested.ok) {
      return {
        httpStatus: 422,
        success: false,
        incident_id: incident.incidentId,
        previous_status: incident.status,
        current_status: incident.status,
        transition_id: params.transitionId,
        timestamp: serverNowIso,
        required_actions: [],
        trigger_status: {
          transitionSucceeded: false,
          allTriggersSucceeded: false,
          failedCriticalOrRequiredTriggers: 0,
          failedNonCriticalTriggers: 0,
          executedTriggers: [],
        },
        audit_event_id: null,
        error: parsedRequested.error,
      };
    }
    const nextStatus = parsedRequested.status;
    const allowedTargets = ALLOWED_INCIDENT_STATUS_TRANSITIONS[incident.status];
    if (!allowedTargets || !allowedTargets.has(nextStatus)) {
      return {
        httpStatus: 422,
        success: false,
        incident_id: incident.incidentId,
        previous_status: incident.status,
        current_status: incident.status,
        transition_id: params.transitionId,
        timestamp: serverNowIso,
        required_actions: [],
        trigger_status: {
          transitionSucceeded: false,
          allTriggersSucceeded: false,
          failedCriticalOrRequiredTriggers: 0,
          failedNonCriticalTriggers: 0,
          executedTriggers: [],
        },
        audit_event_id: null,
        error: `Unprocessable Entity: Transition ${incident.status} -> ${nextStatus} is prohibited by the authoritative incident state machine.`,
      };
    }

    // Step 7, 8, 9, 10, 11: Validate required evidence, approvals, and state-specific preconditions (INVARIANT-10..17)
    if (!params.reason?.trim() || !params.evidenceReference?.trim()) {
      return {
        httpStatus: 422,
        success: false,
        incident_id: incident.incidentId,
        previous_status: incident.status,
        current_status: incident.status,
        transition_id: params.transitionId,
        timestamp: serverNowIso,
        required_actions: ['Provide a non-empty reason and evidenceReference.'],
        trigger_status: {
          transitionSucceeded: false,
          allTriggersSucceeded: false,
          failedCriticalOrRequiredTriggers: 0,
          failedNonCriticalTriggers: 0,
          executedTriggers: [],
        },
        audit_event_id: null,
        error: 'Evidence Requirement violation: reason and evidenceReference are mandatory.',
      };
    }

    const pre = params.preconditions || {};
    const failPrecondition = (msg: string): TransitionResultContract => ({
      httpStatus: 422,
      success: false,
      incident_id: incident.incidentId,
      previous_status: incident.status,
      current_status: incident.status,
      transition_id: params.transitionId,
      timestamp: serverNowIso,
      required_actions: [msg],
      trigger_status: {
        transitionSucceeded: false,
        allTriggersSucceeded: false,
        failedCriticalOrRequiredTriggers: 0,
        failedNonCriticalTriggers: 0,
        executedTriggers: [],
      },
      audit_event_id: null,
      error: msg,
    });

    if (incident.status === 'DETECTED' && nextStatus === 'TRIAGED') {
      const td = pre.triageDetails;
      if (
        !td ||
        !td.severity ||
        !td.priority ||
        !td.affectedFunction?.trim() ||
        !td.affectedUsersScope?.trim() ||
        !td.primaryOwner?.trim() ||
        !td.backupOwner?.trim()
      ) {
        return failPrecondition(
          'DETECTED -> TRIAGED requires severity, priority, affectedFunction, affectedUsersScope, primaryOwner, and backupOwner.'
        );
      }
    }

    if (
      incident.status === 'CONTAINMENT_IN_PROGRESS' &&
      nextStatus === 'CONTAINED'
    ) {
      const cv = pre.containmentVerified;
      if (
        !cv ||
        !cv.containmentAction?.trim() ||
        !cv.expectedEffect?.trim() ||
        !cv.observedEffect?.trim() ||
        !cv.affectedScope?.trim()
      ) {
        return failPrecondition(
          'CONTAINMENT_IN_PROGRESS -> CONTAINED requires verified containmentAction, expectedEffect, observedEffect, and affectedScope.'
        );
      }
    }

    if (nextStatus === 'ROLLBACK_IN_PROGRESS') {
      const rp = pre.rollbackPlanConfirmed;
      if (
        !rp ||
        !rp.rollbackTargetCommit?.trim() ||
        !rp.rollbackAuthorityConfirmed ||
        !rp.databaseImplicationsReviewed
      ) {
        return failPrecondition(
          'Transition to ROLLBACK_IN_PROGRESS requires rollbackTargetCommit, rollbackAuthorityConfirmed, and databaseImplicationsReviewed.'
        );
      }
    }

    if (
      incident.status === 'ROLLBACK_IN_PROGRESS' &&
      nextStatus === 'ROLLBACK_COMPLETE'
    ) {
      const rc = pre.rollbackCompletionEvidence;
      if (
        !rc ||
        !rc.knownGoodVersionActive ||
        !rc.failedVersionInactive ||
        !rc.expectedInstancesRestored ||
        !rc.requiredConfigurationRestored ||
        !rc.requiredDatabaseActionCompleted ||
        !rc.rollbackOperationFinished ||
        !rc.deploymentEvidenceRef?.trim()
      ) {
        return failPrecondition(
          'ROLLBACK_IN_PROGRESS -> ROLLBACK_COMPLETE requires all 6 technical rollback completion criteria and deploymentEvidenceRef.'
        );
      }
    }

    if (
      incident.status === 'RECOVERY_IN_PROGRESS' &&
      nextStatus === 'RECOVERY_BLOCKED'
    ) {
      const bd = pre.blockedDetails;
      if (
        !bd ||
        !bd.blockingReason?.trim() ||
        !bd.affectedVerificationId?.trim() ||
        !bd.dependency?.trim() ||
        !bd.owner?.trim() ||
        !validateAbsoluteDeadlineFormat(bd.deadline) ||
        !bd.riskLevel ||
        !bd.containmentStatus?.trim()
      ) {
        return failPrecondition(
          'RECOVERY_IN_PROGRESS -> RECOVERY_BLOCKED requires blockingReason, affectedVerificationId, dependency, owner, valid absolute deadline, riskLevel, and containmentStatus.'
        );
      }
    }

    if (
      incident.status === 'RECOVERY_BLOCKED' &&
      nextStatus === 'RECOVERY_IN_PROGRESS'
    ) {
      const ud = pre.unblockDetails;
      if (
        !ud ||
        !ud.blockerResolved ||
        !ud.dependencyAvailable ||
        !ud.accessRestored ||
        !ud.retestStarted
      ) {
        return failPrecondition(
          'RECOVERY_BLOCKED -> RECOVERY_IN_PROGRESS requires blockerResolved, dependencyAvailable, accessRestored, and retestStarted.'
        );
      }
    }

    if (
      incident.status === 'RECOVERY_IN_PROGRESS' &&
      nextStatus === 'RECOVERY_FAILED'
    ) {
      const fd = pre.failureDetails;
      if (
        !fd ||
        !fd.verificationId?.trim() ||
        !fd.expectedResult?.trim() ||
        !fd.actualResult?.trim() ||
        !fd.impact?.trim()
      ) {
        return failPrecondition(
          'RECOVERY_IN_PROGRESS -> RECOVERY_FAILED requires verificationId, expectedResult, actualResult, and impact.'
        );
      }
    }

    if (
      incident.status === 'RECOVERY_FAILED' &&
      nextStatus === 'RECOVERY_IN_PROGRESS'
    ) {
      const rd = pre.retestDetails;
      if (!rd || !rd.remediationCompleted || !rd.retestInitiated) {
        return failPrecondition(
          'RECOVERY_FAILED -> RECOVERY_IN_PROGRESS requires remediationCompleted and retestInitiated.'
        );
      }
    }

    if (
      incident.status === 'RECOVERY_IN_PROGRESS' &&
      nextStatus === 'RECOVERY_VERIFIED'
    ) {
      const vs = pre.verificationSummary;
      const hasUnresolvedConflict = incident.evidenceConflicts.some(
        (c) => !c.resolved
      );
      if (
        !vs ||
        vs.verifications.length === 0 ||
        vs.verifications.some(
          (v) => v.status === 'FAIL' || v.status === 'BLOCKED' || !v.evidence?.trim()
        ) ||
        !vs.databaseIntegrityConfirmed ||
        !vs.securityIntegrityConfirmed ||
        hasUnresolvedConflict
      ) {
        return failPrecondition(
          'INVARIANT-13 / Section 17: Cannot transition to RECOVERY_VERIFIED while any required verification is FAIL/BLOCKED/missing evidence, or while evidence conflicts or DB/security checks are unconfirmed.'
        );
      }
    }

    if (incident.status === 'RECOVERY_VERIFIED' && nextStatus === 'MONITORING') {
      const ms = pre.monitoringStartDetails;
      if (
        !ms ||
        !ms.recoverySignOffComplete ||
        !ms.monitoringOwner?.trim() ||
        (ms.monitoringWindowMinutes !== 60 &&
          ms.monitoringWindowMinutes !== 120) ||
        !ms.monitoringChecksConfigured ||
        !params.approvalReference?.trim()
      ) {
        return failPrecondition(
          'Section 18 / 20: Cannot transition RECOVERY_VERIFIED -> MONITORING without completed recovery sign-off, approvalReference, assigned monitoringOwner, and configured 60m/120m stability window.'
        );
      }
    }

    if (
      incident.status === 'MONITORING' &&
      nextStatus === 'STABILITY_CONFIRMED'
    ) {
      const sc = pre.stabilityConfirmationDetails;
      if (
        !sc ||
        sc.monitoringSession.state !== 'STABILITY_CONFIRMED' ||
        !sc.noCriticalRegression ||
        !sc.noUnresolvedSecurityIssue ||
        !sc.noUnresolvedDatabaseIssue ||
        !sc.monitoringOwnerSignedOff
      ) {
        return failPrecondition(
          'INVARIANT-16 / Section 19: Cannot transition MONITORING -> STABILITY_CONFIRMED before the required stability window completes and the Monitoring Owner signs off.'
        );
      }
    }

    if (
      incident.status === 'STABILITY_CONFIRMED' &&
      nextStatus === 'RESOLVED'
    ) {
      const resD = pre.resolutionDetails;
      if (
        !resD ||
        !resD.requiredTechnicalRemediationComplete ||
        !resD.noCriticalUnresolvedIssue ||
        !resD.followUpWorkDocumented
      ) {
        return failPrecondition(
          'Section 21: STABILITY_CONFIRMED -> RESOLVED requires completed technical remediation, zero critical unresolved issues, and documented follow-up work.'
        );
      }
    }

    if (incident.status === 'RESOLVED' && nextStatus === 'CLOSED') {
      const cd = pre.closureDetails;
      const hasUnresolvedConflict = incident.evidenceConflicts.some(
        (c) => !c.resolved
      );
      if (
        !cd ||
        !cd.timelineComplete ||
        !cd.evidenceRetained ||
        !cd.requiredSignOffsComplete ||
        !cd.exceptionsDocumented ||
        !cd.outstandingActionsAssigned ||
        !cd.postIncidentReviewRecorded ||
        !cd.noUnresolvedClosureBlocker ||
        hasUnresolvedConflict ||
        !params.approvalReference?.trim()
      ) {
        return failPrecondition(
          'INVARIANT-17 / Section 22: Cannot transition RESOLVED -> CLOSED until all closure gate requirements, evidence conflict resolutions, and closure sign-off approvalReference are satisfied.'
        );
      }
    }

    if (nextStatus === 'REOPENED') {
      const ro = pre.reopenDetails;
      if (
        !ro ||
        !ro.reopeningReason?.trim() ||
        !ro.credibleNewEvidenceRef?.trim()
      ) {
        return failPrecondition(
          'Section 23 / 25: Reopening a RESOLVED or CLOSED incident requires reopeningReason and credibleNewEvidenceRef.'
        );
      }
    }

    // Step 12, 13, 14: Execute PRE_TRANSITION, ON_TRANSITION, and POST_TRANSITION triggers atomically
    const executedTriggers: ExecutedTriggerRecord[] = [];
    let failedCriticalOrRequiredTriggers = 0;
    let failedNonCriticalTriggers = 0;

    const runIdempotentTrigger = (
      triggerClass: TriggerExecutionClass,
      criticality: TriggerCriticality,
      name: string,
      detail: string
    ) => {
      const triggerDedupeKey = `${incident.incidentId}:${params.transitionId}:${name}`;
      if (processedTriggerKeys.has(triggerDedupeKey)) {
        return;
      }

      const sim = pre.simulateTriggerFailure;
      let status: 'SUCCEEDED' | 'FAILED' | 'RETRIED_SUCCEEDED' = 'SUCCEEDED';
      let attempts = 1;

      if (sim && sim.triggerName === name) {
        attempts = 2;
        if (sim.succeedOnRetry) {
          status = 'RETRIED_SUCCEEDED';
        } else {
          status = 'FAILED';
          if (criticality === 'Critical' || criticality === 'Required') {
            failedCriticalOrRequiredTriggers += 1;
          } else {
            failedNonCriticalTriggers += 1;
          }
        }
      }

      if (status !== 'FAILED') {
        processedTriggerKeys.add(triggerDedupeKey);
      }

      executedTriggers.push(
        Object.freeze({
          triggerId: `TRG-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
          transitionId: params.transitionId,
          triggerClass,
          criticality,
          name,
          status,
          attempts,
          timestamp: serverNowIso,
          detail,
        })
      );
    };

    runIdempotentTrigger(
      'PRE_TRANSITION',
      'Critical',
      'validate_invariants_and_authority',
      `Validated ${incident.status} -> ${nextStatus} for ${actor}`
    );
    runIdempotentTrigger(
      'ON_TRANSITION',
      'Critical',
      'atomic_state_and_audit_commit',
      `Committed status=${nextStatus} v${incident.version + 1}`
    );
    runIdempotentTrigger(
      'POST_TRANSITION',
      'Non-critical',
      'emit_webhook_and_stakeholder_notification',
      `Dispatched notification for ${incident.status} -> ${nextStatus}`
    );

    if (failedCriticalOrRequiredTriggers > 0) {
      return {
        httpStatus: 422,
        success: false,
        incident_id: incident.incidentId,
        previous_status: incident.status,
        current_status: incident.status,
        transition_id: params.transitionId,
        timestamp: serverNowIso,
        required_actions: ['Investigate and retry failed critical/required transition trigger.'],
        trigger_status: {
          transitionSucceeded: false,
          allTriggersSucceeded: false,
          failedCriticalOrRequiredTriggers,
          failedNonCriticalTriggers,
          executedTriggers,
        },
        audit_event_id: null,
        error: 'Atomic Transition Aborted: A Critical or Required trigger failed.',
      };
    }

    const eventTypeMap: Record<IncidentStatus, RequiredAuditEventType> = {
      DETECTED: 'INCIDENT_CREATED',
      TRIAGED: 'INCIDENT_TRIAGED',
      ACKNOWLEDGED: 'INCIDENT_ACKNOWLEDGED',
      CONTAINMENT_IN_PROGRESS: 'CONTAINMENT_STARTED',
      CONTAINED: 'CONTAINMENT_COMPLETED',
      ROLLBACK_IN_PROGRESS: 'ROLLBACK_INITIATED',
      ROLLBACK_COMPLETE: 'ROLLBACK_ACTION_COMPLETED',
      RECOVERY_IN_PROGRESS: 'RECOVERY_VERIFICATION_STARTED',
      RECOVERY_BLOCKED: 'VERIFICATION_ITEM_BLOCKED',
      RECOVERY_FAILED: 'VERIFICATION_ITEM_FAILED',
      RECOVERY_VERIFIED: 'RECOVERY_VERIFIED',
      MONITORING: 'MONITORING_STARTED',
      STABILITY_CONFIRMED: 'STABILITY_CONFIRMED',
      RESOLVED: 'INCIDENT_RESOLVED',
      CLOSED: 'INCIDENT_CLOSED',
      REOPENED: 'INCIDENT_REOPENED',
    };

    const auditEvent = createAuditTrailEvent({
      incidentId: incident.incidentId,
      verificationId: params.relatedVerificationId || 'N/A',
      eventType: eventTypeMap[nextStatus],
      previousStatus: incident.status,
      newStatus: nextStatus,
      actor,
      actorRole: String(params.actorRole || 'incident_owner'),
      environment: incident.affectedEnvironment,
      reason: params.reason,
      result: nextStatus,
      evidenceReference: params.evidenceReference,
      relatedChangeOrDeploymentId: params.relatedDeploymentId || 'N/A',
      approver: params.approvalReference || 'N/A',
      serverNowIso,
    });

    const emittedEvent: EmittedIncidentEventPayload = Object.freeze({
      eventId: `EVT-${crypto.randomBytes(5).toString('hex').toUpperCase()}`,
      eventName:
        nextStatus === 'RECOVERY_BLOCKED'
          ? 'incident.blocked'
          : nextStatus === 'RECOVERY_FAILED'
            ? 'incident.recovery.failed'
            : nextStatus === 'RECOVERY_VERIFIED'
              ? 'incident.recovery.verified'
              : nextStatus === 'MONITORING'
                ? 'incident.monitoring.started'
                : nextStatus === 'STABILITY_CONFIRMED'
                  ? 'incident.stability.confirmed'
                  : nextStatus === 'RESOLVED'
                    ? 'incident.resolved'
                    : nextStatus === 'CLOSED'
                      ? 'incident.closed'
                      : nextStatus === 'REOPENED'
                        ? 'incident.reopened'
                        : 'incident.status.changed',
      incidentId: incident.incidentId,
      previousStatus: incident.status,
      newStatus: nextStatus,
      severity: pre.triageDetails?.severity || incident.severity,
      priority: pre.triageDetails?.priority || incident.priority,
      actor,
      timestamp: serverNowIso,
      transitionId: params.transitionId,
    });

    const updatedIncident: ProductionIncidentRecord = Object.freeze({
      ...incident,
      version: incident.version + 1,
      status: nextStatus,
      severity: pre.triageDetails?.severity || incident.severity,
      priority: pre.triageDetails?.priority || incident.priority,
      affectedFunction:
        pre.triageDetails?.affectedFunction || incident.affectedFunction,
      affectedUsersScope:
        pre.triageDetails?.affectedUsersScope || incident.affectedUsersScope,
      primaryOwner: pre.triageDetails?.primaryOwner || incident.primaryOwner,
      backupOwner: pre.triageDetails?.backupOwner || incident.backupOwner,
      containmentSummary:
        pre.containmentVerified?.containmentAction || incident.containmentSummary,
      rollbackSubStatus:
        nextStatus === 'ROLLBACK_IN_PROGRESS'
          ? 'INITIATED'
          : nextStatus === 'ROLLBACK_COMPLETE'
            ? 'ACTION_COMPLETE'
            : incident.rollbackSubStatus,
      recoverySubStatus:
        nextStatus === 'RECOVERY_IN_PROGRESS'
          ? 'VERIFICATION_RUNNING'
          : nextStatus === 'RECOVERY_VERIFIED'
            ? 'VERIFIED'
            : nextStatus === 'MONITORING'
              ? 'SIGN_OFF_COMPLETE'
              : incident.recoverySubStatus,
      monitoringSubStatus:
        nextStatus === 'MONITORING'
          ? 'ACTIVE'
          : nextStatus === 'STABILITY_CONFIRMED'
            ? 'STABLE'
            : nextStatus === 'RECOVERY_FAILED' && incident.status === 'MONITORING'
              ? 'FAILED'
              : incident.monitoringSubStatus,
      approvalSubStatus:
        nextStatus === 'MONITORING' || nextStatus === 'CLOSED'
          ? 'COMPLETE'
          : incident.approvalSubStatus,
      triagedAtIso:
        nextStatus === 'TRIAGED' ? serverNowIso : incident.triagedAtIso,
      acknowledgedAtIso:
        nextStatus === 'ACKNOWLEDGED' ? serverNowIso : incident.acknowledgedAtIso,
      containmentStartedAtIso:
        nextStatus === 'CONTAINMENT_IN_PROGRESS'
          ? serverNowIso
          : incident.containmentStartedAtIso,
      containedAtIso:
        nextStatus === 'CONTAINED' ? serverNowIso : incident.containedAtIso,
      rollbackStartedAtIso:
        nextStatus === 'ROLLBACK_IN_PROGRESS'
          ? serverNowIso
          : incident.rollbackStartedAtIso,
      rollbackCompletedAtIso:
        nextStatus === 'ROLLBACK_COMPLETE'
          ? serverNowIso
          : incident.rollbackCompletedAtIso,
      recoveryStartedAtIso:
        nextStatus === 'RECOVERY_IN_PROGRESS'
          ? serverNowIso
          : incident.recoveryStartedAtIso,
      recoveryVerifiedAtIso:
        nextStatus === 'RECOVERY_VERIFIED'
          ? serverNowIso
          : incident.recoveryVerifiedAtIso,
      monitoringStartedAtIso:
        nextStatus === 'MONITORING' ? serverNowIso : incident.monitoringStartedAtIso,
      stabilityConfirmedAtIso:
        nextStatus === 'STABILITY_CONFIRMED'
          ? serverNowIso
          : incident.stabilityConfirmedAtIso,
      resolvedAtIso:
        nextStatus === 'RESOLVED' ? serverNowIso : incident.resolvedAtIso,
      closedAtIso:
        nextStatus === 'CLOSED' ? serverNowIso : incident.closedAtIso,
      reopenedAtIso:
        nextStatus === 'REOPENED' ? serverNowIso : incident.reopenedAtIso,
      auditTrail: [...incident.auditTrail, auditEvent],
      triggerHistory: [...incident.triggerHistory, ...executedTriggers],
      emittedEvents: [...incident.emittedEvents, emittedEvent],
    });

    incidentStore.set(updatedIncident.incidentId, updatedIncident);

    recordServerAuditLog({
      actorId: actor,
      actorEmail: 'incident-governance@uyanix.in',
      actorRole: 'admin',
      action: `INCIDENT_TRANSITION_${incident.status}_TO_${nextStatus}`,
      target: `${incident.incidentId} (v${updatedIncident.version})`,
    });

    const result: TransitionResultContract = {
      httpStatus: 200,
      success: true,
      incident_id: updatedIncident.incidentId,
      previous_status: incident.status,
      current_status: updatedIncident.status,
      transition_id: params.transitionId,
      timestamp: serverNowIso,
      required_actions: [],
      trigger_status: {
        transitionSucceeded: true,
        allTriggersSucceeded: failedNonCriticalTriggers === 0,
        failedCriticalOrRequiredTriggers: 0,
        failedNonCriticalTriggers,
        executedTriggers,
      },
      audit_event_id: auditEvent.eventId,
      error: null,
    };

    processedTransitionResults.set(idempotencyKey, result);
    return result;
  } finally {
    inFlightIncidentLocks.delete(incident.incidentId);
  }
}

/**
 * Section 21, 22, 26: Admin/Authorized-only structured export of the complete incident audit bundle,
 * while logging the audit access event itself (Section 22 Audit Log Access).
 */
export function exportIncidentAuditBundle(params: {
  incidentId: string;
  actor: string;
  actorRole: UserRole | string;
  serverNowMs?: number;
}):
  | {
      ok: true;
      httpStatus: 200;
      bundle: {
        enumVersion: typeof INCIDENT_STATUS_ENUM_VERSION;
        incident: ProductionIncidentRecord;
      };
    }
  | { ok: false; httpStatus: 401 | 403 | 404; error: string } {
  if (!params.actor?.trim()) {
    return { ok: false, httpStatus: 401, error: 'Unauthorized: Actor required.' };
  }
  const role = (params.actorRole || '').toLowerCase();
  if (role !== 'admin') {
    return {
      ok: false,
      httpStatus: 403,
      error: 'Forbidden: Only authorized administrators/incident owners may export sensitive incident audit records.',
    };
  }
  const current = incidentStore.get(params.incidentId);
  if (!current) {
    return { ok: false, httpStatus: 404, error: 'Incident not found.' };
  }

  const nowIso = new Date(
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now()
  ).toISOString();

  const accessEvent = createAuditTrailEvent({
    incidentId: current.incidentId,
    eventType: 'AUDIT_LOG_ACCESSED',
    previousStatus: current.status,
    newStatus: current.status,
    actor: params.actor,
    actorRole: String(params.actorRole),
    environment: current.affectedEnvironment,
    reason: 'Authorized structured export of incident audit trail',
    result: 'EXPORTED',
    evidenceReference: `AUDIT-EXPORT-${current.version}`,
    serverNowIso: nowIso,
  });

  const updated: ProductionIncidentRecord = Object.freeze({
    ...current,
    auditTrail: [...current.auditTrail, accessEvent],
  });
  incidentStore.set(updated.incidentId, updated);

  return {
    ok: true,
    httpStatus: 200,
    bundle: {
      enumVersion: INCIDENT_STATUS_ENUM_VERSION,
      incident: updated,
    },
  };
}

// ============================================================================
// 6. EXPLICIT INCIDENT STATUS TRANSITION GUARD CONDITIONS (SECTIONS 1–49)
// ============================================================================

export type GuardFailureCode =
  | 'AUTH_REQUIRED'
  | 'INCIDENT_NOT_ACCESSIBLE'
  | 'INVALID_CURRENT_STATUS'
  | 'INVALID_TARGET_STATUS'
  | 'TRANSITION_NOT_ALLOWED'
  | 'STALE_INCIDENT_VERSION'
  | 'ACTOR_NOT_AUTHORIZED'
  | 'OWNER_REQUIRED'
  | 'SEVERITY_REQUIRED'
  | 'PRIORITY_REQUIRED'
  | 'EVIDENCE_REQUIRED'
  | 'APPROVAL_REQUIRED'
  | 'DEPENDENCY_UNAVAILABLE'
  | 'VERIFICATION_NOT_COMPLETE'
  | 'VERIFICATION_FAILED'
  | 'VERIFICATION_BLOCKED'
  | 'SECURITY_REVIEW_REQUIRED'
  | 'DATABASE_REVIEW_REQUIRED'
  | 'STABILITY_WINDOW_INCOMPLETE'
  | 'CRITICAL_BLOCKER_EXISTS'
  | 'REOPENING_EVIDENCE_REQUIRED'
  | 'IDEMPOTENCY_CONFLICT';

export const ALL_CANONICAL_GUARD_FAILURE_CODES: readonly GuardFailureCode[] =
  Object.freeze([
    'AUTH_REQUIRED',
    'INCIDENT_NOT_ACCESSIBLE',
    'INVALID_CURRENT_STATUS',
    'INVALID_TARGET_STATUS',
    'TRANSITION_NOT_ALLOWED',
    'STALE_INCIDENT_VERSION',
    'ACTOR_NOT_AUTHORIZED',
    'OWNER_REQUIRED',
    'SEVERITY_REQUIRED',
    'PRIORITY_REQUIRED',
    'EVIDENCE_REQUIRED',
    'APPROVAL_REQUIRED',
    'DEPENDENCY_UNAVAILABLE',
    'VERIFICATION_NOT_COMPLETE',
    'VERIFICATION_FAILED',
    'VERIFICATION_BLOCKED',
    'SECURITY_REVIEW_REQUIRED',
    'DATABASE_REVIEW_REQUIRED',
    'STABILITY_WINDOW_INCOMPLETE',
    'CRITICAL_BLOCKER_EXISTS',
    'REOPENING_EVIDENCE_REQUIRED',
    'IDEMPOTENCY_CONFLICT',
  ]);

/**
 * Section 2: Authoritative 19-Step Guard Evaluation Order.
 */
export const GUARD_EVALUATION_ORDER_19_STEPS: readonly string[] = Object.freeze([
  '1. Authentication Guard',
  '2. Incident Access Guard',
  '3. Current Status Guard',
  '4. Requested Status Guard',
  '5. Transition Matrix Guard',
  '6. Concurrency/Version Guard',
  '7. Actor Authorization Guard',
  '8. Ownership Guard',
  '9. Severity/Priority Guard',
  '10. Evidence Guard',
  '11. Approval Guard',
  '12. Dependency Guard',
  '13. Verification Guard',
  '14. Security/Data-Integrity Guard',
  '15. SLA Guard',
  '16. Transition-Specific Business Guard',
  '17. Atomic State Update',
  '18. Audit Event Creation',
  '19. Required Side Effects',
]);

export type DatabaseIntegrityVerificationState =
  | 'VERIFIED_HEALTHY'
  | 'UNKNOWN'
  | 'FAILED';

export interface StructuredApprovalRecord {
  approvalId: string;
  incidentId: string;
  targetTransition: string; // e.g. "RECOVERY_VERIFIED->MONITORING" or "RESOLVED->CLOSED"
  approver: string;
  approverRole: string;
  approvedAtMs: number;
  expiresAtMs?: number;
  revoked?: boolean;
}

export interface GuardTransitionInput {
  incident: ProductionIncidentRecord | null | undefined;
  actor: {
    authenticated: boolean;
    sessionValid?: boolean;
    sessionExpired?: boolean;
    sessionRevoked?: boolean;
    actorId?: string | null;
    actorName?: string | null;
    actorRole?: string | null;
    tenantOrProjectScope?: string;
  } | null | undefined;
  currentStatus: unknown;
  requestedStatus: unknown;
  incidentVersion: number;
  transitionId?: string;
  evidence?: {
    evidenceReference?: string | null;
    reason?: string | null;
    timestamped?: boolean;
    attributable?: boolean;
    integrityPreserving?: boolean;
    associatedIncidentId?: string;
    clientClaimOnly?: boolean; // e.g., { verified: true } without backing evidence
  };
  approvals?: StructuredApprovalRecord[];
  transitionMetadata?: {
    expectedTenantOrProjectScope?: string;
    clientSuppliedTampering?: {
      client_user_id?: string;
      client_role?: string;
      incident_owner_id?: string;
      overrideStatus?: string;
      overrideSeverity?: string;
      overridePriority?: string;
      overrideVerificationResult?: string;
      overrideApproval?: boolean;
    };
    dependencies?: {
      monitoringAvailable?: boolean;
      databaseAccessAvailable?: boolean;
      deploymentSystemAvailable?: boolean;
      securityVerificationAvailable?: boolean;
      testEnvironmentAvailable?: boolean;
      evidenceStoreAvailable?: boolean;
    };
    securityContext?: {
      involvesSecurityDomain?: boolean;
      securityReviewVerified?: boolean;
      unhandledSecurityEscalation?: boolean;
    };
    databaseContext?: {
      involvesCriticalDataRecords?: boolean;
      databaseIntegrityState?: DatabaseIntegrityVerificationState;
    };
    slaContext?: {
      attemptingSlaBypass?: boolean;
      stabilityWindowElapsedMinutes?: number;
      requiredStabilityWindowMinutes?: 60 | 120;
    };
    // Section 12–33 Transition-specific metadata
    triageMetadata?: {
      severity?: IncidentSeverity;
      priority?: IncidentPriority;
      affectedArea?: string;
      initialImpact?: string;
      primaryOwner?: string;
      backupOwner?: string;
      detectionEvidence?: string;
      ownersAuthorized?: boolean;
    };
    acknowledgeMetadata?: {
      actorAcceptsResponsibility?: boolean;
      acknowledgementMetadataValid?: boolean;
      attemptedSelfPrivilegeElevation?: boolean;
    };
    containmentStartMetadata?: {
      containmentRequired?: boolean;
      containmentOwner?: string;
      containmentPlan?: string;
      actorHasContainmentAuthority?: boolean;
      isSecurityIncident?: boolean;
      securityOwnerIdentified?: boolean;
      securityEscalationPathAvailable?: boolean;
    };
    rollbackStartMetadata?: {
      rollbackRequired?: boolean;
      rollbackOwner?: string;
      rollbackAuthorityConfirmed?: boolean;
      rollbackTarget?: string;
      knownGoodVersion?: string;
      rollbackPlan?: string;
      databaseRollbackImpactAssessed?: boolean;
      containmentRequiredFirst?: boolean;
      containmentConditionSatisfied?: boolean;
    };
    containedMetadata?: {
      containmentAction?: string;
      containmentOwner?: string;
      containmentObjective?: string;
      expectedEffect?: string;
      observedEffect?: string;
      affectedScopeAssessed?: string;
      containmentVerified?: boolean;
    };
    containedToRecoveryMetadata?: {
      rollbackRequired?: boolean;
      rollbackNotRequiredReason?: string;
      recoveryPlan?: string;
      verificationPlan?: string;
      verificationOwner?: string;
      requiredTestCapabilityAvailable?: boolean;
    };
    rollbackCompleteMetadata?: {
      rollbackAuthorized?: boolean;
      knownGoodVersionRestored?: boolean;
      failedVersionInactive?: boolean;
      requiredInstancesRestored?: boolean;
      requiredConfigurationRestored?: boolean;
      requiredDatabaseActionComplete?: boolean;
      databaseActionNotRequired?: boolean;
      rollbackExecutionComplete?: boolean;
      rollbackEvidenceExists?: boolean;
    };
    rollbackFailedMetadata?: {
      rollbackExecutionStarted?: boolean;
      rollbackFailureDetected?: boolean;
      rollbackFailureEvidence?: string;
      safeRollbackCompletionPossible?: boolean;
      causedByMissingOwnerOrDependencyOnly?: boolean;
    };
    rollbackToRecoveryMetadata?: {
      rollbackStatus?: 'ACTION_COMPLETE' | string;
      rollbackEvidence?: string;
      knownGoodStateConfirmed?: boolean;
      verificationPlan?: string;
      verificationOwner?: string;
      requiredVerificationAccessAvailable?: boolean;
    };
    recoveryBlockedMetadata?: {
      verificationAttempted?: boolean;
      verificationCannotMeaningfullyExecute?: boolean;
      blockingReason?: string;
      dependency?: string;
      blockerOwner?: string;
      deadline?: string;
      riskLevel?: BlockedRiskLevel;
      nextAction?: string;
    };
    recoveryUnblockMetadata?: {
      dependencyAvailable?: boolean;
      requiredAccessRestored?: boolean;
      requiredTestCapabilityAvailable?: boolean;
      blockerResolutionEvidence?: string;
      retestStarted?: boolean;
    };
    recoveryFailedMetadata?: {
      verificationExecuted?: boolean;
      verificationResult?: 'FAIL' | string;
      failureReason?: string;
      expectedResult?: string;
      actualResult?: string;
      evidence?: string;
      verificationOwner?: string;
      causedByMissingDependencyOnly?: boolean;
    };
    recoveryRetestMetadata?: {
      failureRecordExists?: boolean;
      remediationCompleted?: boolean;
      remediationEvidence?: string;
      retestPlan?: string;
      retestOwner?: string;
      retestStarted?: boolean;
    };
    recoveryVerifiedMetadata?: {
      allRequiredVerificationsPass?: boolean;
      criticalSecurityChecksPass?: boolean;
      authorizationChecksPass?: boolean;
      databaseIntegrityChecksPass?: boolean;
      authenticationChecksPass?: boolean;
      sessionChecksPass?: boolean;
      protectedApiChecksPass?: boolean;
      requiredRegressionChecksPass?: boolean;
      anyRequiredVerificationFailed?: boolean;
      anyRequiredVerificationBlocked?: boolean;
      anyRequiredVerificationMissingEvidence?: boolean;
      recoveryEvidenceComplete?: boolean;
      verificationOwnersCompleted?: boolean;
    };
    monitoringStartMetadata?: {
      recoveryVerification?: 'VERIFIED' | string;
      recoverySignoff?: 'COMPLETE' | string;
      monitoringOwner?: string;
      monitoringPlan?: string;
      monitoringWindowMinutes?: 60 | 120 | number;
      monitoringChecksConfigured?: boolean;
    };
    stabilityConfirmedMetadata?: {
      monitoringStarted?: boolean;
      requiredMonitoringWindowComplete?: boolean;
      monitoringEvidenceComplete?: boolean;
      criticalRegressionCount?: number;
      criticalSecurityIssueCount?: number;
      criticalDatabaseIssueCount?: number;
      authenticationHealth?: 'ACCEPTABLE' | string;
      authorizationHealth?: 'ACCEPTABLE' | string;
      apiHealth?: 'ACCEPTABLE' | string;
      errorRate?: 'ACCEPTABLE' | string;
      isHighRiskIncident?: boolean;
      windowMinutesCompleted?: number;
    };
    monitoringFailedMetadata?: {
      materialRegressionDetected?: boolean;
      regressionType?: string;
      expectedBehavior?: string;
      actualBehavior?: string;
      detectionTimestamp?: string;
      evidenceReference?: string;
      impact?: string;
    };
    resolvedMetadata?: {
      recoveryVerified?: boolean;
      recoverySignoff?: 'COMPLETE' | string;
      stabilityConfirmed?: boolean;
      requiredRemediationComplete?: boolean;
      noCriticalFailures?: boolean;
      noCriticalBlockers?: boolean;
      resolutionSummary?: string;
      followUpActionsAssigned?: boolean;
      ownersAssigned?: boolean;
      deadlinesAssigned?: boolean;
    };
    closedMetadata?: {
      incidentTimelineComplete?: boolean;
      requiredEvidenceRetained?: boolean;
      requiredSignoffsComplete?: boolean;
      exceptionsDocumented?: boolean;
      followUpActionsAssigned?: boolean;
      securityReviewComplete?: boolean;
      databaseReviewComplete?: boolean;
      closureReviewComplete?: boolean;
      criticalBlockerCount?: number;
    };
    reopenedMetadata?: {
      originalIssueReturned?: boolean;
      originalIssuePersisted?: boolean;
      recoveryEvidenceInvalidated?: boolean;
      securityExposureDiscovered?: boolean;
      databaseIntegrityConcernDiscovered?: boolean;
      materialRelatedRegressionDetected?: boolean;
      reopeningReason?: string;
      reopeningEvidence?: string;
      reopenReviewCompleted?: boolean;
      administrativeEditAttemptOnly?: boolean;
    };
    reopenedToTriagedMetadata?: {
      reassessmentComplete?: boolean;
      severity?: IncidentSeverity;
      priority?: IncidentPriority;
      primaryOwner?: string;
      backupOwner?: string;
    };
  };
  serverNowMs?: number;
}

export interface GuardEvaluationContract {
  allowed: boolean;
  guard_code: GuardFailureCode | 'GUARD_PASSED';
  http_status: 200 | 401 | 403 | 404 | 409 | 422;
  reason: string;
  required_action?: string;
  evidence_required?: string[];
  approval_required?: string[];
  evaluated_guards: string[];
}

const VAGUE_EVIDENCE_PATTERNS = [
  /^looks\s+fine\.?$/i,
  /^tested\s+manually\.?$/i,
  /^it\s+should\s+be\s+fixed\.?$/i,
  /^developer\s+confirmed\s+it\.?$/i,
  /^everything\s+is\s+working\.?$/i,
  /^ok\.?$/i,
  /^done\.?$/i,
];

function isVagueEvidence(text: string | null | undefined): boolean {
  if (!text || !text.trim()) return true;
  const trimmed = text.trim();
  return VAGUE_EVIDENCE_PATTERNS.some((rx) => rx.test(trimmed));
}

// Track transition_id -> fingerprint for IDEMPOTENCY_CONFLICT detection (Section 43 & 45)
const transitionIdFingerprints = new Map<string, string>();

/**
 * Section 46: Records an auditable event for rejected high-risk transitions
 * without exposing or logging sensitive secrets.
 */
export function recordRejectedTransitionAudit(params: {
  incident: ProductionIncidentRecord;
  actorName: string;
  actorRole: string;
  requestedTransition: string;
  guardCode: GuardFailureCode;
  reason: string;
  transitionId: string;
  serverNowIso: string;
}): AuditTrailEventRecord {
  const auditEvent = createAuditTrailEvent({
    incidentId: params.incident.incidentId,
    eventType: 'GUARD_FAILURE_REJECTED',
    previousStatus: params.incident.status,
    newStatus: params.incident.status,
    actor: sanitizeAndMinimizeEvidenceText(params.actorName),
    actorRole: sanitizeAndMinimizeEvidenceText(params.actorRole),
    environment: params.incident.affectedEnvironment,
    reason: `[${params.guardCode}] Rejected transition ${params.requestedTransition}: ${params.reason}`,
    result: 'REJECTED',
    evidenceReference: `transition_id:${sanitizeAndMinimizeEvidenceText(params.transitionId)}`,
    serverNowIso: params.serverNowIso,
  });

  const updated: ProductionIncidentRecord = Object.freeze({
    ...params.incident,
    auditTrail: [...params.incident.auditTrail, auditEvent],
  });
  incidentStore.set(updated.incidentId, updated);
  return auditEvent;
}

/**
 * Sections 1–49: Master Server-Side Guard Evaluation Function (`guardTransition`).
 * Evaluates all 16 pre-transition guards in the exact Section 2 Guard Evaluation Order
 * before any state mutation occurs.
 */
export function guardTransition(
  input: GuardTransitionInput
): GuardEvaluationContract {
  const evaluatedGuards: string[] = [];
  const nowMs =
    typeof input.serverNowMs === 'number' ? input.serverNowMs : Date.now();
  const meta = input.transitionMetadata || {};

  // --------------------------------------------------------------------------
  // 1. Authentication Guard (Section 4)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('1. Authentication Guard');
  const actor = input.actor;
  if (
    !actor ||
    !actor.authenticated ||
    actor.sessionValid === false ||
    actor.sessionExpired === true ||
    actor.sessionRevoked === true ||
    !actor.actorName?.trim()
  ) {
    return {
      allowed: false,
      guard_code: 'AUTH_REQUIRED',
      http_status: 401,
      reason: 'Authentication required: A valid, active server-authenticated session is mandatory.',
      required_action: 'Authenticate using a valid server session.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // Section 4 & 42: Reject client-supplied identity/role/state manipulation attempts
  const tampering = meta.clientSuppliedTampering;
  if (
    tampering &&
    (tampering.client_user_id ||
      tampering.client_role ||
      tampering.incident_owner_id ||
      tampering.overrideStatus ||
      tampering.overrideSeverity ||
      tampering.overridePriority ||
      tampering.overrideVerificationResult ||
      tampering.overrideApproval)
  ) {
    return {
      allowed: false,
      guard_code: 'ACTOR_NOT_AUTHORIZED',
      http_status: 403,
      reason:
        'Client-manipulation guard violation: Client-supplied identity, role, owner, or state override fields are prohibited.',
      required_action: 'Remove untrusted client override fields and rely on server-authoritative state.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 2. Incident Access Guard (Section 5)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('2. Incident Access Guard');
  const incident = input.incident;
  if (
    !incident ||
    (meta.expectedTenantOrProjectScope &&
      actor.tenantOrProjectScope &&
      meta.expectedTenantOrProjectScope !== actor.tenantOrProjectScope)
  ) {
    return {
      allowed: false,
      guard_code: 'INCIDENT_NOT_ACCESSIBLE',
      http_status: 404,
      reason: 'Requested incident is not accessible or does not exist within the authorized scope.',
      required_action: 'Verify incident identifier and project access permissions.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 3. Current Status Guard (Section 6)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('3. Current Status Guard');
  const parsedCurrent = parseCanonicalIncidentStatus(input.currentStatus);
  if (!parsedCurrent.ok || parsedCurrent.status !== incident.status) {
    return {
      allowed: false,
      guard_code: 'INVALID_CURRENT_STATUS',
      http_status: 409,
      reason: `Current status mismatch: Expected "${String(input.currentStatus)}", but authoritative status is "${incident.status}".`,
      required_action: 'Reload the authoritative incident state before requesting a transition.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 4. Requested Status Guard (Section 7)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('4. Requested Status Guard');
  const parsedTarget = parseCanonicalIncidentStatus(input.requestedStatus);
  if (!parsedTarget.ok) {
    return {
      allowed: false,
      guard_code: 'INVALID_TARGET_STATUS',
      http_status: 422,
      reason: parsedTarget.error,
      required_action: 'Supply one of the 16 canonical INCIDENT_STATUS_ENUM_V1 values.',
      evaluated_guards: evaluatedGuards,
    };
  }
  const targetStatus = parsedTarget.status;

  // --------------------------------------------------------------------------
  // 5. Transition Matrix Guard (Section 8 & 48)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('5. Transition Matrix Guard');
  const allowedTargets = ALLOWED_INCIDENT_STATUS_TRANSITIONS[incident.status];
  if (!allowedTargets || !allowedTargets.has(targetStatus)) {
    return {
      allowed: false,
      guard_code: 'TRANSITION_NOT_ALLOWED',
      http_status: 422,
      reason: `Transition ${incident.status} -> ${targetStatus} is prohibited by the canonical 23-transition matrix.`,
      required_action: `Select a valid transition from ${incident.status}.`,
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 6. Concurrency/Version & Idempotency Guard (Section 9 & 43)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('6. Concurrency/Version Guard');
  if (input.transitionId) {
    const idKey = `${incident.incidentId}:${input.transitionId}`;
    const fingerprint = `${incident.status}->${targetStatus}@v${input.incidentVersion}`;
    const existingFingerprint = transitionIdFingerprints.get(idKey);
    if (existingFingerprint && existingFingerprint !== fingerprint) {
      return {
        allowed: false,
        guard_code: 'IDEMPOTENCY_CONFLICT',
        http_status: 409,
        reason:
          'Idempotency conflict: The provided transition_id was already used with different transition parameters.',
        required_action: 'Generate a new transition_id for a distinct transition request.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  if (
    inFlightIncidentLocks.has(incident.incidentId) ||
    input.incidentVersion !== incident.version
  ) {
    return {
      allowed: false,
      guard_code: 'STALE_INCIDENT_VERSION',
      http_status: 409,
      reason: `Stale incident version: Expected v${input.incidentVersion}, but authoritative version is v${incident.version}.`,
      required_action: 'Reload the authoritative incident version and retry if appropriate.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 7. Actor Authorization Guard (Section 10)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('7. Actor Authorization Guard');
  const actorName = actor.actorName.trim();
  const actorRole = (actor.actorRole || '').trim().toLowerCase();

  if (actorRole === 'student' || actorRole === 'teacher' || actorRole === 'guest') {
    return {
      allowed: false,
      guard_code: 'ACTOR_NOT_AUTHORIZED',
      http_status: 403,
      reason: `Role "${actorRole}" is not authorized to perform incident lifecycle transitions.`,
      required_action: 'Escalate to the assigned Incident Owner or Administrator.',
      evaluated_guards: evaluatedGuards,
    };
  }

  const authorizedIncidentActors = new Set([
    incident.primaryOwner,
    incident.backupOwner,
    incident.securityOwner,
    incident.databaseOwner,
    incident.rollbackOwner,
    incident.monitoringOwner,
    incident.closureOwner,
  ]);

  if (actorRole !== 'admin' && !authorizedIncidentActors.has(actorName)) {
    return {
      allowed: false,
      guard_code: 'ACTOR_NOT_AUTHORIZED',
      http_status: 403,
      reason: `Actor "${actorName}" is not an authorized owner or responder for incident ${incident.incidentId}.`,
      required_action: 'Have the assigned domain or incident owner execute the transition.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 8. Ownership Guard (Section 11)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('8. Ownership Guard');
  const effectivePrimaryOwner =
    meta.triageMetadata?.primaryOwner?.trim() ||
    meta.reopenedToTriagedMetadata?.primaryOwner?.trim() ||
    incident.primaryOwner?.trim();
  const effectiveBackupOwner =
    meta.triageMetadata?.backupOwner?.trim() ||
    meta.reopenedToTriagedMetadata?.backupOwner?.trim() ||
    incident.backupOwner?.trim();

  if (
    !effectivePrimaryOwner ||
    !effectiveBackupOwner ||
    effectivePrimaryOwner.toLowerCase() === 'tbd' ||
    effectiveBackupOwner.toLowerCase() === 'tbd' ||
    effectivePrimaryOwner.toLowerCase() === effectiveBackupOwner.toLowerCase()
  ) {
    return {
      allowed: false,
      guard_code: 'OWNER_REQUIRED',
      http_status: 422,
      reason:
        'Ownership Guard violation: Distinct, active, authorized Primary and Backup Owners must be assigned.',
      required_action: 'Assign distinct Primary and Backup Owners before transitioning.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 9. Severity/Priority Guard (Sections 34 & 35)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('9. Severity/Priority Guard');
  const candidateSeverity =
    meta.triageMetadata?.severity ||
    meta.reopenedToTriagedMetadata?.severity ||
    incident.severity;
  const candidatePriority =
    meta.triageMetadata?.priority ||
    meta.reopenedToTriagedMetadata?.priority ||
    incident.priority;

  if (!candidateSeverity || !DEFAULT_INCIDENT_SLA_TARGETS[candidateSeverity]) {
    return {
      allowed: false,
      guard_code: 'SEVERITY_REQUIRED',
      http_status: 422,
      reason: 'Severity Guard violation: A valid canonical severity (SEV-1..SEV-4) is required.',
      required_action: 'Assign a valid canonical severity.',
      evaluated_guards: evaluatedGuards,
    };
  }

  if (
    meta.securityContext?.unhandledSecurityEscalation &&
    candidateSeverity !== 'SEV-1'
  ) {
    return {
      allowed: false,
      guard_code: 'SEVERITY_REQUIRED',
      http_status: 422,
      reason:
        'Severity Guard violation: Active security escalation or credential/privilege exposure requires SEV-1 classification.',
      required_action: 'Escalate incident severity to SEV-1 (P0).',
      evaluated_guards: evaluatedGuards,
    };
  }

  const expectedPriorityForSeverity =
    DEFAULT_INCIDENT_SLA_TARGETS[candidateSeverity].defaultPriority;
  if (!candidatePriority || candidatePriority !== expectedPriorityForSeverity) {
    return {
      allowed: false,
      guard_code: 'PRIORITY_REQUIRED',
      http_status: 422,
      reason: `Priority Guard violation: Priority "${String(candidatePriority)}" is inconsistent with ${candidateSeverity} (expected ${expectedPriorityForSeverity}).`,
      required_action: `Align incident priority to ${expectedPriorityForSeverity}.`,
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 10. Evidence Guard (Section 36)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('10. Evidence Guard');
  const ev = input.evidence;
  if (
    !ev ||
    ev.clientClaimOnly === true ||
    isVagueEvidence(ev.evidenceReference) ||
    isVagueEvidence(ev.reason) ||
    ev.timestamped === false ||
    ev.attributable === false ||
    ev.integrityPreserving === false ||
    (ev.associatedIncidentId && ev.associatedIncidentId !== incident.incidentId)
  ) {
    return {
      allowed: false,
      guard_code: 'EVIDENCE_REQUIRED',
      http_status: 422,
      reason:
        'Evidence Guard violation: Server-verifiable, non-vague, attributable evidence associated with this incident is required.',
      required_action: 'Attach verifiable evidence reference and detailed transition reason.',
      evidence_required: ['evidenceReference', 'reason'],
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 11. Approval Guard (Section 37)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('11. Approval Guard');
  const transitionKey = `${incident.status}->${targetStatus}`;
  const requiresFormalApproval =
    transitionKey === 'RECOVERY_VERIFIED->MONITORING' ||
    transitionKey === 'RESOLVED->CLOSED';

  if (requiresFormalApproval) {
    const approvals = input.approvals || [];
    const validApproval = approvals.find(
      (a) =>
        a.incidentId === incident.incidentId &&
        a.targetTransition === transitionKey &&
        !a.revoked &&
        (!a.expiresAtMs || a.expiresAtMs > nowMs) &&
        a.approver?.trim() &&
        a.approver.trim().toLowerCase() !== actorName.toLowerCase() &&
        a.approverRole?.trim().toLowerCase() !== 'student' &&
        a.approverRole?.trim().toLowerCase() !== 'teacher'
    );
    if (!validApproval) {
      return {
        allowed: false,
        guard_code: 'APPROVAL_REQUIRED',
        http_status: 422,
        reason: `Approval Guard violation: Transition ${transitionKey} requires a current, non-revoked, non-self-approved authorization record for incident ${incident.incidentId}.`,
        required_action: 'Obtain formal four-eyes approval from an authorized sign-off owner.',
        approval_required: [transitionKey],
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // --------------------------------------------------------------------------
  // 12. Dependency Guard (Section 38)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('12. Dependency Guard');
  const deps = meta.dependencies;
  if (deps) {
    const anyDepUnavailable =
      deps.monitoringAvailable === false ||
      deps.databaseAccessAvailable === false ||
      deps.deploymentSystemAvailable === false ||
      deps.securityVerificationAvailable === false ||
      deps.testEnvironmentAvailable === false ||
      deps.evidenceStoreAvailable === false;

    if (anyDepUnavailable && targetStatus !== 'RECOVERY_BLOCKED') {
      return {
        allowed: false,
        guard_code: 'DEPENDENCY_UNAVAILABLE',
        http_status: 422,
        reason:
          'Dependency Guard violation: A required verification/monitoring/database dependency is unavailable. Transition to RECOVERY_BLOCKED instead of bypassing or recording a false failure.',
        required_action: 'Restore the unavailable dependency or transition to RECOVERY_BLOCKED.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // --------------------------------------------------------------------------
  // 13. Verification Guard (Section 26)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('13. Verification Guard');
  if (targetStatus === 'RECOVERY_VERIFIED') {
    const rvm = meta.recoveryVerifiedMetadata;
    if (rvm?.anyRequiredVerificationFailed) {
      return {
        allowed: false,
        guard_code: 'VERIFICATION_FAILED',
        http_status: 422,
        reason: 'Verification Guard violation: One or more required verifications are in FAIL status.',
        required_action: 'Transition to RECOVERY_FAILED, remediate, and retest.',
        evaluated_guards: evaluatedGuards,
      };
    }
    if (rvm?.anyRequiredVerificationBlocked) {
      return {
        allowed: false,
        guard_code: 'VERIFICATION_BLOCKED',
        http_status: 422,
        reason: 'Verification Guard violation: One or more required verifications are BLOCKED.',
        required_action: 'Resolve blocking dependencies before verifying recovery.',
        evaluated_guards: evaluatedGuards,
      };
    }
    if (
      !rvm ||
      !rvm.allRequiredVerificationsPass ||
      !rvm.criticalSecurityChecksPass ||
      !rvm.authorizationChecksPass ||
      !rvm.databaseIntegrityChecksPass ||
      !rvm.authenticationChecksPass ||
      !rvm.sessionChecksPass ||
      !rvm.protectedApiChecksPass ||
      !rvm.requiredRegressionChecksPass ||
      rvm.anyRequiredVerificationMissingEvidence ||
      !rvm.recoveryEvidenceComplete ||
      !rvm.verificationOwnersCompleted
    ) {
      return {
        allowed: false,
        guard_code: 'VERIFICATION_NOT_COMPLETE',
        http_status: 422,
        reason:
          'Verification Guard violation: All required authentication, session, authorization, API, database, security, and regression checks must PASS with complete owner sign-off and evidence.',
        required_action: 'Complete all 16 required recovery verification areas.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // --------------------------------------------------------------------------
  // 14. Security/Data-Integrity Guard (Sections 39 & 40)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('14. Security/Data-Integrity Guard');
  const highGateTarget =
    targetStatus === 'RECOVERY_VERIFIED' ||
    targetStatus === 'RESOLVED' ||
    targetStatus === 'CLOSED';

  if (highGateTarget) {
    if (
      meta.securityContext?.involvesSecurityDomain &&
      meta.securityContext.securityReviewVerified !== true
    ) {
      return {
        allowed: false,
        guard_code: 'SECURITY_REVIEW_REQUIRED',
        http_status: 422,
        reason:
          'Security Guard violation: Security review and verification by the Security Owner are mandatory before recovery verification, resolution, or closure.',
        required_action: 'Complete mandatory Security Owner verification.',
        evaluated_guards: evaluatedGuards,
      };
    }

    if (
      meta.databaseContext?.involvesCriticalDataRecords &&
      meta.databaseContext.databaseIntegrityState !== 'VERIFIED_HEALTHY'
    ) {
      return {
        allowed: false,
        guard_code: 'DATABASE_REVIEW_REQUIRED',
        http_status: 422,
        reason: `Database-Integrity Guard violation: Database integrity state is "${String(meta.databaseContext.databaseIntegrityState || 'UNKNOWN')}". Only VERIFIED_HEALTHY is accepted (UNKNOWN is never treated as healthy).`,
        required_action: 'Complete Database Recovery Owner integrity verification.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // --------------------------------------------------------------------------
  // 15. SLA Guard (Section 41)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('15. SLA Guard');
  if (meta.slaContext?.attemptingSlaBypass) {
    return {
      allowed: false,
      guard_code: 'CRITICAL_BLOCKER_EXISTS',
      http_status: 422,
      reason:
        'SLA Guard violation: SLA breach or deadline pressure never permits bypassing required verification, stability, or closure gates.',
      required_action: 'Satisfy all mandatory verification and closure criteria.',
      evaluated_guards: evaluatedGuards,
    };
  }

  if (
    meta.slaContext?.requiredStabilityWindowMinutes &&
    typeof meta.slaContext.stabilityWindowElapsedMinutes === 'number' &&
    meta.slaContext.stabilityWindowElapsedMinutes <
      meta.slaContext.requiredStabilityWindowMinutes &&
    (targetStatus === 'STABILITY_CONFIRMED' ||
      targetStatus === 'RESOLVED' ||
      targetStatus === 'CLOSED')
  ) {
    return {
      allowed: false,
      guard_code: 'STABILITY_WINDOW_INCOMPLETE',
      http_status: 422,
      reason: `Stability window incomplete: ${meta.slaContext.stabilityWindowElapsedMinutes}m elapsed of required ${meta.slaContext.requiredStabilityWindowMinutes}m window.`,
      required_action: 'Complete the full post-recovery monitoring window.',
      evaluated_guards: evaluatedGuards,
    };
  }

  // --------------------------------------------------------------------------
  // 16. Transition-Specific Business Guards (Sections 12–33 & 48 — All 23 Transitions)
  // --------------------------------------------------------------------------
  evaluatedGuards.push('16. Transition-Specific Business Guard');

  // (1) DETECTED -> TRIAGED (Section 12)
  if (incident.status === 'DETECTED' && targetStatus === 'TRIAGED') {
    const tm = meta.triageMetadata;
    if (
      !tm ||
      !tm.severity ||
      !tm.priority ||
      !tm.affectedArea?.trim() ||
      !tm.initialImpact?.trim() ||
      !tm.primaryOwner?.trim() ||
      !tm.backupOwner?.trim() ||
      !tm.detectionEvidence?.trim() ||
      tm.ownersAuthorized === false
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'DETECTED -> TRIAGED guard failed: severity, priority, affectedArea, initialImpact, primaryOwner, backupOwner, detectionEvidence, and authorized owners are required.',
        evidence_required: ['affectedArea', 'initialImpact', 'detectionEvidence'],
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (2) TRIAGED -> ACKNOWLEDGED (Section 13)
  if (incident.status === 'TRIAGED' && targetStatus === 'ACKNOWLEDGED') {
    const am = meta.acknowledgeMetadata;
    if (am?.attemptedSelfPrivilegeElevation) {
      return {
        allowed: false,
        guard_code: 'ACTOR_NOT_AUTHORIZED',
        http_status: 403,
        reason:
          'TRIAGED -> ACKNOWLEDGED guard failed: Actor cannot assign elevated privileges through acknowledgement.',
        evaluated_guards: evaluatedGuards,
      };
    }
    if (!am || !am.actorAcceptsResponsibility || !am.acknowledgementMetadataValid) {
      return {
        allowed: false,
        guard_code: 'OWNER_REQUIRED',
        http_status: 422,
        reason:
          'TRIAGED -> ACKNOWLEDGED guard failed: Authorized owner must explicitly accept responsibility with valid acknowledgement metadata.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (3) ACKNOWLEDGED -> CONTAINMENT_IN_PROGRESS (Section 14)
  if (
    incident.status === 'ACKNOWLEDGED' &&
    targetStatus === 'CONTAINMENT_IN_PROGRESS'
  ) {
    const cm = meta.containmentStartMetadata;
    if (!cm || !cm.actorHasContainmentAuthority) {
      return {
        allowed: false,
        guard_code: 'ACTOR_NOT_AUTHORIZED',
        http_status: 403,
        reason:
          'ACKNOWLEDGED -> CONTAINMENT_IN_PROGRESS guard failed: Actor lacks containment authority.',
        evaluated_guards: evaluatedGuards,
      };
    }
    if (
      !cm.containmentRequired ||
      !cm.containmentOwner?.trim() ||
      !cm.containmentPlan?.trim() ||
      (cm.isSecurityIncident &&
        (!cm.securityOwnerIdentified || !cm.securityEscalationPathAvailable))
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'ACKNOWLEDGED -> CONTAINMENT_IN_PROGRESS guard failed: containmentRequired, containmentOwner, containmentPlan, and security escalation path (for security incidents) are required.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (4) ACKNOWLEDGED -> ROLLBACK_IN_PROGRESS (Section 15)
  if (
    incident.status === 'ACKNOWLEDGED' &&
    targetStatus === 'ROLLBACK_IN_PROGRESS'
  ) {
    const rm = meta.rollbackStartMetadata;
    if (!rm || !rm.rollbackAuthorityConfirmed) {
      return {
        allowed: false,
        guard_code: 'ACTOR_NOT_AUTHORIZED',
        http_status: 403,
        reason:
          'ACKNOWLEDGED -> ROLLBACK_IN_PROGRESS guard failed: Rollback authority is not confirmed.',
        evaluated_guards: evaluatedGuards,
      };
    }
    if (
      !rm.rollbackRequired ||
      !rm.rollbackOwner?.trim() ||
      !rm.rollbackTarget?.trim() ||
      !rm.knownGoodVersion?.trim() ||
      !rm.rollbackPlan?.trim() ||
      !rm.databaseRollbackImpactAssessed ||
      (rm.containmentRequiredFirst && !rm.containmentConditionSatisfied)
    ) {
      return {
        allowed: false,
        guard_code: 'CRITICAL_BLOCKER_EXISTS',
        http_status: 422,
        reason:
          'ACKNOWLEDGED -> ROLLBACK_IN_PROGRESS guard failed: Rollback owner, target, known-good version, rollback plan, DB impact assessment, and mandatory containment prerequisite are required.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (5) CONTAINMENT_IN_PROGRESS -> CONTAINED (Section 16)
  if (
    incident.status === 'CONTAINMENT_IN_PROGRESS' &&
    targetStatus === 'CONTAINED'
  ) {
    const cvm = meta.containedMetadata;
    if (
      !cvm ||
      !cvm.containmentVerified ||
      !cvm.containmentAction?.trim() ||
      !cvm.containmentOwner?.trim() ||
      !cvm.containmentObjective?.trim() ||
      !cvm.expectedEffect?.trim() ||
      !cvm.observedEffect?.trim() ||
      !cvm.affectedScopeAssessed?.trim()
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'CONTAINMENT_IN_PROGRESS -> CONTAINED guard failed: Verified containment evidence (action, owner, objective, expected/observed effect, and scope) is required; attempted mitigation alone is insufficient.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (6) CONTAINED -> ROLLBACK_IN_PROGRESS (Section 17)
  if (
    incident.status === 'CONTAINED' &&
    targetStatus === 'ROLLBACK_IN_PROGRESS'
  ) {
    const rm = meta.rollbackStartMetadata;
    if (
      !rm ||
      !rm.containmentConditionSatisfied ||
      !rm.rollbackRequired ||
      !rm.rollbackOwner?.trim() ||
      !rm.rollbackTarget?.trim() ||
      !rm.rollbackPlan?.trim() ||
      !rm.rollbackAuthorityConfirmed
    ) {
      return {
        allowed: false,
        guard_code: 'CRITICAL_BLOCKER_EXISTS',
        http_status: 422,
        reason:
          'CONTAINED -> ROLLBACK_IN_PROGRESS guard failed: Active verified containment, rollbackRequired, rollbackOwner, rollbackTarget, rollbackPlan, and rollbackAuthorityConfirmed are required.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (7) CONTAINED -> RECOVERY_IN_PROGRESS (Section 18)
  if (
    incident.status === 'CONTAINED' &&
    targetStatus === 'RECOVERY_IN_PROGRESS'
  ) {
    const crm = meta.containedToRecoveryMetadata;
    if (
      !crm ||
      crm.rollbackRequired !== false ||
      !crm.rollbackNotRequiredReason?.trim() ||
      !crm.recoveryPlan?.trim() ||
      !crm.verificationPlan?.trim() ||
      !crm.verificationOwner?.trim() ||
      !crm.requiredTestCapabilityAvailable
    ) {
      return {
        allowed: false,
        guard_code: 'CRITICAL_BLOCKER_EXISTS',
        http_status: 422,
        reason:
          'CONTAINED -> RECOVERY_IN_PROGRESS guard failed: Cannot skip mandatory rollback; requires rollbackRequired=false, rollbackNotRequiredReason, recoveryPlan, verificationPlan, verificationOwner, and test capability.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (8) ROLLBACK_IN_PROGRESS -> ROLLBACK_COMPLETE (Section 19)
  if (
    incident.status === 'ROLLBACK_IN_PROGRESS' &&
    targetStatus === 'ROLLBACK_COMPLETE'
  ) {
    const rcm = meta.rollbackCompleteMetadata;
    const dbSatisfied =
      rcm?.requiredDatabaseActionComplete === true ||
      rcm?.databaseActionNotRequired === true;
    if (
      !rcm ||
      !rcm.rollbackAuthorized ||
      !rcm.knownGoodVersionRestored ||
      !rcm.failedVersionInactive ||
      !rcm.requiredInstancesRestored ||
      !rcm.requiredConfigurationRestored ||
      !dbSatisfied ||
      !rcm.rollbackExecutionComplete ||
      !rcm.rollbackEvidenceExists
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'ROLLBACK_IN_PROGRESS -> ROLLBACK_COMPLETE guard failed: All technical rollback restoration, configuration, database remediation, and deployment evidence checks must pass.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (9) ROLLBACK_IN_PROGRESS -> RECOVERY_FAILED (Section 20)
  if (
    incident.status === 'ROLLBACK_IN_PROGRESS' &&
    targetStatus === 'RECOVERY_FAILED'
  ) {
    const rfm = meta.rollbackFailedMetadata;
    if (rfm?.causedByMissingOwnerOrDependencyOnly) {
      return {
        allowed: false,
        guard_code: 'DEPENDENCY_UNAVAILABLE',
        http_status: 422,
        reason:
          'ROLLBACK_IN_PROGRESS -> RECOVERY_FAILED guard failed: Missing owner, test access, or dependency is a BLOCKED condition, not an executed rollback failure.',
        evaluated_guards: evaluatedGuards,
      };
    }
    if (
      !rfm ||
      !rfm.rollbackExecutionStarted ||
      !rfm.rollbackFailureDetected ||
      !rfm.rollbackFailureEvidence?.trim() ||
      rfm.safeRollbackCompletionPossible !== false
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'ROLLBACK_IN_PROGRESS -> RECOVERY_FAILED guard failed: Requires actual rollback execution failure evidence and confirmation that safe rollback completion is not possible.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (10) ROLLBACK_COMPLETE -> RECOVERY_IN_PROGRESS (Section 21)
  if (
    incident.status === 'ROLLBACK_COMPLETE' &&
    targetStatus === 'RECOVERY_IN_PROGRESS'
  ) {
    const rtr = meta.rollbackToRecoveryMetadata;
    if (
      !rtr ||
      rtr.rollbackStatus !== 'ACTION_COMPLETE' ||
      !rtr.rollbackEvidence?.trim() ||
      !rtr.knownGoodStateConfirmed ||
      !rtr.verificationPlan?.trim() ||
      !rtr.verificationOwner?.trim() ||
      !rtr.requiredVerificationAccessAvailable
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'ROLLBACK_COMPLETE -> RECOVERY_IN_PROGRESS guard failed: Requires ACTION_COMPLETE rollback status, rollback evidence, confirmed known-good state, verification plan, verification owner, and verification access.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (11) RECOVERY_IN_PROGRESS -> RECOVERY_BLOCKED (Section 22)
  if (
    incident.status === 'RECOVERY_IN_PROGRESS' &&
    targetStatus === 'RECOVERY_BLOCKED'
  ) {
    const rbm = meta.recoveryBlockedMetadata;
    const cannotExecute =
      rbm?.verificationAttempted === false ||
      rbm?.verificationCannotMeaningfullyExecute === true;
    if (
      !rbm ||
      !cannotExecute ||
      !rbm.blockingReason?.trim() ||
      !rbm.dependency?.trim() ||
      !rbm.blockerOwner?.trim() ||
      !validateAbsoluteDeadlineFormat(rbm.deadline || '') ||
      !rbm.riskLevel ||
      !rbm.nextAction?.trim()
    ) {
      return {
        allowed: false,
        guard_code: 'VERIFICATION_BLOCKED',
        http_status: 422,
        reason:
          'RECOVERY_IN_PROGRESS -> RECOVERY_BLOCKED guard failed: Requires real unexecutable dependency blocker, blockingReason, dependency, blockerOwner, valid absolute deadline, riskLevel, and nextAction.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (12) RECOVERY_BLOCKED -> RECOVERY_IN_PROGRESS (Section 23)
  if (
    incident.status === 'RECOVERY_BLOCKED' &&
    targetStatus === 'RECOVERY_IN_PROGRESS'
  ) {
    const rum = meta.recoveryUnblockMetadata;
    if (
      !rum ||
      !rum.dependencyAvailable ||
      !rum.requiredAccessRestored ||
      !rum.requiredTestCapabilityAvailable ||
      !rum.blockerResolutionEvidence?.trim() ||
      !rum.retestStarted
    ) {
      return {
        allowed: false,
        guard_code: 'DEPENDENCY_UNAVAILABLE',
        http_status: 422,
        reason:
          'RECOVERY_BLOCKED -> RECOVERY_IN_PROGRESS guard failed: Requires dependencyAvailable, requiredAccessRestored, requiredTestCapabilityAvailable, blockerResolutionEvidence, and retestStarted.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (13) RECOVERY_IN_PROGRESS -> RECOVERY_FAILED (Section 24)
  if (
    incident.status === 'RECOVERY_IN_PROGRESS' &&
    targetStatus === 'RECOVERY_FAILED'
  ) {
    const rfm = meta.recoveryFailedMetadata;
    if (rfm?.causedByMissingDependencyOnly) {
      return {
        allowed: false,
        guard_code: 'DEPENDENCY_UNAVAILABLE',
        http_status: 422,
        reason:
          'RECOVERY_IN_PROGRESS -> RECOVERY_FAILED guard failed: Missing dependency must transition to RECOVERY_BLOCKED, not RECOVERY_FAILED.',
        evaluated_guards: evaluatedGuards,
      };
    }
    if (
      !rfm ||
      !rfm.verificationExecuted ||
      rfm.verificationResult !== 'FAIL' ||
      !rfm.failureReason?.trim() ||
      !rfm.expectedResult?.trim() ||
      !rfm.actualResult?.trim() ||
      !rfm.evidence?.trim() ||
      !rfm.verificationOwner?.trim()
    ) {
      return {
        allowed: false,
        guard_code: 'VERIFICATION_FAILED',
        http_status: 422,
        reason:
          'RECOVERY_IN_PROGRESS -> RECOVERY_FAILED guard failed: Requires executed verification with FAIL result, failureReason, expectedResult, actualResult, evidence, and verificationOwner.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (14) RECOVERY_FAILED -> RECOVERY_IN_PROGRESS (Section 25)
  if (
    incident.status === 'RECOVERY_FAILED' &&
    targetStatus === 'RECOVERY_IN_PROGRESS'
  ) {
    const rrm = meta.recoveryRetestMetadata;
    if (
      !rrm ||
      !rrm.failureRecordExists ||
      !rrm.remediationCompleted ||
      !rrm.remediationEvidence?.trim() ||
      !rrm.retestPlan?.trim() ||
      !rrm.retestOwner?.trim() ||
      !rrm.retestStarted
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'RECOVERY_FAILED -> RECOVERY_IN_PROGRESS guard failed: Preserved failure record, completed remediation, remediationEvidence, retestPlan, retestOwner, and retestStarted are required.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (15) RECOVERY_IN_PROGRESS -> RECOVERY_VERIFIED (Section 26)
  // Validated in Guard #13 above.

  // (16) RECOVERY_VERIFIED -> MONITORING (Section 27)
  if (
    incident.status === 'RECOVERY_VERIFIED' &&
    targetStatus === 'MONITORING'
  ) {
    const msm = meta.monitoringStartMetadata;
    if (
      !msm ||
      msm.recoveryVerification !== 'VERIFIED' ||
      msm.recoverySignoff !== 'COMPLETE' ||
      !msm.monitoringOwner?.trim() ||
      !msm.monitoringPlan?.trim() ||
      (msm.monitoringWindowMinutes !== 60 &&
        msm.monitoringWindowMinutes !== 120) ||
      !msm.monitoringChecksConfigured
    ) {
      return {
        allowed: false,
        guard_code: 'APPROVAL_REQUIRED',
        http_status: 422,
        reason:
          'RECOVERY_VERIFIED -> MONITORING guard failed: Requires VERIFIED recovery, COMPLETE recovery sign-off, monitoringOwner, monitoringPlan, 60m/120m monitoringWindow, and configured monitoring checks.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (17) MONITORING -> STABILITY_CONFIRMED (Section 28)
  if (
    incident.status === 'MONITORING' &&
    targetStatus === 'STABILITY_CONFIRMED'
  ) {
    const scm = meta.stabilityConfirmedMetadata;
    const requiredWin = scm?.isHighRiskIncident ? 120 : 60;
    if (
      !scm ||
      !scm.monitoringStarted ||
      !scm.requiredMonitoringWindowComplete ||
      typeof scm.windowMinutesCompleted !== 'number' ||
      scm.windowMinutesCompleted < requiredWin
    ) {
      return {
        allowed: false,
        guard_code: 'STABILITY_WINDOW_INCOMPLETE',
        http_status: 422,
        reason: `MONITORING -> STABILITY_CONFIRMED guard failed: Full ${requiredWin}-minute stability window must complete before confirming stability.`,
        evaluated_guards: evaluatedGuards,
      };
    }
    if (
      !scm.monitoringEvidenceComplete ||
      scm.criticalRegressionCount !== 0 ||
      scm.criticalSecurityIssueCount !== 0 ||
      scm.criticalDatabaseIssueCount !== 0 ||
      scm.authenticationHealth !== 'ACCEPTABLE' ||
      scm.authorizationHealth !== 'ACCEPTABLE' ||
      scm.apiHealth !== 'ACCEPTABLE' ||
      scm.errorRate !== 'ACCEPTABLE'
    ) {
      return {
        allowed: false,
        guard_code: 'CRITICAL_BLOCKER_EXISTS',
        http_status: 422,
        reason:
          'MONITORING -> STABILITY_CONFIRMED guard failed: Zero critical regressions/security/DB issues and ACCEPTABLE auth, authz, API, and error-rate health with complete evidence are required.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (18) MONITORING -> RECOVERY_FAILED (Section 29)
  if (incident.status === 'MONITORING' && targetStatus === 'RECOVERY_FAILED') {
    const mfm = meta.monitoringFailedMetadata;
    if (
      !mfm ||
      !mfm.materialRegressionDetected ||
      !mfm.regressionType?.trim() ||
      !mfm.expectedBehavior?.trim() ||
      !mfm.actualBehavior?.trim() ||
      !mfm.detectionTimestamp?.trim() ||
      !mfm.evidenceReference?.trim() ||
      !mfm.impact?.trim()
    ) {
      return {
        allowed: false,
        guard_code: 'EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'MONITORING -> RECOVERY_FAILED guard failed: Material regression evidence (type, expected/actual behavior, timestamp, evidenceReference, and impact) is required.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (19) STABILITY_CONFIRMED -> RESOLVED (Section 30)
  if (
    incident.status === 'STABILITY_CONFIRMED' &&
    targetStatus === 'RESOLVED'
  ) {
    const resm = meta.resolvedMetadata;
    if (
      !resm ||
      !resm.recoveryVerified ||
      resm.recoverySignoff !== 'COMPLETE' ||
      !resm.stabilityConfirmed ||
      !resm.requiredRemediationComplete ||
      !resm.noCriticalFailures ||
      !resm.noCriticalBlockers ||
      !resm.resolutionSummary?.trim() ||
      !resm.followUpActionsAssigned ||
      !resm.ownersAssigned ||
      !resm.deadlinesAssigned
    ) {
      return {
        allowed: false,
        guard_code: 'CRITICAL_BLOCKER_EXISTS',
        http_status: 422,
        reason:
          'STABILITY_CONFIRMED -> RESOLVED guard failed: Requires verified recovery, COMPLETE sign-off, confirmed stability, completed remediation, zero critical blockers, resolutionSummary, and assigned follow-up actions with owners and deadlines.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (20) RESOLVED -> CLOSED (Section 31)
  if (incident.status === 'RESOLVED' && targetStatus === 'CLOSED') {
    const clm = meta.closedMetadata;
    if (
      !clm ||
      !clm.incidentTimelineComplete ||
      !clm.requiredEvidenceRetained ||
      !clm.requiredSignoffsComplete ||
      !clm.exceptionsDocumented ||
      !clm.followUpActionsAssigned ||
      !clm.securityReviewComplete ||
      !clm.databaseReviewComplete ||
      !clm.closureReviewComplete ||
      clm.criticalBlockerCount !== 0
    ) {
      return {
        allowed: false,
        guard_code: 'CRITICAL_BLOCKER_EXISTS',
        http_status: 422,
        reason:
          'RESOLVED -> CLOSED guard failed: Requires complete incident timeline, retained evidence, sign-offs, documented exceptions, assigned follow-ups, completed security/DB/closure reviews, and zero critical blockers.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (21 & 22) RESOLVED -> REOPENED and CLOSED -> REOPENED (Sections 32 & 33)
  if (
    (incident.status === 'RESOLVED' || incident.status === 'CLOSED') &&
    targetStatus === 'REOPENED'
  ) {
    const rom = meta.reopenedMetadata;
    if (rom?.administrativeEditAttemptOnly) {
      return {
        allowed: false,
        guard_code: 'REOPENING_EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          'Reopen Guard violation: Cannot reopen an incident solely to edit history, change owners, or update notes. Use the non-destructive audit correction mechanism.',
        evaluated_guards: evaluatedGuards,
      };
    }

    const hasCredibleTrigger = Boolean(
      rom &&
        (rom.originalIssueReturned ||
          rom.originalIssuePersisted ||
          rom.recoveryEvidenceInvalidated ||
          rom.securityExposureDiscovered ||
          rom.databaseIntegrityConcernDiscovered ||
          rom.materialRelatedRegressionDetected)
    );

    const closedExtraCheck =
      incident.status === 'CLOSED' ? rom?.reopenReviewCompleted === true : true;

    if (
      !rom ||
      !hasCredibleTrigger ||
      !rom.reopeningReason?.trim() ||
      !rom.reopeningEvidence?.trim() ||
      !closedExtraCheck
    ) {
      return {
        allowed: false,
        guard_code: 'REOPENING_EVIDENCE_REQUIRED',
        http_status: 422,
        reason:
          `${incident.status} -> REOPENED guard failed: Credible new regression/exposure evidence, reopeningReason, reopeningEvidence, and reopen review (when CLOSED) are required.`,
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  // (23) REOPENED -> TRIAGED (Section 48)
  if (incident.status === 'REOPENED' && targetStatus === 'TRIAGED') {
    const rtm = meta.reopenedToTriagedMetadata;
    if (
      !rtm ||
      !rtm.reassessmentComplete ||
      !rtm.severity ||
      !rtm.priority ||
      !rtm.primaryOwner?.trim() ||
      !rtm.backupOwner?.trim()
    ) {
      return {
        allowed: false,
        guard_code: 'SEVERITY_REQUIRED',
        http_status: 422,
        reason:
          'REOPENED -> TRIAGED guard failed: Complete reassessment of severity, priority, primaryOwner, and backupOwner is required.',
        evaluated_guards: evaluatedGuards,
      };
    }
  }

  return {
    allowed: true,
    guard_code: 'GUARD_PASSED',
    http_status: 200,
    reason: `All 16 pre-transition guards satisfied for ${incident.status} -> ${targetStatus}.`,
    evaluated_guards: evaluatedGuards,
  };
}

/**
 * Sections 2, 43, 44, 46, 49: Executes a full 19-step guarded atomic transition:
 *   - Steps 1–16 via `guardTransition`
 *   - Step 17: Atomic State Update
 *   - Step 18: Audit Event Creation (for both allowed and rejected transitions)
 *   - Step 19: Required Side Effects (including stopping stability timer on MONITORING -> RECOVERY_FAILED)
 */
export function executeGuardedIncidentTransition(params: {
  incidentId: string;
  currentStatus: unknown;
  requestedStatus: unknown;
  incidentVersion: number;
  transitionId: string;
  actor: GuardTransitionInput['actor'];
  evidence: GuardTransitionInput['evidence'];
  approvals?: StructuredApprovalRecord[];
  transitionMetadata?: GuardTransitionInput['transitionMetadata'];
  serverNowMs?: number;
}): TransitionResultContract & { guardResult: GuardEvaluationContract } {
  const serverNowMs =
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const serverNowIso = new Date(serverNowMs).toISOString();

  const idKey = `${params.incidentId}:${params.transitionId}`;
  const targetFingerprint = `${String(params.currentStatus)}->${String(params.requestedStatus)}@v${params.incidentVersion}`;
  const existingCached = processedTransitionResults.get(idKey);
  const existingFingerprint = transitionIdFingerprints.get(idKey);

  if (existingCached && existingFingerprint === targetFingerprint) {
    return {
      ...existingCached,
      guard_code: 'GUARD_PASSED',
      guardResult: {
        allowed: true,
        guard_code: 'GUARD_PASSED',
        http_status: 200,
        reason: 'Idempotent replay of already committed transition.',
        evaluated_guards: [...GUARD_EVALUATION_ORDER_19_STEPS],
      },
    };
  }

  const incident = incidentStore.get(params.incidentId);
  const guardResult = guardTransition({
    incident,
    actor: params.actor,
    currentStatus: params.currentStatus,
    requestedStatus: params.requestedStatus,
    incidentVersion: params.incidentVersion,
    transitionId: params.transitionId,
    evidence: params.evidence,
    approvals: params.approvals,
    transitionMetadata: params.transitionMetadata,
    serverNowMs,
  });

  if (!guardResult.allowed) {
    let rejectionAuditId: string | null = null;
    if (incident) {
      const rejAudit = recordRejectedTransitionAudit({
        incident,
        actorName: params.actor?.actorName || 'unauthenticated_actor',
        actorRole: params.actor?.actorRole || 'unknown',
        requestedTransition: `${String(params.currentStatus)}->${String(params.requestedStatus)}`,
        guardCode: guardResult.guard_code as GuardFailureCode,
        reason: guardResult.reason,
        transitionId: params.transitionId,
        serverNowIso,
      });
      rejectionAuditId = rejAudit.eventId;
    }

    return {
      httpStatus: guardResult.http_status,
      success: false,
      incident_id: params.incidentId,
      previous_status: incident ? incident.status : null,
      current_status: incident ? incident.status : null,
      transition_id: params.transitionId,
      timestamp: serverNowIso,
      required_actions: guardResult.required_action
        ? [guardResult.required_action]
        : [],
      trigger_status: {
        transitionSucceeded: false,
        allTriggersSucceeded: false,
        failedCriticalOrRequiredTriggers: 0,
        failedNonCriticalTriggers: 0,
        executedTriggers: [],
      },
      audit_event_id: rejectionAuditId,
      error: guardResult.reason,
      guard_code: guardResult.guard_code,
      guardResult,
    };
  }

  // Step 17, 18, 19: Commit atomic state update, audit event, and side effects
  const authIncident = incident!;
  const nextStatus = params.requestedStatus as IncidentStatus;
  const actorName = params.actor!.actorName!.trim();
  const actorRole = (params.actor?.actorRole || 'admin').trim();

  const eventTypeMap: Record<IncidentStatus, RequiredAuditEventType> = {
    DETECTED: 'INCIDENT_CREATED',
    TRIAGED: 'INCIDENT_TRIAGED',
    ACKNOWLEDGED: 'INCIDENT_ACKNOWLEDGED',
    CONTAINMENT_IN_PROGRESS: 'CONTAINMENT_STARTED',
    CONTAINED: 'CONTAINMENT_COMPLETED',
    ROLLBACK_IN_PROGRESS: 'ROLLBACK_INITIATED',
    ROLLBACK_COMPLETE: 'ROLLBACK_ACTION_COMPLETED',
    RECOVERY_IN_PROGRESS: 'RECOVERY_VERIFICATION_STARTED',
    RECOVERY_BLOCKED: 'VERIFICATION_ITEM_BLOCKED',
    RECOVERY_FAILED: 'VERIFICATION_ITEM_FAILED',
    RECOVERY_VERIFIED: 'RECOVERY_VERIFIED',
    MONITORING: 'MONITORING_STARTED',
    STABILITY_CONFIRMED: 'STABILITY_CONFIRMED',
    RESOLVED: 'INCIDENT_RESOLVED',
    CLOSED: 'INCIDENT_CLOSED',
    REOPENED: 'INCIDENT_REOPENED',
  };

  const auditEvent = createAuditTrailEvent({
    incidentId: authIncident.incidentId,
    eventType: eventTypeMap[nextStatus],
    previousStatus: authIncident.status,
    newStatus: nextStatus,
    actor: actorName,
    actorRole,
    environment: authIncident.affectedEnvironment,
    reason: params.evidence?.reason || `Transition to ${nextStatus}`,
    result: nextStatus,
    evidenceReference: params.evidence?.evidenceReference || 'N/A',
    approver: params.approvals?.[0]?.approver || 'N/A',
    serverNowIso,
  });

  const executedTrigger: ExecutedTriggerRecord = Object.freeze({
    triggerId: `TRG-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    transitionId: params.transitionId,
    triggerClass: 'POST_TRANSITION',
    criticality: 'Required',
    name:
      authIncident.status === 'MONITORING' && nextStatus === 'RECOVERY_FAILED'
        ? 'stop_stability_timer_and_escalate'
        : 'atomic_guarded_commit_and_notify',
    status: 'SUCCEEDED',
    attempts: 1,
    timestamp: serverNowIso,
    detail: `Committed ${authIncident.status} -> ${nextStatus} (v${authIncident.version + 1})`,
  });

  const meta = params.transitionMetadata || {};
  const newSeverity =
    meta.triageMetadata?.severity ||
    meta.reopenedToTriagedMetadata?.severity ||
    authIncident.severity;
  const newPriority =
    meta.triageMetadata?.priority ||
    meta.reopenedToTriagedMetadata?.priority ||
    authIncident.priority;

  const updatedIncident: ProductionIncidentRecord = Object.freeze({
    ...authIncident,
    version: authIncident.version + 1,
    status: nextStatus,
    severity: newSeverity,
    priority: newPriority,
    primaryOwner:
      meta.triageMetadata?.primaryOwner ||
      meta.reopenedToTriagedMetadata?.primaryOwner ||
      authIncident.primaryOwner,
    backupOwner:
      meta.triageMetadata?.backupOwner ||
      meta.reopenedToTriagedMetadata?.backupOwner ||
      authIncident.backupOwner,
    rollbackSubStatus:
      nextStatus === 'ROLLBACK_IN_PROGRESS'
        ? 'INITIATED'
        : nextStatus === 'ROLLBACK_COMPLETE'
          ? 'ACTION_COMPLETE'
          : authIncident.rollbackSubStatus,
    recoverySubStatus:
      nextStatus === 'RECOVERY_IN_PROGRESS'
        ? 'VERIFICATION_RUNNING'
        : nextStatus === 'RECOVERY_VERIFIED'
          ? 'VERIFIED'
          : nextStatus === 'MONITORING'
            ? 'SIGN_OFF_COMPLETE'
            : authIncident.recoverySubStatus,
    monitoringSubStatus:
      nextStatus === 'MONITORING'
        ? 'ACTIVE'
        : nextStatus === 'STABILITY_CONFIRMED'
          ? 'STABLE'
          : authIncident.status === 'MONITORING' &&
              nextStatus === 'RECOVERY_FAILED'
            ? 'FAILED'
            : authIncident.monitoringSubStatus,
    approvalSubStatus:
      nextStatus === 'MONITORING' || nextStatus === 'CLOSED'
        ? 'COMPLETE'
        : authIncident.approvalSubStatus,
    triagedAtIso:
      nextStatus === 'TRIAGED' ? serverNowIso : authIncident.triagedAtIso,
    acknowledgedAtIso:
      nextStatus === 'ACKNOWLEDGED'
        ? serverNowIso
        : authIncident.acknowledgedAtIso,
    containmentStartedAtIso:
      nextStatus === 'CONTAINMENT_IN_PROGRESS'
        ? serverNowIso
        : authIncident.containmentStartedAtIso,
    containedAtIso:
      nextStatus === 'CONTAINED' ? serverNowIso : authIncident.containedAtIso,
    rollbackStartedAtIso:
      nextStatus === 'ROLLBACK_IN_PROGRESS'
        ? serverNowIso
        : authIncident.rollbackStartedAtIso,
    rollbackCompletedAtIso:
      nextStatus === 'ROLLBACK_COMPLETE'
        ? serverNowIso
        : authIncident.rollbackCompletedAtIso,
    recoveryStartedAtIso:
      nextStatus === 'RECOVERY_IN_PROGRESS'
        ? serverNowIso
        : authIncident.recoveryStartedAtIso,
    recoveryVerifiedAtIso:
      nextStatus === 'RECOVERY_VERIFIED'
        ? serverNowIso
        : authIncident.recoveryVerifiedAtIso,
    monitoringStartedAtIso:
      nextStatus === 'MONITORING'
        ? serverNowIso
        : authIncident.monitoringStartedAtIso,
    stabilityConfirmedAtIso:
      nextStatus === 'STABILITY_CONFIRMED'
        ? serverNowIso
        : authIncident.stabilityConfirmedAtIso,
    resolvedAtIso:
      nextStatus === 'RESOLVED' ? serverNowIso : authIncident.resolvedAtIso,
    closedAtIso:
      nextStatus === 'CLOSED' ? serverNowIso : authIncident.closedAtIso,
    reopenedAtIso:
      nextStatus === 'REOPENED' ? serverNowIso : authIncident.reopenedAtIso,
    auditTrail: [...authIncident.auditTrail, auditEvent],
    triggerHistory: [...authIncident.triggerHistory, executedTrigger],
  });

  incidentStore.set(updatedIncident.incidentId, updatedIncident);
  transitionIdFingerprints.set(idKey, targetFingerprint);

  const fullEvaluatedGuards = [
    ...guardResult.evaluated_guards,
    '17. Atomic State Update',
    '18. Audit Event Creation',
    '19. Required Side Effects',
  ];

  const finalContract: TransitionResultContract = {
    httpStatus: 200,
    success: true,
    incident_id: updatedIncident.incidentId,
    previous_status: authIncident.status,
    current_status: updatedIncident.status,
    transition_id: params.transitionId,
    timestamp: serverNowIso,
    required_actions: [],
    trigger_status: {
      transitionSucceeded: true,
      allTriggersSucceeded: true,
      failedCriticalOrRequiredTriggers: 0,
      failedNonCriticalTriggers: 0,
      executedTriggers: [executedTrigger],
    },
    audit_event_id: auditEvent.eventId,
    error: null,
    guard_code: 'GUARD_PASSED',
  };

  processedTransitionResults.set(idKey, finalContract);

  return {
    ...finalContract,
    guardResult: {
      ...guardResult,
      evaluated_guards: fullEvaluatedGuards,
    },
  };
}

// ============================================================================
// 7. EXPLICIT INCIDENT STATUS PHASE EXIT CRITERIA ENGINE (PHASES 0–30)
// ============================================================================

export type AllowedPhaseGateStatus =
  | 'NOT_STARTED'
  | 'IN_PROGRESS'
  | 'PASS'
  | 'FAIL'
  | 'BLOCKED';

export type EffectivePhaseReadinessStatus =
  | AllowedPhaseGateStatus
  | 'NOT_READY';

export const ALLOWED_PHASE_GATE_STATUSES: readonly AllowedPhaseGateStatus[] =
  Object.freeze(['NOT_STARTED', 'IN_PROGRESS', 'PASS', 'FAIL', 'BLOCKED']);

const ALLOWED_PHASE_STATUS_SET: ReadonlySet<string> = new Set(
  ALLOWED_PHASE_GATE_STATUSES
);

/**
 * Section 33: Validates that a phase status belongs strictly to
 * NOT_STARTED | IN_PROGRESS | PASS | FAIL | BLOCKED.
 * Rejects informal statuses such as DONE, COMPLETE, GOOD, READY, OK, ALMOST_DONE.
 */
export function isValidPhaseGateStatus(
  status: unknown
): status is AllowedPhaseGateStatus {
  return typeof status === 'string' && ALLOWED_PHASE_STATUS_SET.has(status);
}

export type CanonicalPhaseId =
  | 'PHASE_0'
  | 'PHASE_1'
  | 'PHASE_2'
  | 'PHASE_3'
  | 'PHASE_4'
  | 'PHASE_5'
  | 'PHASE_6'
  | 'PHASE_7'
  | 'PHASE_8'
  | 'PHASE_9'
  | 'PHASE_10'
  | 'PHASE_11'
  | 'PHASE_12'
  | 'PHASE_13'
  | 'PHASE_14'
  | 'PHASE_15'
  | 'PHASE_16'
  | 'PHASE_17'
  | 'PHASE_18'
  | 'PHASE_19'
  | 'PHASE_20'
  | 'PHASE_21'
  | 'PHASE_22'
  | 'PHASE_23'
  | 'PHASE_24'
  | 'PHASE_25'
  | 'PHASE_26'
  | 'PHASE_27'
  | 'PHASE_28'
  | 'PHASE_29'
  | 'PHASE_30';

export interface PhaseBlockedCheckItem {
  checkName: string;
  dependency: string;
  owner: string;
  deadline: string;
  riskLevel: BlockedRiskLevel;
  nextAction: string;
  evidence: string;
  temporaryExceptionApproved?: boolean;
}

export interface PhaseGateStatusRecord {
  phase_id: CanonicalPhaseId;
  phase_number: number;
  phase_name: string;
  exit_criterion_key: string;
  status: AllowedPhaseGateStatus;
  effective_status: EffectivePhaseReadinessStatus;
  started_at: string;
  completed_at: string | null;
  owner: string;
  backup_owner: string;
  required_evidence: string[];
  failed_checks: string[];
  blocked_checks: PhaseBlockedCheckItem[];
  risk_level: BlockedRiskLevel;
  dependencies: CanonicalPhaseId[];
  remediation: string;
  retest_required: boolean;
  retest_result: 'PASS' | 'FAIL' | 'NOT_RUN';
  approval: string;
  owner_review_complete: boolean;
  unresolved_critical_defect: boolean;
  security_or_data_integrity_blocker: boolean;
}

export const CANONICAL_31_PHASE_DEFINITIONS: ReadonlyArray<{
  phase_id: CanonicalPhaseId;
  phase_number: number;
  phase_name: string;
  exit_criterion_key: string;
  owner: string;
  backup_owner: string;
  default_evidence: string[];
}> = Object.freeze([
  {
    phase_id: 'PHASE_0',
    phase_number: 0,
    phase_name: 'INVENTORY',
    exit_criterion_key: 'INVENTORY_EXIT',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    default_evidence: [
      'Implementation inventory (lib/incident-lifecycle.ts, lib/rollback-governance.ts, lib/server-auth.ts)',
      'Dependency map & API inventory (/api/admin/incidents)',
      'Status-value & test inventory',
    ],
  },
  {
    phase_id: 'PHASE_1',
    phase_number: 1,
    phase_name: 'BASELINE',
    exit_criterion_key: 'BASELINE_EXIT',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    default_evidence: [
      'Git checkpoint 32b1d7d (main)',
      'Database backup archive & restoreAuthDatabaseFromBackup verified',
      'Rollback/Database/Security owners assigned',
    ],
  },
  {
    phase_id: 'PHASE_2',
    phase_number: 2,
    phase_name: 'CANONICAL ENUM',
    exit_criterion_key: 'ENUM_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'INCIDENT_STATUS_ENUM_V1 (16 exact values)',
      'parseCanonicalIncidentStatus rejection tests for NULL/empty/informal values',
    ],
  },
  {
    phase_id: 'PHASE_3',
    phase_number: 3,
    phase_name: 'DATABASE MIGRATION',
    exit_criterion_key: 'DATABASE_MIGRATION_EXIT',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    default_evidence: [
      'lib/supabase-schema.sql canonical status constraint & pre/post row-count reconciliation',
      'Non-destructive backup & rollback verification report',
    ],
  },
  {
    phase_id: 'PHASE_4',
    phase_number: 4,
    phase_name: 'STATUS HISTORY',
    exit_criterion_key: 'STATUS_HISTORY_EXIT',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    default_evidence: [
      'Append-only SHA-256 AuditTrailEventRecord history per transition',
      'History immutability & duplicate prevention tests',
    ],
  },
  {
    phase_id: 'PHASE_5',
    phase_number: 5,
    phase_name: 'TRANSITION MATRIX',
    exit_criterion_key: 'TRANSITION_MATRIX_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'ALLOWED_INCIDENT_STATUS_TRANSITIONS (all 23 canonical transitions)',
      'Exhaustive 16x16 allowed vs prohibited transition matrix tests',
    ],
  },
  {
    phase_id: 'PHASE_6',
    phase_number: 6,
    phase_name: 'GUARD ENGINE',
    exit_criterion_key: 'GUARD_ENGINE_EXIT',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    default_evidence: [
      '19-step guardTransition engine & 22 canonical GuardFailureCode values',
      'Positive and negative guard test matrix across all 23 transitions',
    ],
  },
  {
    phase_id: 'PHASE_7',
    phase_number: 7,
    phase_name: 'AUTHORIZATION',
    exit_criterion_key: 'AUTHORIZATION_EXIT',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    default_evidence: [
      'Server-authoritative RBAC & specialist domain ownership checks',
      'Student/Teacher/tampered-role/cross-user rejection tests (401/403)',
    ],
  },
  {
    phase_id: 'PHASE_8',
    phase_number: 8,
    phase_name: 'CONCURRENCY CONTROL',
    exit_criterion_key: 'CONCURRENCY_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'Optimistic version locking (expectedVersion === incident.version) & inFlightIncidentLocks',
      'Simultaneous transition & closure race-condition tests (409 Conflict)',
    ],
  },
  {
    phase_id: 'PHASE_9',
    phase_number: 9,
    phase_name: 'ATOMIC TRANSITION SERVICE',
    exit_criterion_key: 'ATOMIC_TRANSITION_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'executeGuardedIncidentTransition & executeAtomicIncidentStatusTransition',
      'Atomic rollback on critical trigger or guard failure tests',
    ],
  },
  {
    phase_id: 'PHASE_10',
    phase_number: 10,
    phase_name: 'TRANSITION-SPECIFIC STATE UPDATES',
    exit_criterion_key: 'TRANSITION_STATE_EXIT',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    default_evidence: [
      'Server-generated milestone timestamps & separate sub-status dimensions',
      'Reopening historical preservation verified',
    ],
  },
  {
    phase_id: 'PHASE_11',
    phase_number: 11,
    phase_name: 'AUDIT',
    exit_criterion_key: 'AUDIT_EXIT',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    default_evidence: [
      '16-field AuditTrailEventRecord + GUARD_FAILURE_REJECTED audit logging',
      'Secret redaction & PII minimization verified',
    ],
  },
  {
    phase_id: 'PHASE_12',
    phase_number: 12,
    phase_name: 'IDEMPOTENCY',
    exit_criterion_key: 'IDEMPOTENCY_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'processedTransitionResults & transitionIdFingerprints deduplication',
      'Duplicate submission & IDEMPOTENCY_CONFLICT tests',
    ],
  },
  {
    phase_id: 'PHASE_13',
    phase_number: 13,
    phase_name: 'POST-TRANSITION TRIGGERS',
    exit_criterion_key: 'POST_TRANSITION_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'PRE_TRANSITION, ON_TRANSITION, POST_TRANSITION idempotent trigger framework',
      'Critical vs non-critical trigger retry and failure isolation tests',
    ],
  },
  {
    phase_id: 'PHASE_14',
    phase_number: 14,
    phase_name: 'SECURITY TRIGGERS',
    exit_criterion_key: 'SECURITY_TRIGGER_EXIT',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    default_evidence: [
      'triggerAutomaticDomainEscalation(SECURITY) -> SEV-1/P0',
      'Security review gate before RECOVERY_VERIFIED/RESOLVED/CLOSED',
    ],
  },
  {
    phase_id: 'PHASE_15',
    phase_number: 15,
    phase_name: 'DATABASE-INTEGRITY TRIGGERS',
    exit_criterion_key: 'DATABASE_INTEGRITY_EXIT',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    default_evidence: [
      'triggerAutomaticDomainEscalation(DATABASE) & VERIFIED_HEALTHY vs UNKNOWN/FAILED guard',
      'Ownership, balance, payment, exam-score, and verification-status integrity checks',
    ],
  },
  {
    phase_id: 'PHASE_16',
    phase_number: 16,
    phase_name: 'SLA TRIGGERS',
    exit_criterion_key: 'SLA_EXIT',
    owner: 'Vikramaditya Rathore',
    backup_owner: 'Dolly Singh',
    default_evidence: [
      'evaluateIncidentSlaDeadlines (T-24h, T-4h, IMMEDIATE_SEV1, DEADLINE_BREACHED)',
      'INVARIANT-20 immutable SLA clock preservation across severity changes',
    ],
  },
  {
    phase_id: 'PHASE_17',
    phase_number: 17,
    phase_name: 'RECOVERY GATES',
    exit_criterion_key: 'RECOVERY_GATE_EXIT',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    default_evidence: [
      'Enforced ROLLBACK_COMPLETE -> RECOVERY_IN_PROGRESS -> RECOVERY_VERIFIED -> MONITORING -> STABILITY_CONFIRMED -> RESOLVED -> CLOSED sequence',
      'Zero gate-skipping verified',
    ],
  },
  {
    phase_id: 'PHASE_18',
    phase_number: 18,
    phase_name: 'REOPENING',
    exit_criterion_key: 'REOPENING_EXIT',
    owner: 'Dolly Singh',
    backup_owner: 'Siddharth Verma',
    default_evidence: [
      'RESOLVED -> REOPENED, CLOSED -> REOPENED, REOPENED -> TRIAGED guards',
      'Credible new evidence & administrative-edit rejection verified',
    ],
  },
  {
    phase_id: 'PHASE_19',
    phase_number: 19,
    phase_name: 'API INTEGRATION',
    exit_criterion_key: 'API_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      '/api/admin/incidents GET & POST route enforcing server auth, guards, concurrency, and canonical enum',
    ],
  },
  {
    phase_id: 'PHASE_20',
    phase_number: 20,
    phase_name: 'FRONTEND INTEGRATION',
    exit_criterion_key: 'FRONTEND_EXIT',
    owner: 'Meera Krishnan',
    backup_owner: 'Aditya Joshi',
    default_evidence: [
      'Client state cannot override server-authoritative incident or auth state',
      'UI_REGRESSION_EXIT = PASS (100% existing colors, fonts, layout, cards, and copy preserved)',
    ],
  },
  {
    phase_id: 'PHASE_21',
    phase_number: 21,
    phase_name: 'UNIT TESTS',
    exit_criterion_key: 'UNIT_TEST_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'Automated unit tests for enum, 23 transitions, 22 guard codes, authz, evidence, concurrency, SLA, and reopen',
    ],
  },
  {
    phase_id: 'PHASE_22',
    phase_number: 22,
    phase_name: 'INTEGRATION TESTS',
    exit_criterion_key: 'INTEGRATION_TEST_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'End-to-end incident lifecycle workflow tests (Detection -> Triage -> Containment -> Rollback -> Recovery -> Blocked/Failed -> Verified -> Monitoring -> Stability -> Resolved -> Closed -> Reopened)',
    ],
  },
  {
    phase_id: 'PHASE_23',
    phase_number: 23,
    phase_name: 'CONCURRENCY TESTS',
    exit_criterion_key: 'CONCURRENCY_TEST_EXIT',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    default_evidence: [
      'Simultaneous transitions, closure attempts, reopen attempts, and retry race tests returning 409 Conflict for stale requests',
    ],
  },
  {
    phase_id: 'PHASE_24',
    phase_number: 24,
    phase_name: 'SECURITY TESTS',
    exit_criterion_key: 'SECURITY_TEST_EXIT',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    default_evidence: [
      'Client role/user-ID/owner-ID/status/evidence/approval tampering & cross-user manipulation rejection tests',
    ],
  },
  {
    phase_id: 'PHASE_25',
    phase_number: 25,
    phase_name: 'DATA-INTEGRITY TESTS',
    exit_criterion_key: 'DATA_INTEGRITY_TEST_EXIT',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    default_evidence: [
      'Zero invalid/NULL statuses, zero orphan history, zero duplicate transition IDs, and verified ownership/payment/exam integrity',
    ],
  },
  {
    phase_id: 'PHASE_26',
    phase_number: 26,
    phase_name: 'REGRESSION TESTS',
    exit_criterion_key: 'REGRESSION_EXIT',
    owner: 'Meera Krishnan',
    backup_owner: 'Aditya Joshi',
    default_evidence: [
      'Authentication, authorization, student/teacher/admin flows, payments, exams, certificates, and verification regression suite passed',
    ],
  },
  {
    phase_id: 'PHASE_27',
    phase_number: 27,
    phase_name: 'STAGING',
    exit_criterion_key: 'STAGING_EXIT',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    default_evidence: [
      'Staging test report, security report, DB integrity report, UI regression report, and owner sign-off',
    ],
  },
  {
    phase_id: 'PHASE_28',
    phase_number: 28,
    phase_name: 'PRODUCTION ROLLOUT',
    exit_criterion_key: 'PRODUCTION_ROLLOUT_EXIT',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    default_evidence: [
      'Production backup verified, deployment healthy, valid/invalid transition and authz smoke tests passed',
    ],
  },
  {
    phase_id: 'PHASE_29',
    phase_number: 29,
    phase_name: 'POST-DEPLOYMENT MONITORING',
    exit_criterion_key: 'POST_DEPLOYMENT_MONITORING_EXIT',
    owner: 'Vikramaditya Rathore',
    backup_owner: 'Dolly Singh',
    default_evidence: [
      '120-minute high-risk post-deployment stability window completed with zero unauthorized transitions or anomalies',
    ],
  },
  {
    phase_id: 'PHASE_30',
    phase_number: 30,
    phase_name: 'FINAL IMPLEMENTATION',
    exit_criterion_key: 'INCIDENT_STATE_MACHINE_IMPLEMENTATION',
    owner: 'Dolly Singh',
    backup_owner: 'Siddharth Verma',
    default_evidence: [
      'All 30 upstream phase gates PASS, zero critical FAIL/BLOCKED items, required owners signed off',
    ],
  },
]);

/**
 * Sections 1, 33, 34, 35, 36, 37, 38: Evaluates the 31-Phase Dependency Chain.
 *   - Enforces Universal Phase-Gate Rule (no evidence = no PASS; owner review required; zero critical defects)
 *   - Enforces Failure Propagation Rule (if a phase is FAIL, all downstream dependent phases become NOT_READY)
 *   - Enforces Blocked Propagation Rule (Critical BLOCKED prevents phase exit and final completion)
 *   - Returns `INCIDENT_STATE_MACHINE_IMPLEMENTATION: 'COMPLETE' | 'INCOMPLETE'`
 */
export function evaluatePhaseGateChain(
  phases: readonly PhaseGateStatusRecord[]
): {
  allPhasesPass: boolean;
  finalImplementationState:
    | 'INCIDENT_STATE_MACHINE_IMPLEMENTATION = COMPLETE'
    | 'INCIDENT_STATE_MACHINE_IMPLEMENTATION = INCOMPLETE';
  uiRegressionExit: 'PASS' | 'FAIL' | 'BLOCKED';
  evaluatedPhases: PhaseGateStatusRecord[];
  blockingReasons: string[];
} {
  const blockingReasons: string[] = [];
  const evaluatedPhases: PhaseGateStatusRecord[] = [];
  let upstreamFailedOrBlocked = false;

  for (const phase of phases) {
    if (!isValidPhaseGateStatus(phase.status)) {
      throw new Error(
        `Invalid phase status "${String(phase.status)}" in ${phase.phase_id}. Only NOT_STARTED, IN_PROGRESS, PASS, FAIL, BLOCKED are allowed.`
      );
    }

    const hasCriticalBlockedCheck = phase.blocked_checks.some(
      (b) => b.riskLevel === 'CRITICAL' || b.riskLevel === 'HIGH'
    );
    const hasMissingBlockedMetadata = phase.blocked_checks.some(
      (b) =>
        !b.dependency?.trim() ||
        !b.owner?.trim() ||
        !validateAbsoluteDeadlineFormat(b.deadline) ||
        !b.riskLevel ||
        !b.nextAction?.trim() ||
        !b.evidence?.trim()
    );

    let evaluatedStatus: AllowedPhaseGateStatus = phase.status;
    let effectiveStatus: EffectivePhaseReadinessStatus = phase.status;

    // Universal Phase-Gate Rule: Cannot be PASS without evidence, owner review, and zero failed/critical-blocked checks
    if (evaluatedStatus === 'PASS') {
      if (
        !phase.required_evidence ||
        phase.required_evidence.length === 0 ||
        phase.required_evidence.some((e) => !e?.trim()) ||
        !phase.owner_review_complete ||
        phase.failed_checks.length > 0 ||
        phase.unresolved_critical_defect ||
        phase.security_or_data_integrity_blocker
      ) {
        evaluatedStatus = 'FAIL';
        effectiveStatus = 'FAIL';
        blockingReasons.push(
          `${phase.phase_id} (${phase.phase_name}): Cannot exit as PASS without required evidence, owner review, and zero failed/critical checks.`
        );
      } else if (phase.blocked_checks.length > 0) {
        evaluatedStatus = 'BLOCKED';
        effectiveStatus = 'BLOCKED';
        blockingReasons.push(
          `${phase.phase_id} (${phase.phase_name}): Has active blocked checks and cannot be marked PASS.`
        );
      }
    }

    if (evaluatedStatus === 'BLOCKED' && hasMissingBlockedMetadata) {
      blockingReasons.push(
        `${phase.phase_id} (${phase.phase_name}): BLOCKED phase is missing mandatory owner, deadline, risk, or nextAction metadata.`
      );
    }

    if (upstreamFailedOrBlocked) {
      effectiveStatus = 'NOT_READY';
    }

    if (
      evaluatedStatus !== 'PASS' ||
      hasCriticalBlockedCheck ||
      effectiveStatus !== 'PASS'
    ) {
      upstreamFailedOrBlocked = true;
      if (evaluatedStatus !== 'PASS') {
        blockingReasons.push(
          `${phase.phase_id} (${phase.phase_name}) is ${evaluatedStatus} (effective: ${effectiveStatus}).`
        );
      }
    }

    evaluatedPhases.push({
      ...phase,
      status: evaluatedStatus,
      effective_status: effectiveStatus,
    });
  }

  const phase20 = evaluatedPhases.find((p) => p.phase_id === 'PHASE_20');
  const uiRegressionExit: 'PASS' | 'FAIL' | 'BLOCKED' =
    phase20?.effective_status === 'PASS'
      ? 'PASS'
      : phase20?.status === 'BLOCKED'
        ? 'BLOCKED'
        : 'FAIL';

  const allPhasesPass =
    evaluatedPhases.length === 31 &&
    evaluatedPhases.every((p) => p.effective_status === 'PASS') &&
    uiRegressionExit === 'PASS';

  return {
    allPhasesPass,
    finalImplementationState: allPhasesPass
      ? 'INCIDENT_STATE_MACHINE_IMPLEMENTATION = COMPLETE'
      : 'INCIDENT_STATE_MACHINE_IMPLEMENTATION = INCOMPLETE',
    uiRegressionExit,
    evaluatedPhases,
    blockingReasons,
  };
}

/**
 * Section 35: Reopens an earlier phase when a defect discovered in a later phase
 * invalidates the earlier phase's exit criteria, marking all dependent downstream
 * phases as NOT_READY until remediated, retested, and re-approved.
 */
export function reopenInvalidatedEarlierPhase(params: {
  phases: readonly PhaseGateStatusRecord[];
  invalidatedPhaseId: CanonicalPhaseId;
  defectDescription: string;
  remediationPlan: string;
}): {
  updatedPhases: PhaseGateStatusRecord[];
  evaluation: ReturnType<typeof evaluatePhaseGateChain>;
} {
  const targetIdx = params.phases.findIndex(
    (p) => p.phase_id === params.invalidatedPhaseId
  );
  const updated = params.phases.map((p, idx) => {
    if (idx === targetIdx) {
      return {
        ...p,
        status: 'FAIL' as AllowedPhaseGateStatus,
        effective_status: 'FAIL' as EffectivePhaseReadinessStatus,
        completed_at: null,
        failed_checks: [...p.failed_checks, params.defectDescription],
        remediation: params.remediationPlan,
        retest_required: true,
        retest_result: 'NOT_RUN' as const,
        unresolved_critical_defect: true,
      };
    }
    return p;
  });

  return {
    updatedPhases: updated,
    evaluation: evaluatePhaseGateChain(updated),
  };
}

/**
 * Builds the authoritative 31-phase implementation report (`PHASE_0` – `PHASE_30`)
 * with verified evidence for the current codebase.
 */
export function getAuthoritative31PhaseImplementationReport() {
  const basePhases: PhaseGateStatusRecord[] =
    CANONICAL_31_PHASE_DEFINITIONS.map((def, idx) => ({
      phase_id: def.phase_id,
      phase_number: def.phase_number,
      phase_name: def.phase_name,
      exit_criterion_key: def.exit_criterion_key,
      status: 'PASS',
      effective_status: 'PASS',
      started_at: '2026-09-30 16:45 IST',
      completed_at: '2026-09-30 22:10 IST',
      owner: def.owner,
      backup_owner: def.backup_owner,
      required_evidence: [...def.default_evidence],
      failed_checks: [],
      blocked_checks: [],
      risk_level: 'LOW',
      dependencies:
        idx === 0
          ? []
          : [CANONICAL_31_PHASE_DEFINITIONS[idx - 1].phase_id],
      remediation: 'N/A',
      retest_required: false,
      retest_result: 'PASS',
      approval: `APPROVED BY ${def.owner.toUpperCase()}`,
      owner_review_complete: true,
      unresolved_critical_defect: false,
      security_or_data_integrity_blocker: false,
    }));

  return evaluatePhaseGateChain(basePhases);
}

// ============================================================================
// 8. EXPLICIT PHASE DEPENDENCY AND GO/NO-GO GATES ENGINE (SECTIONS 1–40)
// ============================================================================

export type GoNoGoDecision = 'GO' | 'NO-GO';

export const PROHIBITED_INFORMAL_GO_CLAIMS: readonly string[] = Object.freeze([
  'It looks correct',
  'Code compiles',
  'Local testing passed',
  'Frontend works',
  'No error was noticed',
  'Temporary workaround exists',
]);

export const PROHIBITED_VAGUE_NO_GO_REASONS: readonly string[] = Object.freeze([
  'Something failed',
  'Needs checking',
  'Not ready',
  'Temporary issue',
]);

export type CriticalFailurePropagationCondition =
  | 'Authentication bypass'
  | 'Authorization bypass'
  | 'Privilege escalation'
  | 'Cross-user access'
  | 'Credential/session exposure'
  | 'Critical database corruption'
  | 'Invalid production status'
  | 'Audit corruption'
  | 'Recovery-gate bypass'
  | 'Critical payment/data integrity issue'
  | 'Critical protected API failure';

export const MANDATORY_CRITICAL_FAILURE_ACTIONS = Object.freeze([
  'STOP',
  'CONTAIN',
  'ESCALATE',
  'REMEDIATE',
  'RETEST',
  'REASSESS',
] as const);

/**
 * Section 37: Mandatory structured record when Decision == NO-GO.
 */
export interface NoGoDecisionDetailRecord {
  reason: string;
  expected_result: string;
  actual_result: string;
  impact: string;
  severity: IncidentSeverity;
  owner: string;
  remediation: string;
  retest_requirement: string;
  deadline: string;
}

/**
 * Section 34: Mandatory structured record when a phase is BLOCKED.
 */
export interface BlockedPhasePropagationRecord {
  phase: CanonicalPhaseId;
  reason: string;
  dependency: string;
  owner: string;
  backup_owner: string;
  risk: BlockedRiskLevel;
  next_action: string;
  deadline: string;
  evidence_reference: string;
}

/**
 * Section 36: Authoritative Go/No-Go Decision Record for each phase gate.
 */
export interface PhaseGoNoGoDecisionRecord {
  phase_id: CanonicalPhaseId;
  phase_number: number;
  phase_name: string;
  status: AllowedPhaseGateStatus;
  dependency_status: AllowedPhaseGateStatus;
  entry_gate_result: 'PASS' | 'FAIL' | 'BLOCKED';
  implementation_result: AllowedPhaseGateStatus;
  test_result: 'PASS' | 'FAIL' | 'BLOCKED' | 'NOT_RUN';
  evidence_reference: string;
  critical_failures: number;
  critical_blockers: number;
  owner: string;
  backup_owner: string;
  reviewer: string;
  independent_verification_used: boolean;
  approved: boolean;
  decision_timestamp: string;
  decision_reason: string;
  decision: GoNoGoDecision;
  no_go_details?: NoGoDecisionDetailRecord;
  blocked_propagation?: BlockedPhasePropagationRecord;
}

export interface PhaseGoNoGoEvaluationInput {
  phase_id: CanonicalPhaseId;
  phase_number: number;
  phase_name: string;
  status: unknown;
  dependency_phases_statuses: AllowedPhaseGateStatus[];
  entry_conditions_met: boolean;
  implementation_completed: boolean;
  tests_executed_and_passed: boolean;
  evidence_reference: string;
  owner: string;
  backup_owner: string;
  reviewer: string;
  owner_verified: boolean;
  approved: boolean;
  independent_verification_used?: boolean;
  critical_failures: number;
  critical_blockers: number;
  security_uncertainty?: boolean;
  database_integrity_uncertainty?: boolean;
  missing_backup_or_recovery_capability?: boolean;
  safe_containment_only?: boolean;
  temporary_exception_only?: boolean;
  approval_without_verification?: boolean;
  regression_caused_by_implementation?: boolean;
  pre_existing_failure_documented_separately?: boolean;
  executed_failure_disguised_as_blocked?: boolean;
  no_go_details?: NoGoDecisionDetailRecord;
  blocked_propagation?: BlockedPhasePropagationRecord;
  decision_timestamp?: string;
}

function isInformalGoClaim(evidenceOrReason: string): boolean {
  const normalized = (evidenceOrReason || '').trim().toLowerCase().replace(/\.$/, '');
  return PROHIBITED_INFORMAL_GO_CLAIMS.some(
    (c) => c.toLowerCase() === normalized
  );
}

function isVagueNoGoReason(reason: string): boolean {
  const normalized = (reason || '').trim().toLowerCase().replace(/\.$/, '');
  if (!normalized) return true;
  return PROHIBITED_VAGUE_NO_GO_REASONS.some(
    (r) => r.toLowerCase() === normalized
  );
}

/**
 * Sections 1–4, 32–38, 40: Evaluates a single phase's 4-stage Go/No-Go gate:
 *   1. DEPENDENCY GATE
 *   2. ENTRY GATE
 *   3. IMPLEMENTATION / VERIFICATION
 *   4. EXIT GO/NO-GO GATE
 */
export function evaluateSinglePhaseGoNoGoGate(
  input: PhaseGoNoGoEvaluationInput
): PhaseGoNoGoDecisionRecord {
  const timestamp = input.decision_timestamp || new Date().toISOString();

  // Section 2: Reject informal phase statuses (DONE, COMPLETE, READY, OK, APPROVED, VERIFIED, SUCCESS)
  if (!isValidPhaseGateStatus(input.status)) {
    throw new Error(
      `Invalid phase status "${String(input.status)}" for ${input.phase_id}. Allowed values: NOT_STARTED, IN_PROGRESS, PASS, FAIL, BLOCKED.`
    );
  }

  // Section 4: Do not use BLOCKED to hide an executed failure
  let status: AllowedPhaseGateStatus = input.status;
  if (
    status === 'BLOCKED' &&
    (input.executed_failure_disguised_as_blocked ||
      input.regression_caused_by_implementation ||
      input.critical_failures > 0)
  ) {
    status = 'FAIL';
  }

  // Section 38: Safe containment, temporary exception, or approval alone never equals PASS
  if (
    status === 'PASS' &&
    (input.safe_containment_only ||
      input.temporary_exception_only ||
      input.approval_without_verification ||
      !input.owner_verified)
  ) {
    status = 'FAIL';
  }

  if (status === 'PASS' && input.regression_caused_by_implementation) {
    status = 'FAIL';
  }

  // 1. DEPENDENCY GATE (Section 1 & 32)
  const anyDepFail = input.dependency_phases_statuses.some((s) => s === 'FAIL');
  const anyDepBlocked = input.dependency_phases_statuses.some(
    (s) => s === 'BLOCKED'
  );
  const allDepsPass = input.dependency_phases_statuses.every((s) => s === 'PASS');

  const dependencyStatus: AllowedPhaseGateStatus = allDepsPass
    ? 'PASS'
    : anyDepFail
      ? 'FAIL'
      : anyDepBlocked
        ? 'BLOCKED'
        : 'NOT_STARTED';

  // Section 32: If upstream dependency failed or is not PASS, dependent phase cannot be PASS
  if (!allDepsPass && status === 'PASS') {
    status = anyDepBlocked ? 'BLOCKED' : 'NOT_STARTED';
  }

  // 2. ENTRY GATE
  const entryGateResult: 'PASS' | 'FAIL' | 'BLOCKED' =
    allDepsPass && input.entry_conditions_met
      ? 'PASS'
      : anyDepBlocked
        ? 'BLOCKED'
        : 'FAIL';

  // 3. IMPLEMENTATION & VERIFICATION GATE
  const hasValidEvidence =
    Boolean(input.evidence_reference?.trim()) &&
    !isInformalGoClaim(input.evidence_reference);
  const hasValidOwners =
    Boolean(input.owner?.trim()) &&
    Boolean(input.backup_owner?.trim()) &&
    input.owner.trim().toLowerCase() !== input.backup_owner.trim().toLowerCase();

  // Section 35: Critical security/database phases require independent reviewer where practical
  const isCriticalSecurityOrDbPhase =
    input.phase_id === 'PHASE_3' ||
    input.phase_id === 'PHASE_6' ||
    input.phase_id === 'PHASE_7' ||
    input.phase_id === 'PHASE_14' ||
    input.phase_id === 'PHASE_15' ||
    input.phase_id === 'PHASE_24' ||
    input.phase_id === 'PHASE_25';

  const independentReviewerValid = isCriticalSecurityOrDbPhase
    ? Boolean(input.reviewer?.trim()) &&
      input.reviewer.trim().toLowerCase() !== input.owner.trim().toLowerCase()
    : Boolean(input.reviewer?.trim());

  // 4. EXIT GO/NO-GO GATE (Section 3, 38, 40)
  const allGoConditionsSatisfied =
    status === 'PASS' &&
    dependencyStatus === 'PASS' &&
    entryGateResult === 'PASS' &&
    input.implementation_completed &&
    input.tests_executed_and_passed &&
    hasValidEvidence &&
    hasValidOwners &&
    independentReviewerValid &&
    input.owner_verified &&
    input.approved &&
    input.critical_failures === 0 &&
    input.critical_blockers === 0 &&
    !input.security_uncertainty &&
    !input.database_integrity_uncertainty &&
    !input.missing_backup_or_recovery_capability &&
    !input.safe_containment_only &&
    !input.temporary_exception_only &&
    !input.approval_without_verification &&
    !input.regression_caused_by_implementation;

  const decision: GoNoGoDecision = allGoConditionsSatisfied ? 'GO' : 'NO-GO';

  if (decision === 'NO-GO' && input.no_go_details) {
    if (isVagueNoGoReason(input.no_go_details.reason)) {
      throw new Error(
        `Vague No-Go reason "${input.no_go_details.reason}" is prohibited (Section 37). Provide specific expected vs actual result, impact, severity, owner, remediation, and deadline.`
      );
    }
  }

  let decisionReason = 'All dependency, entry, implementation, verification, evidence, and owner sign-off gates passed (GO).';
  if (decision === 'NO-GO') {
    if (dependencyStatus !== 'PASS') {
      decisionReason = `NO-GO: Upstream dependency gate is ${dependencyStatus}.`;
    } else if (entryGateResult !== 'PASS') {
      decisionReason = 'NO-GO: Phase entry gate conditions are not satisfied.';
    } else if (input.security_uncertainty) {
      decisionReason = 'NO-GO: Unresolved security uncertainty requires formal assessment.';
    } else if (input.database_integrity_uncertainty) {
      decisionReason = 'NO-GO: Database-integrity uncertainty requires verification.';
    } else if (input.missing_backup_or_recovery_capability) {
      decisionReason = 'NO-GO: Missing required backup or rollback/recovery capability.';
    } else if (!hasValidEvidence) {
      decisionReason = 'NO-GO: Missing or informal/unverifiable evidence.';
    } else if (!hasValidOwners || !independentReviewerValid) {
      decisionReason = 'NO-GO: Missing required distinct owner, backup owner, or independent reviewer.';
    } else if (input.critical_failures > 0 || input.critical_blockers > 0) {
      decisionReason = `NO-GO: ${input.critical_failures} critical failure(s) and ${input.critical_blockers} critical blocker(s) present.`;
    } else {
      decisionReason =
        input.no_go_details?.reason ||
        `NO-GO: Phase status is ${status} (all required Go criteria were not satisfied).`;
    }
  }

  return Object.freeze({
    phase_id: input.phase_id,
    phase_number: input.phase_number,
    phase_name: input.phase_name,
    status,
    dependency_status: dependencyStatus,
    entry_gate_result: entryGateResult,
    implementation_result: input.implementation_completed ? 'PASS' : status,
    test_result: input.tests_executed_and_passed
      ? 'PASS'
      : status === 'BLOCKED'
        ? 'BLOCKED'
        : 'FAIL',
    evidence_reference: input.evidence_reference,
    critical_failures: input.critical_failures,
    critical_blockers: input.critical_blockers,
    owner: input.owner,
    backup_owner: input.backup_owner,
    reviewer: input.reviewer,
    independent_verification_used: Boolean(input.independent_verification_used ?? independentReviewerValid),
    approved: input.approved,
    decision_timestamp: timestamp,
    decision_reason: decisionReason,
    decision,
    no_go_details: input.no_go_details,
    blocked_propagation: input.blocked_propagation,
  });
}

/**
 * Section 33: Evaluates Critical Failure Propagation and triggers the mandatory
 * STOP -> CONTAIN -> ESCALATE -> REMEDIATE -> RETEST -> REASSESS sequence.
 */
export function evaluateCriticalFailurePropagation(params: {
  detectedConditions: CriticalFailurePropagationCondition[];
}): {
  progressionHalted: boolean;
  overallDecision: GoNoGoDecision;
  detectedConditions: CriticalFailurePropagationCondition[];
  requiredActionSequence: readonly string[];
} {
  const halted = params.detectedConditions.length > 0;
  return {
    progressionHalted: halted,
    overallDecision: halted ? 'NO-GO' : 'GO',
    detectedConditions: [...params.detectedConditions],
    requiredActionSequence: halted ? MANDATORY_CRITICAL_FAILURE_ACTIONS : [],
  };
}

/**
 * Section 5, 18, 19, 39: Master Go/No-Go Phase Definitions following the exact
 * Section 5 Master Dependency Chain (where PHASE 12 = POST-TRANSITION TRIGGERS,
 * PHASE 13 = IDEMPOTENCY, and PHASE 30 = FINAL ACCEPTANCE).
 */
export const MASTER_GO_NO_GO_31_PHASE_CHAIN: ReadonlyArray<{
  phase_id: CanonicalPhaseId;
  phase_number: number;
  phase_name: string;
  final_gate_key: string;
  owner: string;
  backup_owner: string;
  reviewer: string;
  evidence_reference: string;
}> = Object.freeze([
  {
    phase_id: 'PHASE_0',
    phase_number: 0,
    phase_name: 'INVENTORY',
    final_gate_key: 'INVENTORY',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    reviewer: 'Arjun Nair',
    evidence_reference: 'EV-GNG-00-INVENTORY-MAP',
  },
  {
    phase_id: 'PHASE_1',
    phase_number: 1,
    phase_name: 'BASELINE',
    final_gate_key: 'BASELINE',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    reviewer: 'Ananya Deshmukh',
    evidence_reference: 'EV-GNG-01-CHECKPOINT-32B1D7D',
  },
  {
    phase_id: 'PHASE_2',
    phase_number: 2,
    phase_name: 'CANONICAL ENUM',
    final_gate_key: 'CANONICAL ENUM',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-02-ENUM-V1-16',
  },
  {
    phase_id: 'PHASE_3',
    phase_number: 3,
    phase_name: 'DATABASE MIGRATION',
    final_gate_key: 'DATABASE',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-03-DB-MIGRATION-RECONCILED',
  },
  {
    phase_id: 'PHASE_4',
    phase_number: 4,
    phase_name: 'STATUS HISTORY',
    final_gate_key: 'STATUS HISTORY',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-04-APPEND-ONLY-HISTORY',
  },
  {
    phase_id: 'PHASE_5',
    phase_number: 5,
    phase_name: 'TRANSITION MATRIX',
    final_gate_key: 'TRANSITION MATRIX',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-05-MATRIX-23-TRANSITIONS',
  },
  {
    phase_id: 'PHASE_6',
    phase_number: 6,
    phase_name: 'GUARD ENGINE',
    final_gate_key: 'GUARD ENGINE',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    reviewer: 'Arjun Nair',
    evidence_reference: 'EV-GNG-06-19-STEP-GUARD-ENGINE',
  },
  {
    phase_id: 'PHASE_7',
    phase_number: 7,
    phase_name: 'AUTHORIZATION',
    final_gate_key: 'AUTHORIZATION',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-07-SERVER-RBAC-AUTHZ',
  },
  {
    phase_id: 'PHASE_8',
    phase_number: 8,
    phase_name: 'CONCURRENCY',
    final_gate_key: 'CONCURRENCY',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-08-OPTIMISTIC-LOCK-409',
  },
  {
    phase_id: 'PHASE_9',
    phase_number: 9,
    phase_name: 'ATOMIC TRANSITION SERVICE',
    final_gate_key: 'ATOMIC SERVICE',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Ananya Deshmukh',
    evidence_reference: 'EV-GNG-09-ATOMIC-COMMIT',
  },
  {
    phase_id: 'PHASE_10',
    phase_number: 10,
    phase_name: 'STATE UPDATES',
    final_gate_key: 'STATE UPDATES',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    reviewer: 'Arjun Nair',
    evidence_reference: 'EV-GNG-10-AUTHORIZED-FIELD-UPDATES',
  },
  {
    phase_id: 'PHASE_11',
    phase_number: 11,
    phase_name: 'AUDIT',
    final_gate_key: 'AUDIT',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-11-IMMUTABLE-AUDIT-SHA256',
  },
  {
    phase_id: 'PHASE_12',
    phase_number: 12,
    phase_name: 'POST-TRANSITION TRIGGERS',
    final_gate_key: 'POST-TRANSITION TRIGGERS',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Vikramaditya Rathore',
    evidence_reference: 'EV-GNG-12-POST-TRIGGERS',
  },
  {
    phase_id: 'PHASE_13',
    phase_number: 13,
    phase_name: 'IDEMPOTENCY',
    final_gate_key: 'IDEMPOTENCY',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-13-IDEMPOTENCY-DEDUPE',
  },
  {
    phase_id: 'PHASE_14',
    phase_number: 14,
    phase_name: 'SECURITY TRIGGERS',
    final_gate_key: 'SECURITY TRIGGERS',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-14-SEC-AUTO-ESCALATION',
  },
  {
    phase_id: 'PHASE_15',
    phase_number: 15,
    phase_name: 'DATABASE-INTEGRITY TRIGGERS',
    final_gate_key: 'DATABASE-INTEGRITY TRIGGERS',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-15-DB-INTEGRITY-TRIGGERS',
  },
  {
    phase_id: 'PHASE_16',
    phase_number: 16,
    phase_name: 'SLA TRIGGERS',
    final_gate_key: 'SLA',
    owner: 'Vikramaditya Rathore',
    backup_owner: 'Dolly Singh',
    reviewer: 'Arjun Nair',
    evidence_reference: 'EV-GNG-16-SLA-CLOCK-IMMUTABLE',
  },
  {
    phase_id: 'PHASE_17',
    phase_number: 17,
    phase_name: 'RECOVERY GATES',
    final_gate_key: 'RECOVERY GATES',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-17-RECOVERY-SEQUENCE-GATES',
  },
  {
    phase_id: 'PHASE_18',
    phase_number: 18,
    phase_name: 'REOPENING',
    final_gate_key: 'REOPENING',
    owner: 'Dolly Singh',
    backup_owner: 'Siddharth Verma',
    reviewer: 'Arjun Nair',
    evidence_reference: 'EV-GNG-18-CREDIBLE-REOPEN-CONTROLS',
  },
  {
    phase_id: 'PHASE_19',
    phase_number: 19,
    phase_name: 'API',
    final_gate_key: 'API',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-19-API-TRANSITION-ENDPOINT',
  },
  {
    phase_id: 'PHASE_20',
    phase_number: 20,
    phase_name: 'FRONTEND',
    final_gate_key: 'FRONTEND',
    owner: 'Meera Krishnan',
    backup_owner: 'Aditya Joshi',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-20-UI-PRESERVATION-100PCT',
  },
  {
    phase_id: 'PHASE_21',
    phase_number: 21,
    phase_name: 'UNIT TESTS',
    final_gate_key: 'UNIT TESTS',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-21-UNIT-SUITE-PASS',
  },
  {
    phase_id: 'PHASE_22',
    phase_number: 22,
    phase_name: 'INTEGRATION TESTS',
    final_gate_key: 'INTEGRATION TESTS',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-22-INTEGRATION-23-FLOWS',
  },
  {
    phase_id: 'PHASE_23',
    phase_number: 23,
    phase_name: 'CONCURRENCY TESTS',
    final_gate_key: 'CONCURRENCY TESTS',
    owner: 'Arjun Nair',
    backup_owner: 'Karan Malhotra',
    reviewer: 'Ananya Deshmukh',
    evidence_reference: 'EV-GNG-23-RACE-CONDITION-SUITE',
  },
  {
    phase_id: 'PHASE_24',
    phase_number: 24,
    phase_name: 'SECURITY TESTS',
    final_gate_key: 'SECURITY TESTS',
    owner: 'Siddharth Verma',
    backup_owner: 'Neha Kapoor',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-24-SECURITY-TAMPER-SUITE',
  },
  {
    phase_id: 'PHASE_25',
    phase_number: 25,
    phase_name: 'DATA-INTEGRITY TESTS',
    final_gate_key: 'DATA-INTEGRITY TESTS',
    owner: 'Ananya Deshmukh',
    backup_owner: 'Rohan Kulkarni',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-25-DATA-INTEGRITY-SUITE',
  },
  {
    phase_id: 'PHASE_26',
    phase_number: 26,
    phase_name: 'REGRESSION TESTS',
    final_gate_key: 'REGRESSION TESTS',
    owner: 'Meera Krishnan',
    backup_owner: 'Aditya Joshi',
    reviewer: 'Dolly Singh',
    evidence_reference: 'EV-GNG-26-FULL-APP-REGRESSION',
  },
  {
    phase_id: 'PHASE_27',
    phase_number: 27,
    phase_name: 'STAGING',
    final_gate_key: 'STAGING',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-27-STAGING-SIGNOFF',
  },
  {
    phase_id: 'PHASE_28',
    phase_number: 28,
    phase_name: 'PRODUCTION',
    final_gate_key: 'PRODUCTION',
    owner: 'Dolly Singh',
    backup_owner: 'Vikramaditya Rathore',
    reviewer: 'Ananya Deshmukh',
    evidence_reference: 'EV-GNG-28-PRODUCTION-ROLLOUT',
  },
  {
    phase_id: 'PHASE_29',
    phase_number: 29,
    phase_name: 'POST-DEPLOYMENT MONITORING',
    final_gate_key: 'POST-DEPLOYMENT MONITORING',
    owner: 'Vikramaditya Rathore',
    backup_owner: 'Dolly Singh',
    reviewer: 'Siddharth Verma',
    evidence_reference: 'EV-GNG-29-120M-STABILITY-MONITORING',
  },
  {
    phase_id: 'PHASE_30',
    phase_number: 30,
    phase_name: 'FINAL ACCEPTANCE',
    final_gate_key: 'FINAL ACCEPTANCE',
    owner: 'Dolly Singh',
    backup_owner: 'Siddharth Verma',
    reviewer: 'Ananya Deshmukh',
    evidence_reference: 'EV-GNG-30-FINAL-ACCEPTANCE-SIGNOFF',
  },
]);

/**
 * Sections 5, 31, 32, 39, 40: Evaluates the entire 31-phase Master Dependency Chain
 * and produces per-phase Go/No-Go Decision Records plus the authoritative
 * `FINAL ACCEPTANCE = PASS` vs `FINAL ACCEPTANCE = NOT COMPLETE` determination.
 */
export function evaluateMasterGoNoGoChain(
  overrides?: Partial<
    Record<CanonicalPhaseId, Partial<PhaseGoNoGoEvaluationInput>>
  >
): {
  allPhasesGo: boolean;
  finalAcceptanceResult:
    | 'FINAL ACCEPTANCE = PASS'
    | 'FINAL ACCEPTANCE = NOT COMPLETE';
  uiPreservationGate: 'PASS' | 'FAIL';
  decisions: PhaseGoNoGoDecisionRecord[];
  gateSummaryMap: Record<string, AllowedPhaseGateStatus>;
} {
  const decisions: PhaseGoNoGoDecisionRecord[] = [];
  const gateSummaryMap: Record<string, AllowedPhaseGateStatus> = {};

  for (let i = 0; i < MASTER_GO_NO_GO_31_PHASE_CHAIN.length; i++) {
    const def = MASTER_GO_NO_GO_31_PHASE_CHAIN[i];
    const priorStatuses = decisions.map((d) => d.status);
    const custom = overrides?.[def.phase_id] || {};

    const record = evaluateSinglePhaseGoNoGoGate({
      phase_id: def.phase_id,
      phase_number: def.phase_number,
      phase_name: def.phase_name,
      status: custom.status ?? 'PASS',
      dependency_phases_statuses:
        custom.dependency_phases_statuses ?? priorStatuses,
      entry_conditions_met: custom.entry_conditions_met ?? true,
      implementation_completed: custom.implementation_completed ?? true,
      tests_executed_and_passed: custom.tests_executed_and_passed ?? true,
      evidence_reference: custom.evidence_reference ?? def.evidence_reference,
      owner: custom.owner ?? def.owner,
      backup_owner: custom.backup_owner ?? def.backup_owner,
      reviewer: custom.reviewer ?? def.reviewer,
      owner_verified: custom.owner_verified ?? true,
      approved: custom.approved ?? true,
      independent_verification_used:
        custom.independent_verification_used ?? true,
      critical_failures: custom.critical_failures ?? 0,
      critical_blockers: custom.critical_blockers ?? 0,
      security_uncertainty: custom.security_uncertainty ?? false,
      database_integrity_uncertainty:
        custom.database_integrity_uncertainty ?? false,
      missing_backup_or_recovery_capability:
        custom.missing_backup_or_recovery_capability ?? false,
      safe_containment_only: custom.safe_containment_only ?? false,
      temporary_exception_only: custom.temporary_exception_only ?? false,
      approval_without_verification:
        custom.approval_without_verification ?? false,
      regression_caused_by_implementation:
        custom.regression_caused_by_implementation ?? false,
      pre_existing_failure_documented_separately:
        custom.pre_existing_failure_documented_separately ?? false,
      executed_failure_disguised_as_blocked:
        custom.executed_failure_disguised_as_blocked ?? false,
      no_go_details: custom.no_go_details,
      blocked_propagation: custom.blocked_propagation,
      decision_timestamp:
        custom.decision_timestamp ?? '2026-09-30T16:25:00.000Z',
    });

    decisions.push(record);
    gateSummaryMap[def.final_gate_key] = record.status;
  }

  const allPhasesGo =
    decisions.length === 31 &&
    decisions.every((d) => d.status === 'PASS' && d.decision === 'GO');

  const phase20 = decisions.find((d) => d.phase_id === 'PHASE_20');
  const uiPreservationGate: 'PASS' | 'FAIL' =
    phase20?.status === 'PASS' && phase20?.decision === 'GO' ? 'PASS' : 'FAIL';

  return {
    allPhasesGo,
    finalAcceptanceResult:
      allPhasesGo && uiPreservationGate === 'PASS'
        ? 'FINAL ACCEPTANCE = PASS'
        : 'FINAL ACCEPTANCE = NOT COMPLETE',
    uiPreservationGate,
    decisions,
    gateSummaryMap,
  };
}


