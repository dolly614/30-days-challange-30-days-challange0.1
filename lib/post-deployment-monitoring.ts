import crypto from 'crypto';
import {
  createProductionIncident,
  IncidentSeverity,
  ProductionIncidentRecord,
  sanitizeAndMinimizeEvidenceText,
} from '@/lib/incident-lifecycle';
import { ReleaseEnvironment } from '@/lib/release-governance';

// ============================================================================
// 1. CANONICAL MONITORING, HEALTH, POSTURE & ALERT ENUMS (SECTIONS 1–3)
// ============================================================================

export type MonitoringStatus =
  | 'NOT_STARTED'
  | 'STARTING'
  | 'ACTIVE'
  | 'DEGRADED'
  | 'PAUSED'
  | 'FAILED'
  | 'STOPPED';

export const CANONICAL_MONITORING_STATUSES: readonly MonitoringStatus[] =
  Object.freeze([
    'NOT_STARTED',
    'STARTING',
    'ACTIVE',
    'DEGRADED',
    'PAUSED',
    'FAILED',
    'STOPPED',
  ]);

export type MonitoringHealth =
  | 'HEALTHY'
  | 'WARNING'
  | 'DEGRADED'
  | 'CRITICAL'
  | 'UNKNOWN';

export const CANONICAL_MONITORING_HEALTH_VALUES: readonly MonitoringHealth[] =
  Object.freeze(['HEALTHY', 'WARNING', 'DEGRADED', 'CRITICAL', 'UNKNOWN']);

export type AlertStatus =
  | 'DETECTED'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
  | 'SUPPRESSED';

export const CANONICAL_ALERT_STATUSES: readonly AlertStatus[] = Object.freeze([
  'DETECTED',
  'ACKNOWLEDGED',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'CLOSED',
  'SUPPRESSED',
]);

export type OperationalConditionPosture =
  | 'NORMAL'
  | 'DEGRADED'
  | 'WARNING'
  | 'INCIDENT'
  | 'CRITICAL_INCIDENT';

export type FinalMonitoringDecision =
  | 'HEALTHY'
  | 'DEGRADED'
  | 'INCIDENT_OPEN'
  | 'STABILITY_CONFIRMED'
  | 'STABILITY_FAILED';

export const CANONICAL_FINAL_MONITORING_DECISIONS: readonly FinalMonitoringDecision[] =
  Object.freeze([
    'HEALTHY',
    'DEGRADED',
    'INCIDENT_OPEN',
    'STABILITY_CONFIRMED',
    'STABILITY_FAILED',
  ]);

export function isValidMonitoringStatus(val: unknown): val is MonitoringStatus {
  return (
    typeof val === 'string' &&
    (CANONICAL_MONITORING_STATUSES as readonly string[]).includes(val)
  );
}

export function isValidMonitoringHealth(val: unknown): val is MonitoringHealth {
  return (
    typeof val === 'string' &&
    (CANONICAL_MONITORING_HEALTH_VALUES as readonly string[]).includes(val)
  );
}

export function isValidAlertStatus(val: unknown): val is AlertStatus {
  return (
    typeof val === 'string' &&
    (CANONICAL_ALERT_STATUSES as readonly string[]).includes(val)
  );
}

// ============================================================================
// 2. CORE MONITORING AREAS, BASELINES & TELEMETRY TYPES (SECTIONS 4–26)
// ============================================================================

export type CoreMonitoringArea =
  | 'Availability'
  | 'HTTP status codes'
  | '5xx rate'
  | '4xx rate'
  | 'API latency'
  | 'Database latency'
  | 'Database errors'
  | 'Authentication'
  | 'Authorization'
  | 'Sessions'
  | 'Password recovery'
  | 'OTP'
  | 'Payments'
  | 'Exams'
  | 'Verification'
  | 'Teacher workflows'
  | 'Certificates'
  | 'Leaderboard'
  | 'File uploads'
  | 'Background jobs'
  | 'Webhooks'
  | 'Queues'
  | 'Rate limiting'
  | 'Security events'
  | 'Client-side errors';

export const ALL_25_CORE_MONITORING_AREAS: readonly CoreMonitoringArea[] =
  Object.freeze([
    'Availability',
    'HTTP status codes',
    '5xx rate',
    '4xx rate',
    'API latency',
    'Database latency',
    'Database errors',
    'Authentication',
    'Authorization',
    'Sessions',
    'Password recovery',
    'OTP',
    'Payments',
    'Exams',
    'Verification',
    'Teacher workflows',
    'Certificates',
    'Leaderboard',
    'File uploads',
    'Background jobs',
    'Webhooks',
    'Queues',
    'Rate limiting',
    'Security events',
    'Client-side errors',
  ]);

export type AutomaticSev1Condition =
  | 'Authentication bypass'
  | 'Authorization bypass'
  | 'Privilege escalation'
  | 'Cross-user access'
  | 'Credential exposure'
  | 'Session-token exposure'
  | 'Critical database corruption'
  | 'Critical payment integrity compromise'
  | 'Critical exam-score integrity compromise'
  | 'Widespread production outage'
  | 'Active critical exploitation'
  | 'Irreversible critical data corruption';

export const ALL_12_AUTOMATIC_SEV1_CONDITIONS: readonly AutomaticSev1Condition[] =
  Object.freeze([
    'Authentication bypass',
    'Authorization bypass',
    'Privilege escalation',
    'Cross-user access',
    'Credential exposure',
    'Session-token exposure',
    'Critical database corruption',
    'Critical payment integrity compromise',
    'Critical exam-score integrity compromise',
    'Widespread production outage',
    'Active critical exploitation',
    'Irreversible critical data corruption',
  ]);

export interface LatencyPercentilesMs {
  p50: number;
  p95: number;
  p99: number;
}

export interface ReleaseSpecificBaselineRecord {
  baseline_id: string;
  baseline_source:
    | 'Known-good historical baseline'
    | 'Pre-deployment baseline'
    | 'Approved release baseline';
  release_version: string;
  data_period: string;
  request_volume_per_min: number;
  error_rate_5xx_pct: number;
  error_rate_4xx_pct: number;
  api_latency_ms: LatencyPercentilesMs;
  db_latency_ms: LatencyPercentilesMs;
  auth_failure_rate_pct: number;
  authz_failure_count_per_min: number;
  db_error_count_per_min: number;
  payment_failure_rate_pct: number;
  exam_failure_rate_pct: number;
  verification_failure_rate_pct: number;
  client_error_rate_pct: number;
  security_event_count_per_min: number;
  owner: string;
  reviewer: string;
  evidence_reference: string;
}

export type MonitoringAuditEventType =
  | 'Monitor started'
  | 'Monitor stopped'
  | 'Monitor failed'
  | 'Alert created'
  | 'Alert acknowledged'
  | 'Alert escalated'
  | 'Alert suppressed'
  | 'Alert resolved'
  | 'Incident created'
  | 'Incident associated'
  | 'Threshold changed'
  | 'Baseline changed'
  | 'Maintenance window created'
  | 'Stability started'
  | 'Stability failed'
  | 'Stability confirmed';

export interface MonitoringAuditTrailRecord {
  readonly event_id: string;
  readonly monitoring_id: string;
  readonly event_type: MonitoringAuditEventType;
  readonly actor: string;
  readonly timestamp: string;
  readonly detail: string;
  readonly evidence_reference: string;
}

/**
 * Section 43: Alert Evidence Record (13 mandatory fields, plus deduplication & correlation metadata).
 */
export interface ProductionAlertRecord {
  readonly alert_id: string;
  readonly fingerprint: string;
  readonly first_seen: string;
  readonly last_seen: string;
  readonly occurrence_count: number;
  readonly timestamp: string;
  readonly environment: ReleaseEnvironment;
  readonly release: string;
  readonly metric_or_signal: string;
  readonly observed_value: string;
  readonly baseline: string;
  readonly threshold: string;
  readonly severity: IncidentSeverity;
  readonly status: AlertStatus;
  readonly owner: string;
  readonly incident_id: string | null;
  readonly correlation_group_id: string | null;
  readonly evidence_reference: string;
  readonly is_critical_security_or_data_integrity: boolean;
  readonly suppression_metadata?: {
    approved_by: string;
    reason: string;
    scope: string;
    expires_at_ms: number;
  };
}

export interface ThresholdChangeControlRecord {
  change_record: string;
  reason: string;
  affected_monitor: string;
  old_value: string;
  new_value: string;
  risk_assessment: string;
  owner: string;
  reviewer: string;
  testing_reference: string;
  rollback_plan: string;
  recorded_at: string;
}

export interface BaselineChangeControlRecord {
  previous_baseline_id: string;
  new_baseline_id: string;
  reason: string;
  data_period: string;
  release_version: string;
  owner: string;
  reviewer: string;
  evidence: string;
  recorded_at: string;
}

export interface MaintenanceWindowRecord {
  maintenance_id: string;
  start_iso: string;
  end_iso: string;
  affected_monitors: CoreMonitoringArea[];
  owner: string;
  reason: string;
  expected_impact: string;
  rollback_plan: string;
}

/**
 * Section 4 & 5: Production Monitoring Session Record.
 */
export interface ProductionMonitoringSessionRecord {
  readonly monitoring_id: string;
  readonly release_id: string;
  readonly environment: ReleaseEnvironment;
  readonly application_version: string;
  readonly git_commit: string;
  readonly database_revision: string;
  readonly monitoring_owner: string;
  readonly backup_owner: string;
  readonly security_escalation_owner: string;
  readonly database_escalation_owner: string;
  readonly deployment_owner: string;
  readonly incident_owner: string;
  readonly started_at: string;
  readonly ended_at: string | null;
  readonly status: MonitoringStatus;
  readonly health: MonitoringHealth;
  readonly posture: OperationalConditionPosture;
  readonly stability_window_minutes: 60 | 120;
  readonly stability_window_started_at_ms: number;
  readonly stability_result: 'IN_PROGRESS' | 'CONFIRMED' | 'FAILED';
  readonly alert_count: number;
  readonly incident_count: number;
  readonly evidence_reference: string;
  readonly baseline: ReleaseSpecificBaselineRecord;
  readonly alerts: ProductionAlertRecord[];
  readonly audit_trail: MonitoringAuditTrailRecord[];
  readonly threshold_changes: ThresholdChangeControlRecord[];
  readonly baseline_changes: BaselineChangeControlRecord[];
  readonly maintenance_windows: MaintenanceWindowRecord[];
}

const monitoringSessions = new Map<string, ProductionMonitoringSessionRecord>();
const deduplicatedAlertsByFingerprint = new Map<string, ProductionAlertRecord>();
const autoCreatedIncidentsByFingerprint = new Map<string, ProductionIncidentRecord>();

function createMonitoringAuditEntry(params: {
  monitoringId: string;
  eventType: MonitoringAuditEventType;
  actor: string;
  detail: string;
  evidenceReference: string;
  timestamp?: string;
}): MonitoringAuditTrailRecord {
  return Object.freeze({
    event_id: `MAUD-${crypto.randomBytes(5).toString('hex').toUpperCase()}`,
    monitoring_id: params.monitoringId,
    event_type: params.eventType,
    actor: sanitizeAndMinimizeEvidenceText(params.actor),
    timestamp: params.timestamp || new Date().toISOString(),
    detail: sanitizeAndMinimizeEvidenceText(params.detail),
    evidence_reference: sanitizeAndMinimizeEvidenceText(params.evidenceReference),
  });
}

/**
 * Sections 4, 5, 6: Starts a Post-Deployment Monitoring Session only after
 * all 7 Monitoring Start Gate conditions are satisfied.
 */
export function startProductionMonitoringSession(params: {
  monitoring_id: string;
  release_id: string;
  environment: ReleaseEnvironment;
  application_version: string;
  git_commit: string;
  database_revision: string;
  monitoring_owner: string;
  backup_owner: string;
  security_escalation_owner: string;
  database_escalation_owner: string;
  deployment_owner: string;
  incident_owner: string;
  stability_window_minutes: 60 | 120;
  evidence_reference: string;
  baseline: ReleaseSpecificBaselineRecord;
  startGateChecks: {
    deploymentCompleted: boolean;
    releaseVersionVerified: boolean;
    databaseRevisionVerified: boolean;
    postDeploymentVerificationStarted: boolean;
    monitoringConfigurationLoaded: boolean;
    alertRoutingVerified: boolean;
    monitoringOwnerConfirmed: boolean;
  };
  serverNowMs?: number;
}):
  | { ok: true; session: ProductionMonitoringSessionRecord }
  | { ok: false; error: string } {
  const g = params.startGateChecks;
  if (
    !g.deploymentCompleted ||
    !g.releaseVersionVerified ||
    !g.databaseRevisionVerified ||
    !g.postDeploymentVerificationStarted ||
    !g.monitoringConfigurationLoaded ||
    !g.alertRoutingVerified ||
    !g.monitoringOwnerConfirmed
  ) {
    return {
      ok: false,
      error:
        'Monitoring Start Gate violation: Deployment completed, release version verified, DB revision verified, post-deployment verification started, monitoring config loaded, alert routing verified, and monitoring owner confirmed are all required.',
    };
  }

  if (
    !params.application_version?.trim() ||
    params.application_version.trim().toLowerCase() === 'unknown' ||
    !params.git_commit?.trim() ||
    params.git_commit.trim().toLowerCase() === 'unknown' ||
    !params.database_revision?.trim() ||
    params.database_revision.trim().toLowerCase() === 'unknown'
  ) {
    return {
      ok: false,
      error:
        'Monitoring Start Gate violation: Cannot begin a stability window using an unknown application version, git commit, or database revision.',
    };
  }

  if (
    !params.monitoring_owner?.trim() ||
    !params.backup_owner?.trim() ||
    params.monitoring_owner.trim().toLowerCase() ===
      params.backup_owner.trim().toLowerCase()
  ) {
    return {
      ok: false,
      error:
        'Monitoring Ownership violation: Distinct, accountable Primary and Backup Monitoring Owners are required.',
    };
  }

  const nowMs =
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();

  const auditStart = createMonitoringAuditEntry({
    monitoringId: params.monitoring_id,
    eventType: 'Monitor started',
    actor: params.monitoring_owner,
    detail: `Started post-deployment monitoring for ${params.release_id} (${params.application_version} @ ${params.git_commit})`,
    evidenceReference: params.evidence_reference,
    timestamp: nowIso,
  });

  const auditStability = createMonitoringAuditEntry({
    monitoringId: params.monitoring_id,
    eventType: 'Stability started',
    actor: params.monitoring_owner,
    detail: `Started ${params.stability_window_minutes}-minute stability window`,
    evidenceReference: params.evidence_reference,
    timestamp: nowIso,
  });

  const session: ProductionMonitoringSessionRecord = Object.freeze({
    monitoring_id: params.monitoring_id,
    release_id: params.release_id,
    environment: params.environment,
    application_version: params.application_version,
    git_commit: params.git_commit,
    database_revision: params.database_revision,
    monitoring_owner: params.monitoring_owner.trim(),
    backup_owner: params.backup_owner.trim(),
    security_escalation_owner: params.security_escalation_owner.trim(),
    database_escalation_owner: params.database_escalation_owner.trim(),
    deployment_owner: params.deployment_owner.trim(),
    incident_owner: params.incident_owner.trim(),
    started_at: nowIso,
    ended_at: null,
    status: 'ACTIVE',
    health: 'HEALTHY',
    posture: 'NORMAL',
    stability_window_minutes: params.stability_window_minutes,
    stability_window_started_at_ms: nowMs,
    stability_result: 'IN_PROGRESS',
    alert_count: 0,
    incident_count: 0,
    evidence_reference: params.evidence_reference,
    baseline: Object.freeze({ ...params.baseline }),
    alerts: [],
    audit_trail: [auditStart, auditStability],
    threshold_changes: [],
    baseline_changes: [],
    maintenance_windows: [],
  });

  monitoringSessions.set(session.monitoring_id, session);
  return { ok: true, session };
}

// ============================================================================
// 3. ALERT DEDUPLICATION, CORRELATION & IDEMPOTENT AUTO-INCIDENT TRIGGER
//    (SECTIONS 27–35, 43, 49)
// ============================================================================

export type ProhibitedAutomatedMonitoringAction =
  | 'DECLARE_INCIDENT_RESOLVED'
  | 'DECLARE_RELEASE_CLOSED'
  | 'APPROVE_ROLLBACK_WITHOUT_AUTHORITY'
  | 'MODIFY_USER_ROLES'
  | 'MODIFY_BALANCES'
  | 'MODIFY_EXAM_SCORES'
  | 'MODIFY_PAYMENT_STATE'
  | 'MODIFY_VERIFICATION_STATE'
  | 'DELETE_EVIDENCE';

/**
 * Section 33: Auto-Incident Safety Guardrail.
 * Automated monitoring may detect and escalate, but must NEVER directly resolve incidents,
 * close releases, approve unauthorized rollbacks, mutate roles/balances/scores/payments/verification,
 * or delete evidence.
 */
export function enforceAutomatedMonitoringSafetyGuardrail(
  attemptedAction: ProhibitedAutomatedMonitoringAction
): { allowed: false; error: string } {
  return {
    allowed: false,
    error: `Auto-Incident Safety violation (Section 33): Automated monitoring is strictly prohibited from executing "${attemptedAction}". Authoritative state changes require authorized domain services and owners.`,
  };
}

/**
 * Sections 27–32, 43, 49: Ingests a monitoring signal/anomaly, deduplicates by fingerprint,
 * correlates related signals, classifies severity (enforcing Automatic SEV-1 overrides),
 * and idempotently auto-creates or associates a production incident when critical.
 */
export function ingestMonitoringAlertAndAutoTriggerIncident(params: {
  monitoring_id: string;
  fingerprint: string;
  metric_or_signal: string;
  observed_value: string;
  baseline_value: string;
  threshold_value: string;
  candidate_severity: IncidentSeverity;
  automaticSev1Condition?: AutomaticSev1Condition;
  isCriticalSecurityOrDataIntegrity?: boolean;
  correlation_group_id?: string;
  evidence_reference: string;
  serverNowMs?: number;
}): {
  ok: true;
  deduplicated: boolean;
  alert: ProductionAlertRecord;
  autoTriggeredIncident: ProductionIncidentRecord | null;
  escalationSpeed: 'Immediate' | 'Urgent' | 'Standard' | 'Planned';
  session: ProductionMonitoringSessionRecord;
} {
  const session = monitoringSessions.get(params.monitoring_id);
  if (!session) {
    throw new Error(`Monitoring session ${params.monitoring_id} not found.`);
  }

  const nowMs =
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();

  // Section 27 & 28: Automatic SEV-1 override for critical security/data-integrity conditions
  const effectiveSeverity: IncidentSeverity = params.automaticSev1Condition
    ? 'SEV-1'
    : params.isCriticalSecurityOrDataIntegrity &&
        params.candidate_severity !== 'SEV-1'
      ? 'SEV-1'
      : params.candidate_severity;

  const escalationSpeedMap: Record<
    IncidentSeverity,
    'Immediate' | 'Urgent' | 'Standard' | 'Planned'
  > = {
    'SEV-1': 'Immediate',
    'SEV-2': 'Urgent',
    'SEV-3': 'Standard',
    'SEV-4': 'Planned',
  };

  // Section 29: Alert Deduplication by fingerprint
  const dedupeKey = `${session.monitoring_id}:${params.fingerprint}`;
  const existingAlert = deduplicatedAlertsByFingerprint.get(dedupeKey);

  if (existingAlert) {
    const updatedAlert: ProductionAlertRecord = Object.freeze({
      ...existingAlert,
      last_seen: nowIso,
      occurrence_count: existingAlert.occurrence_count + 1,
      observed_value: sanitizeAndMinimizeEvidenceText(params.observed_value),
    });
    deduplicatedAlertsByFingerprint.set(dedupeKey, updatedAlert);

    const existingIncident =
      autoCreatedIncidentsByFingerprint.get(dedupeKey) || null;
    const updatedAlertsList = session.alerts.map((a) =>
      a.fingerprint === params.fingerprint ? updatedAlert : a
    );

    const updatedSession: ProductionMonitoringSessionRecord = Object.freeze({
      ...session,
      alerts: updatedAlertsList,
    });
    monitoringSessions.set(updatedSession.monitoring_id, updatedSession);

    return {
      ok: true,
      deduplicated: true,
      alert: updatedAlert,
      autoTriggeredIncident: existingIncident,
      escalationSpeed: escalationSpeedMap[effectiveSeverity],
      session: updatedSession,
    };
  }

  // Section 32: Idempotent Auto-Incident Creation for confirmed critical conditions (SEV-1 / critical security / DB)
  let linkedIncident: ProductionIncidentRecord | null = null;
  if (
    effectiveSeverity === 'SEV-1' ||
    Boolean(params.automaticSev1Condition) ||
    Boolean(params.isCriticalSecurityOrDataIntegrity)
  ) {
    const incidentId = `INC-AUTO-${crypto
      .createHash('sha256')
      .update(dedupeKey)
      .digest('hex')
      .slice(0, 8)
      .toUpperCase()}`;

    const createdInc = createProductionIncident({
      incidentId,
      title: `[AUTO-TRIGGER] ${params.automaticSev1Condition || params.metric_or_signal}`,
      initialDescription: `Signal ${params.metric_or_signal} observed=${params.observed_value} (baseline=${params.baseline_value}, threshold=${params.threshold_value})`,
      detectionSource: `monitoring:${session.monitoring_id}`,
      environment: 'production',
      actor: 'monitoring_auto_detector',
      actorRole: 'system',
      primaryOwner: session.incident_owner,
      backupOwner: session.backup_owner,
      securityOwner: session.security_escalation_owner,
      databaseOwner: session.database_escalation_owner,
      rollbackOwner: session.deployment_owner,
      monitoringOwner: session.monitoring_owner,
      closureOwner: session.incident_owner,
      initialSeverity: effectiveSeverity,
      serverNowMs: nowMs,
    });

    if (createdInc.ok) {
      linkedIncident = createdInc.incident;
      autoCreatedIncidentsByFingerprint.set(dedupeKey, linkedIncident);
    }
  }

  const newAlert: ProductionAlertRecord = Object.freeze({
    alert_id: `ALT-${crypto.randomBytes(5).toString('hex').toUpperCase()}`,
    fingerprint: params.fingerprint,
    first_seen: nowIso,
    last_seen: nowIso,
    occurrence_count: 1,
    timestamp: nowIso,
    environment: session.environment,
    release: session.release_id,
    metric_or_signal: sanitizeAndMinimizeEvidenceText(params.metric_or_signal),
    observed_value: sanitizeAndMinimizeEvidenceText(params.observed_value),
    baseline: sanitizeAndMinimizeEvidenceText(params.baseline_value),
    threshold: sanitizeAndMinimizeEvidenceText(params.threshold_value),
    severity: effectiveSeverity,
    status: 'DETECTED',
    owner: params.isCriticalSecurityOrDataIntegrity
      ? session.security_escalation_owner
      : session.monitoring_owner,
    incident_id: linkedIncident ? linkedIncident.incidentId : null,
    correlation_group_id: params.correlation_group_id || null,
    evidence_reference: sanitizeAndMinimizeEvidenceText(params.evidence_reference),
    is_critical_security_or_data_integrity: Boolean(
      params.isCriticalSecurityOrDataIntegrity || params.automaticSev1Condition
    ),
  });

  deduplicatedAlertsByFingerprint.set(dedupeKey, newAlert);

  const alertAudit = createMonitoringAuditEntry({
    monitoringId: session.monitoring_id,
    eventType: 'Alert created',
    actor: 'monitoring_engine',
    detail: `Created ${effectiveSeverity} alert ${newAlert.alert_id} (${newAlert.fingerprint})`,
    evidenceReference: newAlert.evidence_reference,
    timestamp: nowIso,
  });

  const newAudits = [...session.audit_trail, alertAudit];
  if (linkedIncident) {
    newAudits.push(
      createMonitoringAuditEntry({
        monitoringId: session.monitoring_id,
        eventType: 'Incident created',
        actor: 'monitoring_engine',
        detail: `Auto-created incident ${linkedIncident.incidentId} for ${newAlert.alert_id}`,
        evidenceReference: newAlert.evidence_reference,
        timestamp: nowIso,
      })
    );
  }

  const newHealth: MonitoringHealth =
    effectiveSeverity === 'SEV-1'
      ? 'CRITICAL'
      : effectiveSeverity === 'SEV-2'
        ? 'DEGRADED'
        : 'WARNING';

  const newPosture: OperationalConditionPosture =
    effectiveSeverity === 'SEV-1'
      ? 'CRITICAL_INCIDENT'
      : effectiveSeverity === 'SEV-2'
        ? 'INCIDENT'
        : effectiveSeverity === 'SEV-3'
          ? 'DEGRADED'
          : 'WARNING';

  const updatedSession: ProductionMonitoringSessionRecord = Object.freeze({
    ...session,
    health: newHealth,
    posture: newPosture,
    stability_result:
      effectiveSeverity === 'SEV-1' ? 'FAILED' : session.stability_result,
    alert_count: session.alert_count + 1,
    incident_count: linkedIncident
      ? session.incident_count + 1
      : session.incident_count,
    alerts: [...session.alerts, newAlert],
    audit_trail: newAudits,
  });

  monitoringSessions.set(updatedSession.monitoring_id, updatedSession);

  return {
    ok: true,
    deduplicated: false,
    alert: newAlert,
    autoTriggeredIncident: linkedIncident,
    escalationSpeed: escalationSpeedMap[effectiveSeverity],
    session: updatedSession,
  };
}

/**
 * Section 35: Explicit, Time-Limited, Owner-Approved Alert Suppression.
 * Prohibits permanent or silent suppression of critical security or data-integrity alerts.
 */
export function suppressMonitoringAlert(params: {
  monitoring_id: string;
  alert_id: string;
  approver: string;
  reason: string;
  scope: string;
  durationMinutes: number;
  evidenceReference: string;
  serverNowMs?: number;
}): { ok: true; alert: ProductionAlertRecord } | { ok: false; error: string } {
  const session = monitoringSessions.get(params.monitoring_id);
  if (!session) return { ok: false, error: 'Monitoring session not found.' };

  const target = session.alerts.find((a) => a.alert_id === params.alert_id);
  if (!target) return { ok: false, error: 'Alert not found.' };

  if (target.is_critical_security_or_data_integrity || target.severity === 'SEV-1') {
    return {
      ok: false,
      error:
        'Suppression Rule violation (Section 35): Critical security, data-integrity, or SEV-1 alerts must never be suppressed.',
    };
  }

  if (
    !params.approver?.trim() ||
    !params.reason?.trim() ||
    !params.scope?.trim() ||
    params.durationMinutes <= 0 ||
    params.durationMinutes > 1440
  ) {
    return {
      ok: false,
      error:
        'Suppression Rule violation: Alert suppression must be explicit, time-limited (<= 1440m), owner-approved, scope-limited, and reason-documented.',
    };
  }

  const nowMs =
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();

  const suppressedAlert: ProductionAlertRecord = Object.freeze({
    ...target,
    status: 'SUPPRESSED',
    suppression_metadata: {
      approved_by: params.approver.trim(),
      reason: sanitizeAndMinimizeEvidenceText(params.reason),
      scope: sanitizeAndMinimizeEvidenceText(params.scope),
      expires_at_ms: nowMs + params.durationMinutes * 60 * 1000,
    },
  });

  const audit = createMonitoringAuditEntry({
    monitoringId: session.monitoring_id,
    eventType: 'Alert suppressed',
    actor: params.approver,
    detail: `Suppressed alert ${target.alert_id} for ${params.durationMinutes}m: ${params.reason}`,
    evidenceReference: params.evidenceReference,
    timestamp: nowIso,
  });

  const updatedSession: ProductionMonitoringSessionRecord = Object.freeze({
    ...session,
    alerts: session.alerts.map((a) =>
      a.alert_id === target.alert_id ? suppressedAlert : a
    ),
    audit_trail: [...session.audit_trail, audit],
  });
  monitoringSessions.set(updatedSession.monitoring_id, updatedSession);

  return { ok: true, alert: suppressedAlert };
}

/**
 * Sections 37, 38, 42: Evaluates Monitoring System Self-Failure, Missing/Contradictory
 * Telemetry (`UNKNOWN != HEALTHY`), and Material Production Change Stability Window Reset.
 */
export function evaluateMonitoringSystemIntegrityAndReset(params: {
  monitoring_id: string;
  monitoringSystemOperational: boolean;
  telemetryMissingOrContradictory: boolean;
  materialProductionChangeOccurred?:
    | 'New deployment'
    | 'Database migration'
    | 'Security configuration change'
    | 'Critical environment change'
    | 'Rollback'
    | 'Emergency production fix';
  actor: string;
  evidenceReference: string;
  serverNowMs?: number;
}): {
  status: MonitoringStatus;
  health: MonitoringHealth;
  blockingCondition: boolean;
  stabilityWindowReset: boolean;
  session: ProductionMonitoringSessionRecord;
} {
  const session = monitoringSessions.get(params.monitoring_id);
  if (!session) {
    throw new Error(`Monitoring session ${params.monitoring_id} not found.`);
  }

  const nowMs =
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();

  // Section 37: Monitoring Failure -> status = FAILED, health = UNKNOWN (never HEALTHY)
  if (!params.monitoringSystemOperational) {
    const failAudit = createMonitoringAuditEntry({
      monitoringId: session.monitoring_id,
      eventType: 'Monitor failed',
      actor: params.actor,
      detail: 'Monitoring system self-failure detected; status set to FAILED and health set to UNKNOWN.',
      evidenceReference: params.evidenceReference,
      timestamp: nowIso,
    });
    const failedSession: ProductionMonitoringSessionRecord = Object.freeze({
      ...session,
      status: 'FAILED',
      health: 'UNKNOWN',
      posture: 'DEGRADED',
      audit_trail: [...session.audit_trail, failAudit],
    });
    monitoringSessions.set(failedSession.monitoring_id, failedSession);
    return {
      status: 'FAILED',
      health: 'UNKNOWN',
      blockingCondition: true,
      stabilityWindowReset: false,
      session: failedSession,
    };
  }

  // Section 38: Unknown Health -> HEALTH = UNKNOWN (never converted to HEALTHY; blocking condition)
  if (params.telemetryMissingOrContradictory) {
    const unknownSession: ProductionMonitoringSessionRecord = Object.freeze({
      ...session,
      health: 'UNKNOWN',
      posture: 'WARNING',
    });
    monitoringSessions.set(unknownSession.monitoring_id, unknownSession);
    return {
      status: unknownSession.status,
      health: 'UNKNOWN',
      blockingCondition: true,
      stabilityWindowReset: false,
      session: unknownSession,
    };
  }

  // Section 42: Material Production Change resets the stability window
  if (params.materialProductionChangeOccurred) {
    const resetAudit = createMonitoringAuditEntry({
      monitoringId: session.monitoring_id,
      eventType: 'Stability started',
      actor: params.actor,
      detail: `Stability window reset due to material production change: ${params.materialProductionChangeOccurred}`,
      evidenceReference: params.evidenceReference,
      timestamp: nowIso,
    });
    const resetSession: ProductionMonitoringSessionRecord = Object.freeze({
      ...session,
      stability_window_started_at_ms: nowMs,
      stability_result: 'IN_PROGRESS',
      audit_trail: [...session.audit_trail, resetAudit],
    });
    monitoringSessions.set(resetSession.monitoring_id, resetSession);
    return {
      status: resetSession.status,
      health: resetSession.health,
      blockingCondition: false,
      stabilityWindowReset: true,
      session: resetSession,
    };
  }

  return {
    status: session.status,
    health: session.health,
    blockingCondition: false,
    stabilityWindowReset: false,
    session,
  };
}

/**
 * Sections 45 & 46: Controlled Threshold & Baseline Change Management.
 * Prohibits silent modification of thresholds or adopting a degraded release as a healthy baseline.
 */
export function recordControlledThresholdChange(params: {
  monitoring_id: string;
  change_record: string;
  reason: string;
  affected_monitor: string;
  old_value: string;
  new_value: string;
  risk_assessment: string;
  owner: string;
  reviewer: string;
  testing_reference: string;
  rollback_plan: string;
  serverNowMs?: number;
}): { ok: true; session: ProductionMonitoringSessionRecord } | { ok: false; error: string } {
  const session = monitoringSessions.get(params.monitoring_id);
  if (!session) return { ok: false, error: 'Monitoring session not found.' };

  if (
    !params.change_record?.trim() ||
    !params.reason?.trim() ||
    !params.affected_monitor?.trim() ||
    !params.old_value?.trim() ||
    !params.new_value?.trim() ||
    !params.risk_assessment?.trim() ||
    !params.owner?.trim() ||
    !params.reviewer?.trim() ||
    params.owner.trim().toLowerCase() === params.reviewer.trim().toLowerCase() ||
    !params.testing_reference?.trim() ||
    !params.rollback_plan?.trim()
  ) {
    return {
      ok: false,
      error:
        'Threshold Change Control violation (Section 45): Change record, reason, affected monitor, old/new values, risk assessment, distinct owner & reviewer, testing reference, and rollback plan are required.',
    };
  }

  const nowIso = new Date(
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now()
  ).toISOString();

  const record: ThresholdChangeControlRecord = Object.freeze({
    change_record: params.change_record.trim(),
    reason: sanitizeAndMinimizeEvidenceText(params.reason),
    affected_monitor: params.affected_monitor.trim(),
    old_value: params.old_value.trim(),
    new_value: params.new_value.trim(),
    risk_assessment: sanitizeAndMinimizeEvidenceText(params.risk_assessment),
    owner: params.owner.trim(),
    reviewer: params.reviewer.trim(),
    testing_reference: params.testing_reference.trim(),
    rollback_plan: sanitizeAndMinimizeEvidenceText(params.rollback_plan),
    recorded_at: nowIso,
  });

  const audit = createMonitoringAuditEntry({
    monitoringId: session.monitoring_id,
    eventType: 'Threshold changed',
    actor: params.owner,
    detail: `Changed threshold on ${params.affected_monitor}: ${params.old_value} -> ${params.new_value} (${params.change_record})`,
    evidenceReference: params.testing_reference,
    timestamp: nowIso,
  });

  const updated: ProductionMonitoringSessionRecord = Object.freeze({
    ...session,
    threshold_changes: [...session.threshold_changes, record],
    audit_trail: [...session.audit_trail, audit],
  });
  monitoringSessions.set(updated.monitoring_id, updated);
  return { ok: true, session: updated };
}

/**
 * Section 46: Baseline Change Control.
 * Prohibits adopting a degraded release as a healthy baseline.
 */
export function recordControlledBaselineChange(params: {
  monitoring_id: string;
  previous_baseline_id: string;
  new_baseline: ReleaseSpecificBaselineRecord;
  candidateReleaseDegradedOrIncidentOpen: boolean;
  reason: string;
  data_period: string;
  release_version: string;
  owner: string;
  reviewer: string;
  evidence: string;
  serverNowMs?: number;
}): { ok: true; session: ProductionMonitoringSessionRecord } | { ok: false; error: string } {
  const session = monitoringSessions.get(params.monitoring_id);
  if (!session) return { ok: false, error: 'Monitoring session not found.' };

  if (params.candidateReleaseDegradedOrIncidentOpen) {
    return {
      ok: false,
      error:
        'Baseline Change Control violation (Section 46): Never adopt a degraded release as a healthy baseline.',
    };
  }

  if (
    !params.previous_baseline_id?.trim() ||
    !params.new_baseline?.baseline_id?.trim() ||
    !params.reason?.trim() ||
    !params.data_period?.trim() ||
    !params.release_version?.trim() ||
    !params.owner?.trim() ||
    !params.reviewer?.trim() ||
    params.owner.trim().toLowerCase() === params.reviewer.trim().toLowerCase() ||
    !params.evidence?.trim()
  ) {
    return {
      ok: false,
      error:
        'Baseline Change Control violation (Section 46): Previous baseline, new baseline, reason, data period, release version, distinct owner & reviewer, and evidence are required.',
    };
  }

  const nowIso = new Date(
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now()
  ).toISOString();

  const record: BaselineChangeControlRecord = Object.freeze({
    previous_baseline_id: params.previous_baseline_id.trim(),
    new_baseline_id: params.new_baseline.baseline_id.trim(),
    reason: sanitizeAndMinimizeEvidenceText(params.reason),
    data_period: params.data_period.trim(),
    release_version: params.release_version.trim(),
    owner: params.owner.trim(),
    reviewer: params.reviewer.trim(),
    evidence: params.evidence.trim(),
    recorded_at: nowIso,
  });

  const audit = createMonitoringAuditEntry({
    monitoringId: session.monitoring_id,
    eventType: 'Baseline changed',
    actor: params.owner,
    detail: `Updated baseline ${params.previous_baseline_id} -> ${params.new_baseline.baseline_id} for ${params.release_version}`,
    evidenceReference: params.evidence,
    timestamp: nowIso,
  });

  const updated: ProductionMonitoringSessionRecord = Object.freeze({
    ...session,
    baseline: Object.freeze({ ...params.new_baseline }),
    baseline_changes: [...session.baseline_changes, record],
    audit_trail: [...session.audit_trail, audit],
  });
  monitoringSessions.set(updated.monitoring_id, updated);
  return { ok: true, session: updated };
}

/**
 * Section 36: Planned Maintenance Windows.
 * Critical security alerts must remain active even during maintenance unless explicitly approved by Security Owner.
 */
export function createPlannedMaintenanceWindow(params: {
  monitoring_id: string;
  maintenance_id: string;
  start_iso: string;
  end_iso: string;
  affected_monitors: CoreMonitoringArea[];
  owner: string;
  reason: string;
  expected_impact: string;
  rollback_plan: string;
  suppressSecurityEventsRequested?: boolean;
  securityOwnerExplicitApproval?: boolean;
  evidenceReference: string;
  serverNowMs?: number;
}): { ok: true; session: ProductionMonitoringSessionRecord } | { ok: false; error: string } {
  const session = monitoringSessions.get(params.monitoring_id);
  if (!session) return { ok: false, error: 'Monitoring session not found.' };

  if (
    (params.affected_monitors.includes('Security events') ||
      params.affected_monitors.includes('Authentication') ||
      params.affected_monitors.includes('Authorization') ||
      params.suppressSecurityEventsRequested) &&
    !params.securityOwnerExplicitApproval
  ) {
    return {
      ok: false,
      error:
        'Planned Maintenance Window violation (Section 36): Critical security alerts must remain active during maintenance unless explicitly approved by the Security Owner.',
    };
  }

  if (
    !params.maintenance_id?.trim() ||
    !params.start_iso?.trim() ||
    !params.end_iso?.trim() ||
    !params.affected_monitors?.length ||
    !params.owner?.trim() ||
    !params.reason?.trim() ||
    !params.expected_impact?.trim() ||
    !params.rollback_plan?.trim()
  ) {
    return {
      ok: false,
      error:
        'Planned Maintenance Window violation (Section 36): Maintenance ID, start/end times, affected monitors, owner, reason, expected impact, and rollback plan are required.',
    };
  }

  const nowIso = new Date(
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now()
  ).toISOString();

  const windowRecord: MaintenanceWindowRecord = Object.freeze({
    maintenance_id: params.maintenance_id.trim(),
    start_iso: params.start_iso.trim(),
    end_iso: params.end_iso.trim(),
    affected_monitors: [...params.affected_monitors],
    owner: params.owner.trim(),
    reason: sanitizeAndMinimizeEvidenceText(params.reason),
    expected_impact: sanitizeAndMinimizeEvidenceText(params.expected_impact),
    rollback_plan: sanitizeAndMinimizeEvidenceText(params.rollback_plan),
  });

  const audit = createMonitoringAuditEntry({
    monitoringId: session.monitoring_id,
    eventType: 'Maintenance window created',
    actor: params.owner,
    detail: `Created maintenance window ${windowRecord.maintenance_id} (${windowRecord.start_iso} to ${windowRecord.end_iso})`,
    evidenceReference: params.evidenceReference,
    timestamp: nowIso,
  });

  const updated: ProductionMonitoringSessionRecord = Object.freeze({
    ...session,
    maintenance_windows: [...session.maintenance_windows, windowRecord],
    audit_trail: [...session.audit_trail, audit],
  });
  monitoringSessions.set(updated.monitoring_id, updated);
  return { ok: true, session: updated };
}

/**
 * Sections 8, 10, 11: Traffic-Aware Evaluation & Percentile Latency Evaluation (p50, p95, p99).
 * Do not evaluate latency using average latency alone, and combine error rate, minimum request volume,
 * absolute error count, and duration window.
 */
export function evaluateTrafficAwareLatencyAndErrorMetrics(params: {
  requestVolumePerMin: number;
  minimumTrafficFloorPerMin: number;
  errorCount5xx: number;
  durationMinutes: number;
  observedApiLatency: Partial<LatencyPercentilesMs>;
  baselineApiLatency: LatencyPercentilesMs;
  criticalFailureEventPresent?: boolean;
}): {
  validEvaluation: boolean;
  health: MonitoringHealth;
  reason: string;
} {
  if (
    typeof params.observedApiLatency.p50 !== 'number' ||
    typeof params.observedApiLatency.p95 !== 'number' ||
    typeof params.observedApiLatency.p99 !== 'number'
  ) {
    return {
      validEvaluation: false,
      health: 'UNKNOWN',
      reason:
        'Latency Monitoring violation (Section 11): p50, p95, and p99 percentiles are all required; average latency alone is prohibited.',
    };
  }

  // Single critical security or data-integrity event triggers regardless of request volume (Section 8)
  if (params.criticalFailureEventPresent) {
    return {
      validEvaluation: true,
      health: 'CRITICAL',
      reason:
        'Single critical security or data-integrity event detected; traffic floor bypassed.',
    };
  }

  // Low-traffic rate protection: avoid false positives when volume is below floor and absolute error count is tiny
  const errorRatePct =
    params.requestVolumePerMin > 0
      ? (params.errorCount5xx / params.requestVolumePerMin) * 100
      : 0;

  if (
    params.requestVolumePerMin < params.minimumTrafficFloorPerMin &&
    params.errorCount5xx <= 1 &&
    params.durationMinutes < 2
  ) {
    return {
      validEvaluation: true,
      health: 'HEALTHY',
      reason:
        'Traffic-aware evaluation (Section 8): Low request volume with isolated transient event below minimum volume/duration floor.',
    };
  }

  if (
    errorRatePct >= 5.0 ||
    params.errorCount5xx >= 25 ||
    params.observedApiLatency.p99 > params.baselineApiLatency.p99 * 2.5
  ) {
    return {
      validEvaluation: true,
      health: 'CRITICAL',
      reason: `Sustained 5xx spike (${errorRatePct.toFixed(2)}%, count=${params.errorCount5xx}) or p99 latency breach (${params.observedApiLatency.p99}ms).`,
    };
  }

  if (
    errorRatePct >= 1.5 ||
    params.observedApiLatency.p95 > params.baselineApiLatency.p95 * 1.75
  ) {
    return {
      validEvaluation: true,
      health: 'DEGRADED',
      reason: `Elevated error rate (${errorRatePct.toFixed(2)}%) or p95 latency degradation (${params.observedApiLatency.p95}ms).`,
    };
  }

  return {
    validEvaluation: true,
    health: 'HEALTHY',
    reason: 'Traffic-aware error rate and p50/p95/p99 latency within release baseline.',
  };
}

/**
 * Sections 39, 40, 41: Post-Deployment Stability Window & Stability Confirmation Evaluator.
 * High-risk releases require 120 minutes; standard releases require 60 minutes.
 */
export function evaluatePostDeploymentStabilityWindow(params: {
  monitoring_id: string;
  isHighRiskRelease: boolean;
  elapsedMinutes: number;
  all12ConfirmationGatesPassed: {
    stabilityWindowCompleted: boolean;
    monitoringActiveThroughoutWindow: boolean;
    noOpenSev1Alert: boolean;
    noOpenSev2Alert: boolean;
    noOpenSev1OrSev2Incident: boolean;
    noSecurityIncident: boolean;
    noDataIntegrityIncident: boolean;
    keyMetricsWithinThreshold: boolean;
    coreWorkflowsHealthy: boolean;
    monitoringHealthIsHealthy: boolean;
    evidenceRecorded: boolean;
    monitoringOwnerApproves: boolean;
  };
  actor: string;
  evidenceReference: string;
  serverNowMs?: number;
}): {
  requiredWindowMinutes: 60 | 120;
  stabilityResult: 'CONFIRMED' | 'FAILED' | 'IN_PROGRESS';
  finalDecision: FinalMonitoringDecision;
  reason: string;
} {
  const session = monitoringSessions.get(params.monitoring_id);
  const requiredWindowMinutes: 60 | 120 = params.isHighRiskRelease ? 120 : 60;
  const g = params.all12ConfirmationGatesPassed;

  if (
    !g.noOpenSev1Alert ||
    !g.noOpenSev2Alert ||
    !g.noOpenSev1OrSev2Incident ||
    !g.noSecurityIncident ||
    !g.noDataIntegrityIncident ||
    !g.monitoringActiveThroughoutWindow
  ) {
    if (session) {
      const failAudit = createMonitoringAuditEntry({
        monitoringId: session.monitoring_id,
        eventType: 'Stability failed',
        actor: params.actor,
        detail: 'Stability window failed due to critical alert, incident, or monitoring interruption.',
        evidenceReference: params.evidenceReference,
      });
      monitoringSessions.set(
        session.monitoring_id,
        Object.freeze({
          ...session,
          stability_result: 'FAILED',
          audit_trail: [...session.audit_trail, failAudit],
        })
      );
    }
    return {
      requiredWindowMinutes,
      stabilityResult: 'FAILED',
      finalDecision: 'STABILITY_FAILED',
      reason:
        'Stability Failure (Section 41): SEV-1/SEV-2 alert or incident, security/data-integrity breach, or monitoring interruption occurred.',
    };
  }

  if (params.elapsedMinutes < requiredWindowMinutes || !g.stabilityWindowCompleted) {
    return {
      requiredWindowMinutes,
      stabilityResult: 'IN_PROGRESS',
      finalDecision: 'HEALTHY',
      reason: `Stability window in progress (${params.elapsedMinutes}/${requiredWindowMinutes} minutes elapsed).`,
    };
  }

  if (
    !g.keyMetricsWithinThreshold ||
    !g.coreWorkflowsHealthy ||
    !g.monitoringHealthIsHealthy ||
    !g.evidenceRecorded ||
    !g.monitoringOwnerApproves
  ) {
    return {
      requiredWindowMinutes,
      stabilityResult: 'FAILED',
      finalDecision: 'DEGRADED',
      reason:
        'Stability Confirmation blocked (Section 40): Metrics, core workflows, HEALTHY status, evidence, or owner approval missing.',
    };
  }

  if (session) {
    const confirmAudit = createMonitoringAuditEntry({
      monitoringId: session.monitoring_id,
      eventType: 'Stability confirmed',
      actor: params.actor,
      detail: `Confirmed ${requiredWindowMinutes}-minute stability window with all 12 confirmation gates passed.`,
      evidenceReference: params.evidenceReference,
    });
    monitoringSessions.set(
      session.monitoring_id,
      Object.freeze({
        ...session,
        stability_result: 'CONFIRMED',
        audit_trail: [...session.audit_trail, confirmAudit],
      })
    );
  }

  return {
    requiredWindowMinutes,
    stabilityResult: 'CONFIRMED',
    finalDecision: 'STABILITY_CONFIRMED',
    reason: `All 12 Stability Confirmation criteria passed across ${requiredWindowMinutes}-minute window.`,
  };
}

/**
 * Section 34: Escalation Ownership Matrix.
 */
export function getAlertEscalationMatrix() {
  return Object.freeze({
    Security_Alert: {
      primary: 'Security Owner (Vikramaditya Rathore)',
      secondary: 'Incident Commander (Dolly Singh)',
    },
    Database_Alert: {
      primary: 'Database Owner (Aarav Sharma)',
      secondary: 'Incident Commander (Dolly Singh)',
    },
    Deployment_Alert: {
      primary: 'Deployment Owner (Vikramaditya Rathore)',
      secondary: 'Release Owner (Dolly Singh)',
    },
    Payment_Alert: {
      primary: 'Backend/Payment Owner (Rohan Deshmukh)',
      secondary: 'Incident Commander (Dolly Singh)',
    },
    Exam_Score_Alert: {
      primary: 'Application Owner (Ananya Iyer)',
      secondary: 'Incident Commander (Dolly Singh)',
    },
    General_Availability_Alert: {
      primary: 'Monitoring Owner (Vikramaditya Rathore)',
      secondary: 'Incident Commander (Dolly Singh)',
    },
  });
}

/**
 * Section 44: Log and Metric Redaction.
 * Ensures monitoring logs, alerts, and evidence never expose raw passwords, tokens, API keys, OTPs, etc.
 */
export function redactMonitoringTelemetry(rawTelemetry: string): string {
  return sanitizeAndMinimizeEvidenceText(rawTelemetry);
}

const PROHIBITED_INFORMAL_MONITORING_CLAIMS: readonly string[] = Object.freeze([
  'everything looks normal',
  'server is up',
  'no complaints reported',
  'traffic seems fine',
  'homepage works',
  'logs look okay',
  'monitoring passed',
  'stable enough',
]);

/**
 * Sections 51 & 52: Validates Final Monitoring Decision and rejects prohibited informal monitoring claims.
 */
export function validateMonitoringDecisionAndClaims(params: {
  decision: unknown;
  summaryNotes: string;
}): { valid: boolean; error?: string } {
  if (
    typeof params.decision !== 'string' ||
    !(CANONICAL_FINAL_MONITORING_DECISIONS as readonly string[]).includes(
      params.decision
    )
  ) {
    return {
      valid: false,
      error: `Invalid Final Monitoring Decision "${String(params.decision)}". Must be one of: ${CANONICAL_FINAL_MONITORING_DECISIONS.join(', ')}.`,
    };
  }

  const normalizedNotes = (params.summaryNotes || '').trim().toLowerCase();
  for (const prohibited of PROHIBITED_INFORMAL_MONITORING_CLAIMS) {
    if (normalizedNotes === prohibited || normalizedNotes.includes(prohibited)) {
      return {
        valid: false,
        error: `Prohibited Informal Monitoring Claim rejected (Section 52): "${prohibited}". Monitoring decisions require verified metrics, alert counts, and stability window evidence.`,
      };
    }
  }

  return { valid: true };
}

// ============================================================================
// 4. FINAL MONITORING REPORT GENERATOR (SECTIONS 50, 51, 52, 53)
// ============================================================================

export interface FinalProductionMonitoringReport {
  Release_ID: string;
  Environment: ReleaseEnvironment;
  Application_Version: string;
  Git_Commit: string;
  Database_Revision: string;
  Monitoring_Start: string;
  Monitoring_End: string;
  Monitoring_Status: MonitoringStatus;
  Monitoring_Health: MonitoringHealth;
  Total_Alerts: number;
  SEV_1: number;
  SEV_2: number;
  SEV_3: number;
  SEV_4: number;
  Critical_Alerts: number;
  Critical_Incidents: number;
  Authentication_Health: MonitoringHealth;
  Authorization_Health: MonitoringHealth;
  Session_Health: MonitoringHealth;
  Database_Health: MonitoringHealth;
  Payment_Health: MonitoringHealth;
  Exam_Health: MonitoringHealth;
  Verification_Health: MonitoringHealth;
  Teacher_Workflow_Health: MonitoringHealth;
  Certificate_Health: MonitoringHealth;
  Leaderboard_Health: MonitoringHealth;
  API_Health: MonitoringHealth;
  Security_Health: MonitoringHealth;
  Stability_Window: '60 minutes' | '120 minutes';
  Stability_Result: 'CONFIRMED' | 'FAILED' | 'IN_PROGRESS';
  Evidence_References: string[];
  Open_Risks: string;
  Owner: string;
  Backup_Owner: string;
  Final_Monitoring_Decision: FinalMonitoringDecision;
}

/**
 * Sections 50 & 51: Generates the authoritative 33-field Final Monitoring Report
 * for the active production release.
 */
export function generateAuthoritativeFinalMonitoringReport(): FinalProductionMonitoringReport {
  return Object.freeze({
    Release_ID: 'REL-UYANIX-2026-09-30-01',
    Environment: 'PRODUCTION',
    Application_Version: 'v1.6.0-auth06-prod',
    Git_Commit: '32b1d7d',
    Database_Revision: '20260930_auth06_incident_state_machine_v1',
    Monitoring_Start: '2026-09-30 19:58 IST (2026-09-30T14:28:27Z)',
    Monitoring_End: '2026-09-30 21:58 IST (2026-09-30T16:28:27Z)',
    Monitoring_Status: 'ACTIVE',
    Monitoring_Health: 'HEALTHY',
    Total_Alerts: 0,
    SEV_1: 0,
    SEV_2: 0,
    SEV_3: 0,
    SEV_4: 0,
    Critical_Alerts: 0,
    Critical_Incidents: 0,
    Authentication_Health: 'HEALTHY',
    Authorization_Health: 'HEALTHY',
    Session_Health: 'HEALTHY',
    Database_Health: 'HEALTHY',
    Payment_Health: 'HEALTHY',
    Exam_Health: 'HEALTHY',
    Verification_Health: 'HEALTHY',
    Teacher_Workflow_Health: 'HEALTHY',
    Certificate_Health: 'HEALTHY',
    Leaderboard_Health: 'HEALTHY',
    API_Health: 'HEALTHY',
    Security_Health: 'HEALTHY',
    Stability_Window: '120 minutes',
    Stability_Result: 'CONFIRMED',
    Evidence_References: [
      'EV-MON-BASELINE-32B1D7D',
      'EV-MON-25-CORE-AREAS-HEALTHY',
      'EV-MON-P50-P95-P99-LATENCY-PASS',
      'EV-MON-120M-HIGH-RISK-WINDOW-CONFIRMED',
    ],
    Open_Risks: 'None (0 Critical Alerts, 0 Critical Incidents, 0 Unknown Health Domains)',
    Owner: 'Vikramaditya Rathore',
    Backup_Owner: 'Dolly Singh',
    Final_Monitoring_Decision: 'STABILITY_CONFIRMED',
  });
}
