import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  requireAdmin,
  requireAuthenticatedUser,
} from '@/lib/server-auth';
import {
  createProductionIncident,
  evaluateMasterGoNoGoChain,
  executeAtomicIncidentStatusTransition,
  executeGuardedIncidentTransition,
  exportIncidentAuditBundle,
  getAuthoritative31PhaseImplementationReport,
  getAuthoritativeIncident,
  INCIDENT_STATUS_ENUM_VERSION,
} from '@/lib/incident-lifecycle';
import { generateAuthoritativeReleaseControlReport } from '@/lib/release-governance';
import { generateAuthoritativeFinalMonitoringReport } from '@/lib/post-deployment-monitoring';
import { generateAuthoritativeDataLifecycleReport } from '@/lib/data-lifecycle-governance';
import { generateAuthoritativeObservabilityControlReport } from '@/lib/observability-control';
import { generateAuthoritativeApiContractReport } from '@/lib/api-contract-governance';
import { generateAuthoritativeDatabaseGovernanceReport } from '@/lib/database-governance';
import { generateAuthoritativeFileSecurityReport } from '@/lib/file-security-governance';
import { generateAuthoritativeWebSecurityReport } from '@/lib/web-security-governance';
import { generateAuthoritativeExamEngineReport } from '@/lib/exam-engine-governance';
import { generateAuthoritativePaymentGovernanceReport } from '@/lib/payment-financial-governance';
import { generateAuthoritativeCertificateGovernanceReport } from '@/lib/certificate-security-governance';
import { generateAuthoritativeAdminControlPlaneReport } from '@/lib/admin-control-plane-governance';
import { generateAuthoritativeGoogleSecurityReport } from '@/lib/google-workspace-security-governance';
import { generateAuthoritativePrivacyConsentReport } from '@/lib/privacy-consent-governance';
import { generateAuthoritativePerformanceScalabilityReport } from '@/lib/performance-scalability-governance';
import { generateAuthoritativeSeoAndUrlHardeningReport } from '@/lib/seo-canonical-url-governance';
import { generateAuthoritativeRoutingAccessControlReport } from '@/lib/routing-access-control-governance';
import { generateAuthoritativeProductionDataIntegrityReport } from '@/lib/production-data-integrity-governance';
import { generateAuthoritativeCommunicationReliabilityReport } from '@/lib/communication-reliability-governance';
import { generateMasterProductionReadinessFinalAuditReport } from '@/lib/master-production-readiness-audit';
import { generatePeriodicProductionReviewReport } from '@/lib/continuous-compliance-governance';
import { generateAuthoritativeSecurityIncidentResponseReport } from '@/lib/security-incident-breach-governance';
import { generateAuthoritativeAutomatedQaReport } from '@/lib/automated-qa-test-control-governance';
import { generateAuthoritativeSupplyChainSecretsReport } from '@/lib/supply-chain-secrets-governance';
import { generateAuthoritativeOperationalResilienceReport } from '@/lib/operational-resilience-governance';
import {
  generateFinalSystemCertificationAndAcceptanceReport,
  generateAuthoritativeContinuousChangeGovernanceReport,
} from '@/lib/final-production-certification-and-change-governance';
import { generateAuthoritativeBusinessContinuityReport } from '@/lib/business-continuity-recovery-governance';
import { generateAuthoritativeProductionMaintenanceReport } from '@/lib/production-maintenance-operational-governance';

export async function GET(req: NextRequest) {
  const auth = requireAdmin(req);
  if (!auth.ok) {
    return auth.response;
  }

  if (
    req.nextUrl.searchParams.get('businessContinuityRecoveryReport') === 'true'
  ) {
    const bcReport = generateAuthoritativeBusinessContinuityReport();
    return NextResponse.json(bcReport, { status: 200 });
  }

  if (
    req.nextUrl.searchParams.get('productionMaintenanceReport') === 'true'
  ) {
    const maintReport = generateAuthoritativeProductionMaintenanceReport();
    return NextResponse.json(maintReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('finalSystemCertificationReport') === 'true') {
    const certReport = generateFinalSystemCertificationAndAcceptanceReport();
    return NextResponse.json(certReport, { status: 200 });
  }

  if (
    req.nextUrl.searchParams.get('continuousChangeGovernanceReport') === 'true'
  ) {
    const chgGovReport =
      generateAuthoritativeContinuousChangeGovernanceReport();
    return NextResponse.json(chgGovReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('operationalResilienceReport') === 'true') {
    const opsResReport = generateAuthoritativeOperationalResilienceReport();
    return NextResponse.json(opsResReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('supplyChainSecretsReport') === 'true') {
    const scReport = generateAuthoritativeSupplyChainSecretsReport();
    return NextResponse.json(scReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('automatedQaReport') === 'true') {
    const qaReport = generateAuthoritativeAutomatedQaReport();
    return NextResponse.json(qaReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('securityIncidentBreachReport') === 'true') {
    const secIncReport = generateAuthoritativeSecurityIncidentResponseReport();
    return NextResponse.json(secIncReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('continuousComplianceReport') === 'true') {
    const contReport = generatePeriodicProductionReviewReport();
    return NextResponse.json(contReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('masterFinalAuditReport') === 'true') {
    const masterReport = generateMasterProductionReadinessFinalAuditReport();
    return NextResponse.json(masterReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('communicationReport') === 'true') {
    const commReport = generateAuthoritativeCommunicationReliabilityReport();
    return NextResponse.json(commReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('dataIntegrityReport') === 'true') {
    const dataIntegrityReport =
      generateAuthoritativeProductionDataIntegrityReport();
    return NextResponse.json(dataIntegrityReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('routingAccessReport') === 'true') {
    const routingReport = generateAuthoritativeRoutingAccessControlReport();
    return NextResponse.json(routingReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('seoUrlReport') === 'true') {
    const seoReport = generateAuthoritativeSeoAndUrlHardeningReport();
    return NextResponse.json(seoReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('performanceReport') === 'true') {
    const perfReport = generateAuthoritativePerformanceScalabilityReport();
    return NextResponse.json(perfReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('privacyConsentReport') === 'true') {
    const privacyReport = generateAuthoritativePrivacyConsentReport();
    return NextResponse.json(privacyReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('googleSecurityReport') === 'true') {
    const googleSecReport = generateAuthoritativeGoogleSecurityReport();
    return NextResponse.json(googleSecReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('adminControlPlaneReport') === 'true') {
    const adminCtrlReport = generateAuthoritativeAdminControlPlaneReport();
    return NextResponse.json(adminCtrlReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('certificateGovernanceReport') === 'true') {
    const certReport = generateAuthoritativeCertificateGovernanceReport();
    return NextResponse.json(certReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('paymentGovernanceReport') === 'true') {
    const paymentReport = generateAuthoritativePaymentGovernanceReport();
    return NextResponse.json(paymentReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('examEngineReport') === 'true') {
    const examReport = generateAuthoritativeExamEngineReport();
    return NextResponse.json(examReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('webSecurityReport') === 'true') {
    const webSecReport = generateAuthoritativeWebSecurityReport();
    return NextResponse.json(webSecReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('fileSecurityReport') === 'true') {
    const fileSecReport = generateAuthoritativeFileSecurityReport();
    return NextResponse.json(fileSecReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('databaseGovernanceReport') === 'true') {
    const dbReport = generateAuthoritativeDatabaseGovernanceReport();
    return NextResponse.json(dbReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('apiContractReport') === 'true') {
    const apiReport = generateAuthoritativeApiContractReport();
    return NextResponse.json(apiReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('observabilityReport') === 'true') {
    const obsReport = generateAuthoritativeObservabilityControlReport();
    return NextResponse.json(obsReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('dataLifecycleReport') === 'true') {
    const lifecycleReport = generateAuthoritativeDataLifecycleReport();
    return NextResponse.json(lifecycleReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('monitoringReport') === 'true') {
    const monitoringReport = generateAuthoritativeFinalMonitoringReport();
    return NextResponse.json(monitoringReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('releaseReport') === 'true') {
    const releaseReport = generateAuthoritativeReleaseControlReport();
    return NextResponse.json(releaseReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('goNoGoReport') === 'true') {
    const goNoGoReport = evaluateMasterGoNoGoChain();
    return NextResponse.json(goNoGoReport, { status: 200 });
  }

  if (req.nextUrl.searchParams.get('phaseReport') === 'true') {
    const phaseReport = getAuthoritative31PhaseImplementationReport();
    return NextResponse.json(phaseReport, { status: 200 });
  }

  const incidentId = req.nextUrl.searchParams.get('incidentId')?.trim() || '';
  const exportBundle = req.nextUrl.searchParams.get('export') === 'true';

  if (!incidentId) {
    return NextResponse.json(
      { error: 'incidentId query parameter is required.' },
      { status: 400 }
    );
  }

  if (exportBundle) {
    const exported = exportIncidentAuditBundle({
      incidentId,
      actor: auth.user.name || auth.user.id,
      actorRole: auth.user.role,
    });
    if (!exported.ok) {
      return NextResponse.json(
        { error: exported.error },
        { status: exported.httpStatus }
      );
    }
    return NextResponse.json(
      {
        incident_id: exported.bundle.incident.incidentId,
        status: exported.bundle.incident.status,
        enum_version: INCIDENT_STATUS_ENUM_VERSION,
        bundle: exported.bundle,
      },
      { status: 200 }
    );
  }

  const incident = getAuthoritativeIncident(incidentId);
  if (!incident) {
    return NextResponse.json(
      { error: 'Not Found: Incident does not exist.' },
      { status: 404 }
    );
  }

  return NextResponse.json(
    {
      incident_id: incident.incidentId,
      status: incident.status,
      version: incident.version,
      severity: incident.severity,
      priority: incident.priority,
      enum_version: INCIDENT_STATUS_ENUM_VERSION,
    },
    { status: 200 }
  );
}

export async function POST(req: NextRequest) {
  // 1. Authenticate first before parsing body (INVARIANT-01 & INVARIANT-08)
  const authUser = requireAuthenticatedUser(req);
  if (!authUser.ok) {
    return authUser.response;
  }

  const roleCheck = requireAdmin(req);
  if (!roleCheck.ok) {
    return roleCheck.response;
  }

  // 2. Rate limiting (429 Too Many Requests)
  const rate = enforceRateLimit(
    `incident_api:${authUser.user.id}`,
    60,
    60_000
  );
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Too Many Requests: Rate limit exceeded.' },
      { status: 429 }
    );
  }

  try {
    const body = await req.json();
    const action = typeof body?.action === 'string' ? body.action : 'TRANSITION';

    if (action === 'CREATE') {
      const created = createProductionIncident({
        incidentId: String(body?.incident_id || ''),
        title: String(body?.title || ''),
        initialDescription: String(body?.initial_description || ''),
        detectionSource: String(body?.detection_source || ''),
        environment: body?.environment || 'production',
        actor: authUser.user.name || authUser.user.id,
        actorRole: authUser.user.role,
      });
      if (!created.ok) {
        return NextResponse.json({ error: created.error }, { status: 422 });
      }
      return NextResponse.json(
        {
          incident_id: created.incident.incidentId,
          status: created.incident.status,
          version: created.incident.version,
          severity: created.incident.severity,
          priority: created.incident.priority,
        },
        { status: 200 }
      );
    }

    if (action === 'GUARDED_TRANSITION') {
      const guarded = executeGuardedIncidentTransition({
        incidentId: String(body?.incident_id || ''),
        currentStatus: body?.current_status,
        requestedStatus: body?.requested_status,
        incidentVersion: Number(body?.expected_version),
        transitionId: String(body?.transition_id || `TRN-${Date.now()}`),
        actor: {
          authenticated: true,
          sessionValid: true,
          actorId: authUser.user.id,
          actorName: authUser.user.name || authUser.user.id,
          actorRole: authUser.user.role, // Server-authoritative role
        },
        evidence: {
          evidenceReference: body?.evidence_reference,
          reason: body?.reason,
          timestamped: true,
          attributable: true,
          integrityPreserving: true,
        },
        approvals: body?.approvals,
        transitionMetadata: {
          ...body?.transition_metadata,
          clientSuppliedTampering: {
            client_user_id: body?.client_user_id,
            client_role: body?.client_role,
            incident_owner_id: body?.incident_owner_id,
          },
        },
      });
      return NextResponse.json(guarded, { status: guarded.httpStatus });
    }

    const result = executeAtomicIncidentStatusTransition({
      incidentId: String(body?.incident_id || ''),
      requestedStatus: body?.requested_status,
      expectedVersion: Number(body?.expected_version),
      transitionId: String(body?.transition_id || `TRN-${Date.now()}`),
      actor: authUser.user.name || authUser.user.id,
      actorRole: authUser.user.role, // Server-authoritative role; ignores any client-supplied role
      reason: String(body?.reason || ''),
      evidenceReference: String(body?.evidence_reference || ''),
      relatedVerificationId: body?.related_verification_id,
      relatedDeploymentId: body?.related_deployment_id,
      approvalReference: body?.approval_reference,
      preconditions: body?.preconditions,
    });

    return NextResponse.json(result, { status: result.httpStatus });
  } catch {
    return NextResponse.json(
      { error: 'Invalid JSON request payload.' },
      { status: 400 }
    );
  }
}
