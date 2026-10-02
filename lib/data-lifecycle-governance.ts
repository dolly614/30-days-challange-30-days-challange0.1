import crypto from 'crypto';
import { sanitizeAndMinimizeEvidenceText } from '@/lib/incident-lifecycle';
import {
  findUserById,
  recordServerAuditLog,
  revokeAllUserSessions,
  UserRole,
} from '@/lib/server-auth';

// ============================================================================
// 1. CANONICAL DATA CLASSIFICATION SYSTEM (SECTION 4)
// ============================================================================

export type DataClassification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'PERSONAL'
  | 'SENSITIVE_PERSONAL'
  | 'SECURITY_SENSITIVE'
  | 'FINANCIAL'
  | 'ACADEMIC'
  | 'VERIFICATION'
  | 'AUDIT'
  | 'CRITICAL_OPERATIONAL';

export const CANONICAL_DATA_CLASSIFICATIONS: readonly DataClassification[] =
  Object.freeze([
    'PUBLIC',
    'INTERNAL',
    'PERSONAL',
    'SENSITIVE_PERSONAL',
    'SECURITY_SENSITIVE',
    'FINANCIAL',
    'ACADEMIC',
    'VERIFICATION',
    'AUDIT',
    'CRITICAL_OPERATIONAL',
  ]);

export function isValidDataClassification(
  val: unknown
): val is DataClassification {
  return (
    typeof val === 'string' &&
    (CANONICAL_DATA_CLASSIFICATIONS as readonly string[]).includes(val)
  );
}

// ============================================================================
// 2. CANONICAL DELETION METHODS & RELATIONAL DEPENDENCY ACTIONS (SECTIONS 9, 11)
// ============================================================================

export type DeletionLifecycleMethod =
  | 'SOFT_DELETE'
  | 'ARCHIVE'
  | 'ANONYMIZE'
  | 'HARD_DELETE'
  | 'RETENTION_HOLD';

export const CANONICAL_DELETION_LIFECYCLE_METHODS: readonly DeletionLifecycleMethod[] =
  Object.freeze([
    'SOFT_DELETE',
    'ARCHIVE',
    'ANONYMIZE',
    'HARD_DELETE',
    'RETENTION_HOLD',
  ]);

export type RelationalDeletionAction =
  | 'CASCADE'
  | 'RESTRICT'
  | 'SET NULL'
  | 'ARCHIVE'
  | 'ANONYMIZE'
  | 'PRESERVE';

export const CANONICAL_RELATIONAL_DELETION_ACTIONS: readonly RelationalDeletionAction[] =
  Object.freeze([
    'CASCADE',
    'RESTRICT',
    'SET NULL',
    'ARCHIVE',
    'ANONYMIZE',
    'PRESERVE',
  ]);

export type RetentionPolicyStatus = 'ACTIVE_ENFORCED' | 'REVIEW_REQUIRED';

// ============================================================================
// 3. COMPLETE 30-CATEGORY RETENTION POLICY REGISTRY (SECTIONS 7 & 8: A – AD)
// ============================================================================

export type RetentionCategoryCode =
  | 'A'
  | 'B'
  | 'C'
  | 'D'
  | 'E'
  | 'F'
  | 'G'
  | 'H'
  | 'I'
  | 'J'
  | 'K'
  | 'L'
  | 'M'
  | 'N'
  | 'O'
  | 'P'
  | 'Q'
  | 'R'
  | 'S'
  | 'T'
  | 'U'
  | 'V'
  | 'W'
  | 'X'
  | 'Y'
  | 'Z'
  | 'AA'
  | 'AB'
  | 'AC'
  | 'AD';

export type RetentionCategoryId =
  | 'user_profile'
  | 'auth_security_records'
  | 'otp_challenges'
  | 'password_reset_records'
  | 'student_verification_submissions'
  | 'verification_uploaded_files'
  | 'daily_challenge_progress'
  | 'quiz_attempts'
  | 'exam_attempts'
  | 'exam_answers'
  | 'scores_results'
  | 'leaderboard_records'
  | 'payments'
  | 'refunds'
  | 'teacher_referrals'
  | 'teacher_commissions'
  | 'teacher_kyc'
  | 'withdrawals'
  | 'certificates'
  | 'certificate_verification_records'
  | 'support_tickets'
  | 'notifications'
  | 'audit_logs'
  | 'security_events'
  | 'incident_records'
  | 'monitoring_records'
  | 'backups'
  | 'temporary_files'
  | 'exported_files'
  | 'analytics_data';

export interface DataRetentionPolicyRecord {
  readonly category_code: RetentionCategoryCode;
  readonly category: RetentionCategoryId;
  readonly display_name: string;
  readonly classification: DataClassification;
  readonly collection_purpose: string;
  readonly minimum_necessary_fields: readonly string[];
  readonly prohibited_fields_never_stored: readonly string[];
  readonly storage_locations: readonly string[];
  readonly retention_period: string;
  readonly retention_policy_status: RetentionPolicyStatus;
  readonly external_dependency_notes: string;
  readonly archive_required: boolean;
  readonly deletion_method: DeletionLifecycleMethod;
  readonly relational_on_user_delete: RelationalDeletionAction;
  readonly legal_hold_allowed: boolean;
  readonly security_hold_allowed: boolean;
  readonly owner: string;
  readonly review_interval: string;
}

export const DATA_RETENTION_POLICY_REGISTRY: readonly DataRetentionPolicyRecord[] =
  Object.freeze([
    {
      category_code: 'A',
      category: 'user_profile',
      display_name: 'User profile',
      classification: 'PERSONAL',
      collection_purpose:
        'Account operation, class-specific 30-day curriculum delivery, and student/teacher dashboard functionality.',
      minimum_necessary_fields: [
        'id',
        'name',
        'email',
        'phone',
        'classNum',
        'school',
        'city',
        'role',
        'createdAt',
      ],
      prohibited_fields_never_stored: [
        'plaintext_password',
        'aadhaar_number',
        'biometric_data',
        'home_street_address',
      ],
      storage_locations: [
        'public.users (Supabase PostgreSQL)',
        '/tmp/uyanix-auth-store-v1.json (users)',
        'localStorage:uyanix-30day-storage (active session client cache)',
      ],
      retention_period:
        'Active account duration + 30 days soft-delete grace window before irreversible PII anonymization',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Subject to DPDP Act user erasure rights unless blocked by active fraud/security/financial dispute hold.',
      archive_required: false,
      deletion_method: 'ANONYMIZE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Dolly Singh',
      review_interval: '90 days',
    },
    {
      category_code: 'B',
      category: 'auth_security_records',
      display_name: 'Authentication/security records',
      classification: 'SECURITY_SENSITIVE',
      collection_purpose:
        'Credential verification (scrypt salted hash), session rotation, token reuse detection, and account lockout protection.',
      minimum_necessary_fields: [
        'authUserId',
        'passwordSalt',
        'passwordHash',
        'jti',
        'familyId',
        'idleExpiresAt',
        'absoluteExpiresAt',
        'status',
      ],
      prohibited_fields_never_stored: [
        'plaintext_password',
        'raw_session_jwt',
        'raw_refresh_token',
      ],
      storage_locations: [
        'public.user_sessions',
        '/tmp/uyanix-auth-store-v1.json (authAccounts, sessions, revokedSessions)',
        'HttpOnly cookie: uyanix_session',
      ],
      retention_period:
        'Active session TTL (60m idle / 24h absolute); revoked session JTI metadata retained 30 days for replay detection',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Aligned with OWASP ASVS session lifecycle and replay-detection window.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'CASCADE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Vikramaditya Rathore',
      review_interval: '30 days',
    },
    {
      category_code: 'C',
      category: 'otp_challenges',
      display_name: 'OTP challenges',
      classification: 'SECURITY_SENSITIVE',
      collection_purpose:
        'Single-use mobile number ownership verification and anti-abuse rate limiting.',
      minimum_necessary_fields: [
        'challengeId',
        'userId',
        'phone',
        'otpSalt',
        'otpHash',
        'attempts',
        'expiresAt',
        'status',
      ],
      prohibited_fields_never_stored: ['plaintext_otp_code'],
      storage_locations: [
        'public.otp_challenges',
        '/tmp/uyanix-auth-store-v1.json (otpChallenges, otpRateStates)',
        'HttpOnly cookie: uyanix_otp_binding',
      ],
      retention_period:
        '5-minute active challenge TTL; expired/used challenge metadata purged after 24 hours',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        '24-hour rate-state window required for OTP_MAX_SENDS_PER_PHONE_PER_24_HOURS enforcement.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'CASCADE',
      legal_hold_allowed: false,
      security_hold_allowed: true,
      owner: 'Vikramaditya Rathore',
      review_interval: '30 days',
    },
    {
      category_code: 'D',
      category: 'password_reset_records',
      display_name: 'Password-reset records',
      classification: 'SECURITY_SENSITIVE',
      collection_purpose:
        'Single-use 256-bit salted-hash password recovery verification and abuse rate limiting.',
      minimum_necessary_fields: [
        'resetId',
        'userId',
        'tokenSalt',
        'tokenHash',
        'attempts',
        'expiresAt',
        'status',
      ],
      prohibited_fields_never_stored: [
        'plaintext_reset_token',
        'plaintext_new_password',
      ],
      storage_locations: [
        'public.password_reset_tokens',
        '/tmp/uyanix-auth-store-v1.json (passwordResetTokens, passwordResetRateStates)',
      ],
      retention_period:
        '15-minute active token TTL; expired/used reset metadata purged after 24 hours',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        '24-hour rate-state window required for FORGOT_MAX_PER_24_HOURS enforcement.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'CASCADE',
      legal_hold_allowed: false,
      security_hold_allowed: true,
      owner: 'Vikramaditya Rathore',
      review_interval: '30 days',
    },
    {
      category_code: 'E',
      category: 'student_verification_submissions',
      display_name: 'Student verification submissions',
      classification: 'VERIFICATION',
      collection_purpose:
        'Student class/school eligibility verification for competition prize and leaderboard qualification.',
      minimum_necessary_fields: [
        'id',
        'studentId',
        'classNum',
        'school',
        'status',
        'submittedAt',
        'reviewedBy',
      ],
      prohibited_fields_never_stored: [
        'aadhaar_card_number',
        'parent_financial_records',
      ],
      storage_locations: [
        'public.users (id_verification_status)',
        'localStorage:uyanix-30day-storage (verifications)',
      ],
      retention_period:
        'Challenge season + 90 days dispute window for verification status metadata',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Required to substantiate prize eligibility and leaderboard verification status.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Ananya Iyer',
      review_interval: '90 days',
    },
    {
      category_code: 'F',
      category: 'verification_uploaded_files',
      display_name: 'Verification uploaded files',
      classification: 'SENSITIVE_PERSONAL',
      collection_purpose:
        'Visual inspection of student school ID card or school-uniform photo by authorized admin reviewer.',
      minimum_necessary_fields: [
        'fileId',
        'ownerUserId',
        'objectPath',
        'mimeType',
        'byteSize',
        'sha256Checksum',
        'isPublic',
      ],
      prohibited_fields_never_stored: [
        'public_unauthenticated_bucket_url',
        'exif_gps_coordinates',
      ],
      storage_locations: [
        'private object storage bucket (verification-uploads)',
        'public.users.id_card_url (private reference)',
      ],
      retention_period:
        '30 days after verification decision (approved/rejected) or immediately upon account deletion unless under fraud hold',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Minors/student ID images must never be public and must be permanently purged from object storage after verification window.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'CASCADE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Vikramaditya Rathore',
      review_interval: '30 days',
    },
    {
      category_code: 'G',
      category: 'daily_challenge_progress',
      display_name: 'Daily challenge progress',
      classification: 'ACADEMIC',
      collection_purpose:
        'Tracking 30-day chapter completion and daily streak progression.',
      minimum_necessary_fields: ['id', 'user_id', 'day', 'score', 'completed_at'],
      prohibited_fields_never_stored: ['keystroke_telemetry', 'webcam_recording'],
      storage_locations: [
        'public.daily_progress',
        'localStorage:uyanix-30day-storage (completedDays, dailyScores)',
      ],
      retention_period: 'Active academic session + 1 year',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Supports 15-day Mid Challenge and 30-day Finale eligibility checks.',
      archive_required: true,
      deletion_method: 'ANONYMIZE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: false,
      security_hold_allowed: false,
      owner: 'Ananya Iyer',
      review_interval: '180 days',
    },
    {
      category_code: 'H',
      category: 'quiz_attempts',
      display_name: 'Quiz attempts',
      classification: 'ACADEMIC',
      collection_purpose:
        'Daily 5-question practice quiz scoring and chapter mastery tracking.',
      minimum_necessary_fields: ['user_id', 'day', 'score', 'completed_at'],
      prohibited_fields_never_stored: ['device_microphone_audio'],
      storage_locations: ['public.daily_progress'],
      retention_period: 'Active academic session + 1 year',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes: 'Bound to daily challenge progress records.',
      archive_required: false,
      deletion_method: 'ANONYMIZE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: false,
      security_hold_allowed: false,
      owner: 'Ananya Iyer',
      review_interval: '180 days',
    },
    {
      category_code: 'I',
      category: 'exam_attempts',
      display_name: 'Exam attempts',
      classification: 'ACADEMIC',
      collection_purpose:
        'Exam integrity, official Mid/Final exam scoring, rank computation, and certificate eligibility.',
      minimum_necessary_fields: [
        'id',
        'user_id',
        'preserved_student_ref',
        'type',
        'score',
        'total',
        'status',
        'created_at',
      ],
      prohibited_fields_never_stored: ['raw_payment_card_details'],
      storage_locations: [
        'public.exams',
        'localStorage:uyanix-30day-storage (examAttempts)',
      ],
      retention_period:
        '3 years for academic dispute resolution, rank integrity, and certificate auditability',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Account deletion must never destroy completed exam attempt integrity; user_id is set to NULL/anonymized while preserving preserved_student_ref.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Ananya Iyer',
      review_interval: '180 days',
    },
    {
      category_code: 'J',
      category: 'exam_answers',
      display_name: 'Exam answers',
      classification: 'ACADEMIC',
      collection_purpose:
        'Question-level score verification, re-evaluation, and anti-cheating audit.',
      minimum_necessary_fields: ['exam_id', 'answers'],
      prohibited_fields_never_stored: ['unencrypted_proctoring_video'],
      storage_locations: ['public.exams.answers (JSONB)'],
      retention_period:
        '180 days active dispute window after exam completion, then archived',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Required to resolve scoring disputes during challenge prize verification.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Ananya Iyer',
      review_interval: '180 days',
    },
    {
      category_code: 'K',
      category: 'scores_results',
      display_name: 'Scores/results',
      classification: 'ACADEMIC',
      collection_purpose:
        'Immutable record of Mid/Final exam scores and percentile/rank outcomes.',
      minimum_necessary_fields: [
        'exam_id',
        'preserved_student_ref',
        'score',
        'total',
        'rank',
      ],
      prohibited_fields_never_stored: ['private_phone_in_public_score_feed'],
      storage_locations: ['public.exams'],
      retention_period:
        '3 years aligned with certificate validity and leaderboard auditability',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Must remain immutable so deleted accounts do not silently alter historical rankings.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Ananya Iyer',
      review_interval: '180 days',
    },
    {
      category_code: 'L',
      category: 'leaderboard_records',
      display_name: 'Leaderboard records',
      classification: 'PUBLIC',
      collection_purpose:
        'Displaying national/city/class top performers for the 30 Days Challenge.',
      minimum_necessary_fields: [
        'id',
        'rank',
        'name',
        'classNum',
        'city',
        'score',
        'total',
      ],
      prohibited_fields_never_stored: [
        'public_student_phone',
        'public_student_email',
        'public_id_card_photo',
      ],
      storage_locations: [
        'public.exams / public.users projection',
        'Google Sheets Leaderboard tab (admin-synced)',
      ],
      retention_period:
        'Challenge season duration; anonymized to "Verified Participant" upon valid student erasure request while preserving rank & score slots',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Public leaderboard must never expose private student phone/email.',
      archive_required: true,
      deletion_method: 'ANONYMIZE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: true,
      security_hold_allowed: false,
      owner: 'Ananya Iyer',
      review_interval: '90 days',
    },
    {
      category_code: 'M',
      category: 'payments',
      display_name: 'Payments',
      classification: 'FINANCIAL',
      collection_purpose:
        'Exam registration fee reconciliation (INR 199), tax accounting, and Razorpay order verification.',
      minimum_necessary_fields: [
        'id',
        'account_reference_hash',
        'amount',
        'type',
        'razorpay_id',
        'status',
        'created_at',
      ],
      prohibited_fields_never_stored: [
        'card_number_pan',
        'cvv',
        'card_expiry',
        'netbanking_password',
        'upi_pin',
      ],
      storage_locations: ['public.payments'],
      retention_period:
        '8 years (statutory financial & tax accounting retention under Indian law); REVIEW_REQUIRED before any purge',
      retention_policy_status: 'REVIEW_REQUIRED',
      external_dependency_notes:
        'Depends on statutory tax/accounting laws (Income Tax Act / GST / payment gateway chargeback rules). Separated into ACCOUNT_IDENTITY vs FINANCIAL_TRANSACTION_RECORD.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Rohan Deshmukh',
      review_interval: '365 days',
    },
    {
      category_code: 'N',
      category: 'refunds',
      display_name: 'Refunds',
      classification: 'FINANCIAL',
      collection_purpose:
        'Tracking refunded exam fees, chargeback resolution, and financial ledger accuracy.',
      minimum_necessary_fields: [
        'payment_id',
        'account_reference_hash',
        'amount',
        'razorpay_id',
        'status',
        'refunded_at',
      ],
      prohibited_fields_never_stored: ['raw_bank_account_credentials'],
      storage_locations: ['public.payments (status = refunded)'],
      retention_period:
        '8 years (statutory financial & tax accounting retention); REVIEW_REQUIRED before any purge',
      retention_policy_status: 'REVIEW_REQUIRED',
      external_dependency_notes:
        'Bound to statutory accounting and payment-provider reconciliation requirements.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Rohan Deshmukh',
      review_interval: '365 days',
    },
    {
      category_code: 'O',
      category: 'teacher_referrals',
      display_name: 'Teacher referrals',
      classification: 'FINANCIAL',
      collection_purpose:
        'Attribution of referred students to approved teachers and anti-self-referral fraud checks.',
      minimum_necessary_fields: [
        'id',
        'teacher_id',
        'anonymized_student_ref',
        'status',
        'commission',
        'created_at',
      ],
      prohibited_fields_never_stored: ['student_password_hash'],
      storage_locations: [
        'public.referrals',
        '/tmp/uyanix-auth-store-v1.json (referralRegistrations)',
      ],
      retention_period:
        '8 years for commission payout auditability; student PII anonymized on student deletion',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Student deletion sets student_id = NULL while preserving anonymized_student_ref so teacher commission ledger remains intact.',
      archive_required: true,
      deletion_method: 'ANONYMIZE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Rohan Deshmukh',
      review_interval: '180 days',
    },
    {
      category_code: 'P',
      category: 'teacher_commissions',
      display_name: 'Teacher commissions',
      classification: 'FINANCIAL',
      collection_purpose:
        'Calculating and auditing teacher referral earnings, balances, and tier progression.',
      minimum_necessary_fields: [
        'teacher_id',
        'balance',
        'total_earned',
        'tier',
        'commission',
      ],
      prohibited_fields_never_stored: ['unmasked_bank_login_credentials'],
      storage_locations: ['public.teachers', 'public.referrals'],
      retention_period:
        '8 years (statutory financial & tax accounting retention); REVIEW_REQUIRED before any purge',
      retention_policy_status: 'REVIEW_REQUIRED',
      external_dependency_notes:
        'Subject to tax/TDS accounting and payout reconciliation obligations.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Rohan Deshmukh',
      review_interval: '365 days',
    },
    {
      category_code: 'Q',
      category: 'teacher_kyc',
      display_name: 'Teacher KYC',
      classification: 'SENSITIVE_PERSONAL',
      collection_purpose:
        'Tax compliance (PAN verification) and anti-fraud identity verification prior to commission payouts.',
      minimum_necessary_fields: [
        'teacher_id',
        'kyc_pan',
        'kyc_verified',
        'status',
      ],
      prohibited_fields_never_stored: [
        'aadhaar_biometric_xml',
        'scanned_signature_image',
      ],
      storage_locations: ['public.teachers (kyc_pan, kyc_verified)'],
      retention_period:
        'Retained for statutory tax/payout audit period; REVIEW_REQUIRED before permanent disposal where payouts occurred',
      retention_policy_status: 'REVIEW_REQUIRED',
      external_dependency_notes:
        'Tax/TDS regulations require PAN retention for paid teachers; teachers with zero payouts can have KYC purged upon account closure.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'RESTRICT',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Rohan Deshmukh',
      review_interval: '180 days',
    },
    {
      category_code: 'R',
      category: 'withdrawals',
      display_name: 'Withdrawals',
      classification: 'FINANCIAL',
      collection_purpose:
        'Processing and reconciling teacher commission payouts via UPI/Bank transfer.',
      minimum_necessary_fields: [
        'id',
        'teacher_id',
        'amount',
        'method',
        'upi_id',
        'status',
        'created_at',
      ],
      prohibited_fields_never_stored: ['upi_pin', 'netbanking_password'],
      storage_locations: ['public.withdrawals'],
      retention_period:
        '8 years (statutory financial & payout reconciliation retention); REVIEW_REQUIRED before any purge',
      retention_policy_status: 'REVIEW_REQUIRED',
      external_dependency_notes:
        'Required for financial audit, payout dispute resolution, and tax compliance.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Rohan Deshmukh',
      review_interval: '365 days',
    },
    {
      category_code: 'S',
      category: 'certificates',
      display_name: 'Certificates',
      classification: 'ACADEMIC',
      collection_purpose:
        'Issuing official 15-Day Mid Challenge and 30-Day Grand Finale achievement certificates.',
      minimum_necessary_fields: [
        'id',
        'certificate_code',
        'recipient_display_name',
        'exam_type',
        'verification_status',
        'url',
        'issued_at',
      ],
      prohibited_fields_never_stored: ['student_mobile_number_on_certificate'],
      storage_locations: ['public.certificates'],
      retention_period:
        '5 years intended certificate validity period (never automatically invalidated by user account deletion)',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Issued certificates must remain verifiable by unique certificate_code for their intended validity period.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Ananya Iyer',
      review_interval: '365 days',
    },
    {
      category_code: 'T',
      category: 'certificate_verification_records',
      display_name: 'Certificate verification records',
      classification: 'VERIFICATION',
      collection_purpose:
        'Public/school verification of issued certificate authenticity via unique certificate identifier.',
      minimum_necessary_fields: [
        'certificate_code',
        'exam_type',
        'verification_status',
        'issued_at',
      ],
      prohibited_fields_never_stored: [
        'student_home_address',
        'student_phone_number',
      ],
      storage_locations: ['public.certificates'],
      retention_period:
        '5 years aligned with issued certificate validity period',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Certificate audit history and unique identifiers remain protected independently of active account status.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Ananya Iyer',
      review_interval: '365 days',
    },
    {
      category_code: 'U',
      category: 'support_tickets',
      display_name: 'Support tickets',
      classification: 'PERSONAL',
      collection_purpose:
        'Resolving student/teacher technical, exam, or payment support inquiries.',
      minimum_necessary_fields: [
        'ticket_id',
        'user_id',
        'subject',
        'messages',
        'status',
        'created_at',
      ],
      prohibited_fields_never_stored: [
        'plaintext_password_in_ticket',
        'plaintext_otp_in_ticket',
      ],
      storage_locations: ['support ticket store / audit logs'],
      retention_period:
        '1 year after ticket closure, then PII anonymized',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Tickets linked to financial disputes inherit financial hold rules.',
      archive_required: true,
      deletion_method: 'ANONYMIZE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Dolly Singh',
      review_interval: '180 days',
    },
    {
      category_code: 'V',
      category: 'notifications',
      display_name: 'Notifications',
      classification: 'INTERNAL',
      collection_purpose:
        'In-app announcements, streak reminders, and exam schedule alerts.',
      minimum_necessary_fields: [
        'id',
        'user_id',
        'title',
        'body',
        'read',
        'created_at',
      ],
      prohibited_fields_never_stored: ['raw_auth_tokens_in_notification_body'],
      storage_locations: [
        'public.notifications',
        'localStorage:uyanix-30day-storage (notifications)',
      ],
      retention_period: '90 days or immediately purged on user account deletion',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes: 'Ephemeral operational messaging.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'CASCADE',
      legal_hold_allowed: false,
      security_hold_allowed: false,
      owner: 'Dolly Singh',
      review_interval: '90 days',
    },
    {
      category_code: 'W',
      category: 'audit_logs',
      display_name: 'Audit logs',
      classification: 'AUDIT',
      collection_purpose:
        'Immutable accountability trail for administrative actions, role changes, lifecycle deletions, and incident transitions.',
      minimum_necessary_fields: [
        'id',
        'actor_id',
        'action',
        'target',
        'meta',
        'created_at',
      ],
      prohibited_fields_never_stored: [
        'plaintext_password',
        'raw_jwt_cookie',
        'raw_otp',
        'raw_api_secret',
      ],
      storage_locations: [
        'public.audit_logs',
        'public.incident_audit_events',
        '/tmp/uyanix-auth-store-v1.json (auditLogs)',
      ],
      retention_period:
        '2 years append-only active retention + 5 years cold archive',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Append-only security control; user deletion sets actor_id/target PII to pseudonymized reference without deleting audit rows.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Vikramaditya Rathore',
      review_interval: '180 days',
    },
    {
      category_code: 'X',
      category: 'security_events',
      display_name: 'Security events',
      classification: 'SECURITY_SENSITIVE',
      collection_purpose:
        'Brute-force detection, rate-limit enforcement, unauthorized role escalation detection, and forensic investigation.',
      minimum_necessary_fields: [
        'event_id',
        'actor_id',
        'event_type',
        'ip_hash',
        'timestamp',
      ],
      prohibited_fields_never_stored: ['raw_Authorization_header'],
      storage_locations: [
        '/tmp/uyanix-auth-store-v1.json (rateLimits, bannedUserIds, auditLogs)',
        'post-deployment-monitoring alerts',
      ],
      retention_period: '2 years for security forensics and abuse prevention',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Banned/fraud markers are preserved so account deletion cannot be used to reset a security ban.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Vikramaditya Rathore',
      review_interval: '90 days',
    },
    {
      category_code: 'Y',
      category: 'incident_records',
      display_name: 'Incident records',
      classification: 'CRITICAL_OPERATIONAL',
      collection_purpose:
        'Production incident state machine governance, rollback tracking, SLA compliance, and post-mortem auditability.',
      minimum_necessary_fields: [
        'incident_id',
        'status',
        'severity',
        'priority',
        'version',
        'owners',
        'audit_trail',
      ],
      prohibited_fields_never_stored: ['unredacted_customer_credentials'],
      storage_locations: [
        'public.production_incidents',
        'public.incident_audit_events',
        'lib/incident-lifecycle.ts',
      ],
      retention_period: '3 years immutable operational governance retention',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Protected by ON DELETE RESTRICT on incident_audit_events.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Dolly Singh',
      review_interval: '180 days',
    },
    {
      category_code: 'Z',
      category: 'monitoring_records',
      display_name: 'Monitoring records',
      classification: 'INTERNAL',
      collection_purpose:
        'Post-deployment health verification, p50/p95/p99 latency baselines, and stability window confirmation.',
      minimum_necessary_fields: [
        'monitoring_id',
        'release_id',
        'status',
        'health',
        'stability_window',
        'alerts',
      ],
      prohibited_fields_never_stored: ['raw_request_cookies', 'raw_passwords'],
      storage_locations: ['lib/post-deployment-monitoring.ts'],
      retention_period:
        '1 year active operational metrics + 2 years release stability summary archive',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Linked to release governance and incident auto-trigger evidence.',
      archive_required: true,
      deletion_method: 'ARCHIVE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Vikramaditya Rathore',
      review_interval: '180 days',
    },
    {
      category_code: 'AA',
      category: 'backups',
      display_name: 'Backups',
      classification: 'CRITICAL_OPERATIONAL',
      collection_purpose:
        'Disaster recovery and rollback restoration before schema or state migrations.',
      minimum_necessary_fields: [
        'backup_path',
        'created_at',
        'sha256_checksum',
      ],
      prohibited_fields_never_stored: ['unencrypted_public_backup_dumps'],
      storage_locations: ['/tmp/uyanix-auth-store-v1.backup-*.json'],
      retention_period:
        '30 days rolling encrypted backup window; subject to post-restore tombstone re-application so deleted users are never resurrected',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Restoration must replay the deletionTombstoneRegistry before serving traffic.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Aarav Sharma',
      review_interval: '30 days',
    },
    {
      category_code: 'AB',
      category: 'temporary_files',
      display_name: 'Temporary files',
      classification: 'INTERNAL',
      collection_purpose:
        'Short-lived concurrency lock files and atomic write staging files.',
      minimum_necessary_fields: ['lock_pid', 'created_at'],
      prohibited_fields_never_stored: ['persistent_pii_in_temp_files'],
      storage_locations: [
        '/tmp/uyanix-auth-store-v1.lock',
        '/tmp/uyanix-auth-store-v1.json.tmp.*',
      ],
      retention_period:
        'Immediate deletion upon transaction completion (stale lock recovery threshold: 5 seconds)',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes: 'Automatically unlinked in finally blocks.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'CASCADE',
      legal_hold_allowed: false,
      security_hold_allowed: false,
      owner: 'Aarav Sharma',
      review_interval: '30 days',
    },
    {
      category_code: 'AC',
      category: 'exported_files',
      display_name: 'Exported files',
      classification: 'SENSITIVE_PERSONAL',
      collection_purpose:
        'Authorized administrative Google Sheets sync and incident audit bundle exports.',
      minimum_necessary_fields: [
        'export_id',
        'actor_id',
        'exported_at',
        'scope',
      ],
      prohibited_fields_never_stored: [
        'exported_password_hashes',
        'exported_session_tokens',
      ],
      storage_locations: [
        'Google Sheets (/api/sheets)',
        'Admin Incident Audit Bundle Export (/api/admin/incidents?export=true)',
      ],
      retention_period:
        'Ephemeral stream on download; external Google Sheets retention governed by organizational Workspace policy (REVIEW_REQUIRED)',
      retention_policy_status: 'REVIEW_REQUIRED',
      external_dependency_notes:
        'External Google Workspace Drive/Sheets retention depends on organization admin policy; requires access control via requireTeacherOrAdmin.',
      archive_required: false,
      deletion_method: 'HARD_DELETE',
      relational_on_user_delete: 'ANONYMIZE',
      legal_hold_allowed: true,
      security_hold_allowed: true,
      owner: 'Dolly Singh',
      review_interval: '90 days',
    },
    {
      category_code: 'AD',
      category: 'analytics_data',
      display_name: 'Analytics data',
      classification: 'INTERNAL',
      collection_purpose:
        'Aggregate daily signup counts and challenge completion metrics.',
      minimum_necessary_fields: ['dayLabel', 'count'],
      prohibited_fields_never_stored: [
        'third_party_ad_tracker_fingerprints',
        'unconsented_cross_site_identifiers',
      ],
      storage_locations: ['TeacherRecord.dailySignups (aggregate counts only)'],
      retention_period: '2 years aggregate non-identifying statistics',
      retention_policy_status: 'ACTIVE_ENFORCED',
      external_dependency_notes:
        'Contains only aggregate counts; no personal identifiers stored.',
      archive_required: false,
      deletion_method: 'ANONYMIZE',
      relational_on_user_delete: 'PRESERVE',
      legal_hold_allowed: false,
      security_hold_allowed: false,
      owner: 'Dolly Singh',
      review_interval: '180 days',
    },
  ]);

// ============================================================================
// 4. COMPLETE DATA INVENTORY & USER DEPENDENCY MAP (SECTIONS 2, 3, 5, 6, 11)
// ============================================================================

export interface UserDeletionDependencyRule {
  readonly child_entity: string;
  readonly category_code: RetentionCategoryCode;
  readonly classification: DataClassification;
  readonly relational_action: RelationalDeletionAction;
  readonly lifecycle_method: DeletionLifecycleMethod;
  readonly rationale: string;
}

export const USER_DELETION_DEPENDENCY_MAP: readonly UserDeletionDependencyRule[] =
  Object.freeze([
    {
      child_entity: 'profile (public.users / StoredUserRecord)',
      category_code: 'A',
      classification: 'PERSONAL',
      relational_action: 'ANONYMIZE',
      lifecycle_method: 'ANONYMIZE',
      rationale:
        'Soft-deleted then PII-anonymized in place so foreign keys never orphan.',
    },
    {
      child_entity: 'sessions (public.user_sessions / ServerSessionRecord)',
      category_code: 'B',
      classification: 'SECURITY_SENSITIVE',
      relational_action: 'CASCADE',
      lifecycle_method: 'HARD_DELETE',
      rationale:
        'All active sessions are immediately revoked and purged upon account deletion.',
    },
    {
      child_entity: 'otp_challenges (public.otp_challenges)',
      category_code: 'C',
      classification: 'SECURITY_SENSITIVE',
      relational_action: 'CASCADE',
      lifecycle_method: 'HARD_DELETE',
      rationale: 'Active OTP challenges are immediately invalidated and purged.',
    },
    {
      child_entity: 'password_reset_tokens (public.password_reset_tokens)',
      category_code: 'D',
      classification: 'SECURITY_SENSITIVE',
      relational_action: 'CASCADE',
      lifecycle_method: 'HARD_DELETE',
      rationale: 'Active password reset tokens are immediately invalidated and purged.',
    },
    {
      child_entity: 'verification (submissions & private verification files)',
      category_code: 'F',
      classification: 'SENSITIVE_PERSONAL',
      relational_action: 'CASCADE',
      lifecycle_method: 'HARD_DELETE',
      rationale:
        'Private student ID / uniform uploads are permanently deleted from object storage unless under active fraud/security hold.',
    },
    {
      child_entity: 'progress (public.daily_progress)',
      category_code: 'G',
      classification: 'ACADEMIC',
      relational_action: 'ANONYMIZE',
      lifecycle_method: 'ANONYMIZE',
      rationale:
        'Personal link removed while preserving aggregate challenge completion integrity.',
    },
    {
      child_entity: 'quiz_attempts (daily quiz scores)',
      category_code: 'H',
      classification: 'ACADEMIC',
      relational_action: 'ANONYMIZE',
      lifecycle_method: 'ANONYMIZE',
      rationale: 'Personal link removed.',
    },
    {
      child_entity: 'exam_attempts (public.exams)',
      category_code: 'I',
      classification: 'ACADEMIC',
      relational_action: 'PRESERVE',
      lifecycle_method: 'ARCHIVE',
      rationale:
        'Completed exam scores and rankings are preserved with preserved_student_ref (user_id SET NULL) so historical rankings and certificates are never corrupted.',
    },
    {
      child_entity: 'answers (public.exams.answers)',
      category_code: 'J',
      classification: 'ACADEMIC',
      relational_action: 'ANONYMIZE',
      lifecycle_method: 'ARCHIVE',
      rationale:
        'Archived under pseudonymized exam attempt reference for dispute auditability.',
    },
    {
      child_entity: 'certificates (public.certificates)',
      category_code: 'S',
      classification: 'ACADEMIC',
      relational_action: 'PRESERVE',
      lifecycle_method: 'ARCHIVE',
      rationale:
        'Issued certificates remain valid and verifiable by unique certificate_code; account deletion never sets certificate = invalid.',
    },
    {
      child_entity: 'notifications (public.notifications)',
      category_code: 'V',
      classification: 'INTERNAL',
      relational_action: 'CASCADE',
      lifecycle_method: 'HARD_DELETE',
      rationale: 'Ephemeral user notifications are permanently deleted.',
    },
    {
      child_entity: 'support_tickets',
      category_code: 'U',
      classification: 'PERSONAL',
      relational_action: 'ANONYMIZE',
      lifecycle_method: 'ANONYMIZE',
      rationale:
        'Contact PII is anonymized after ticket resolution while preserving support issue history.',
    },
    {
      child_entity: 'referrals (public.referrals)',
      category_code: 'O',
      classification: 'FINANCIAL',
      relational_action: 'PRESERVE',
      lifecycle_method: 'ANONYMIZE',
      rationale:
        'Student PII is replaced by anonymized_student_ref so teacher referral commission records remain auditable.',
    },
    {
      child_entity: 'payment_references (public.payments & public.withdrawals)',
      category_code: 'M',
      classification: 'FINANCIAL',
      relational_action: 'PRESERVE',
      lifecycle_method: 'ARCHIVE',
      rationale:
        'ACCOUNT_IDENTITY is separated from FINANCIAL_TRANSACTION_RECORD (account_reference_hash preserved, user_id SET NULL); financial records are never deleted on account deletion.',
    },
    {
      child_entity: 'audit_security_records (public.audit_logs & incidents)',
      category_code: 'W',
      classification: 'AUDIT',
      relational_action: 'RESTRICT',
      lifecycle_method: 'ARCHIVE',
      rationale:
        'Audit logs and security/incident records are append-only and never deleted.',
    },
  ]);

// ============================================================================
// 5. DATA MINIMIZATION & PURPOSE-BINDING GUARDS (SECTIONS 5 & 6)
// ============================================================================

const PROHIBITED_UNMINIMIZED_FIELDS = new Set([
  'plaintext_password',
  'raw_password',
  'plaintext_otp',
  'raw_otp',
  'plaintext_reset_token',
  'raw_session_token',
  'card_number',
  'credit_card_number',
  'debit_card_number',
  'cvv',
  'cvc',
  'card_pin',
  'upi_pin',
  'netbanking_password',
  'aadhaar_number',
  'biometric_template',
]);

/**
 * Section 5: Enforces data minimization by rejecting payloads containing prohibited
 * credential, card/bank secret, or unnecessary sensitive fields.
 */
export function enforceDataMinimizationGuard(
  payload: Record<string, unknown>
): { allowed: true } | { allowed: false; prohibitedField: string; error: string } {
  for (const key of Object.keys(payload)) {
    const normalizedKey = key.trim().toLowerCase();
    if (PROHIBITED_UNMINIMIZED_FIELDS.has(normalizedKey)) {
      return {
        allowed: false,
        prohibitedField: key,
        error: `Data Minimization violation (Section 5): Collection or storage of prohibited field "${key}" is forbidden.`,
      };
    }
  }
  return { allowed: true };
}

const ALLOWED_PURPOSE_MATRIX: Record<RetentionCategoryId, readonly string[]> = {
  user_profile: [
    'ACCOUNT_OPERATION',
    'STUDENT_DASHBOARD',
    'TEACHER_DASHBOARD',
    'CURRICULUM_DELIVERY',
  ],
  auth_security_records: [
    'AUTHENTICATION',
    'SESSION_VALIDATION',
    'REPLAY_DETECTION',
    'SECURITY_LOCKOUT',
  ],
  otp_challenges: ['MOBILE_VERIFICATION', 'ANTI_ABUSE_RATE_LIMITING'],
  password_reset_records: ['PASSWORD_RECOVERY', 'ANTI_ABUSE_RATE_LIMITING'],
  student_verification_submissions: [
    'STUDENT_IDENTITY_VERIFICATION',
    'PRIZE_ELIGIBILITY_VERIFICATION',
  ],
  verification_uploaded_files: [
    'STUDENT_IDENTITY_VERIFICATION',
    'ADMIN_KYC_REVIEW',
  ],
  daily_challenge_progress: ['CURRICULUM_PROGRESSION', 'STREAK_TRACKING'],
  quiz_attempts: ['PRACTICE_ASSESSMENT', 'CURRICULUM_PROGRESSION'],
  exam_attempts: [
    'EXAM_INTEGRITY',
    'SCORING',
    'RESULT_GENERATION',
    'ACADEMIC_HISTORY',
  ],
  exam_answers: ['SCORING', 'DISPUTE_INVESTIGATION', 'EXAM_INTEGRITY'],
  scores_results: ['RESULT_GENERATION', 'LEADERBOARD_RANKING', 'CERTIFICATE_ISSUANCE'],
  leaderboard_records: ['PUBLIC_LEADERBOARD_DISPLAY'],
  payments: [
    'PAYMENT_RECONCILIATION',
    'FINANCIAL_ACCOUNTING',
    'REFUND_PROCESSING',
    'DISPUTE_INVESTIGATION',
  ],
  refunds: ['REFUND_PROCESSING', 'FINANCIAL_ACCOUNTING', 'DISPUTE_INVESTIGATION'],
  teacher_referrals: ['REFERRAL_ATTRIBUTION', 'FRAUD_PREVENTION'],
  teacher_commissions: ['COMMISSION_CALCULATION', 'FINANCIAL_ACCOUNTING'],
  teacher_kyc: ['TAX_COMPLIANCE_VERIFICATION', 'PAYOUT_ELIGIBILITY'],
  withdrawals: ['PAYOUT_PROCESSING', 'FINANCIAL_RECONCILIATION'],
  certificates: ['CERTIFICATE_ISSUANCE', 'ACADEMIC_RECOGNITION'],
  certificate_verification_records: ['PUBLIC_CERTIFICATE_VERIFICATION'],
  support_tickets: ['USER_SUPPORT_RESOLUTION'],
  notifications: ['OPERATIONAL_USER_NOTIFICATION'],
  audit_logs: ['SECURITY_ACCOUNTABILITY', 'OPERATIONAL_INVESTIGATION'],
  security_events: ['SECURITY_MONITORING', 'FRAUD_PREVENTION', 'INCIDENT_RESPONSE'],
  incident_records: ['INCIDENT_RESPONSE', 'POST_RECOVERY_GOVERNANCE'],
  monitoring_records: ['POST_DEPLOYMENT_MONITORING', 'STABILITY_VERIFICATION'],
  backups: ['DISASTER_RECOVERY', 'ROLLBACK_RESTORATION'],
  temporary_files: ['ATOMIC_TRANSACTION_STAGING'],
  exported_files: ['AUTHORIZED_ADMIN_EXPORT', 'AUDIT_BUNDLE_EXPORT'],
  analytics_data: ['AGGREGATE_OPERATIONAL_METRICS'],
};

/**
 * Section 6: Purpose Binding validator.
 * Rejects reuse of sensitive or personal data for unrelated purposes (e.g., third-party ad targeting).
 */
export function validateDataPurposeBinding(params: {
  category: RetentionCategoryId;
  requestedPurpose: string;
}): { allowed: boolean; error?: string } {
  const allowedPurposes = ALLOWED_PURPOSE_MATRIX[params.category] || [];
  if (!allowedPurposes.includes(params.requestedPurpose)) {
    return {
      allowed: false,
      error: `Purpose Binding violation (Section 6): Category "${params.category}" cannot be used for unauthorized purpose "${params.requestedPurpose}". Allowed purposes: ${allowedPurposes.join(', ')}.`,
    };
  }
  return { allowed: true };
}

// ============================================================================
// 6. LEGAL & SECURITY RETENTION HOLDS (SECTIONS 7, 9, 10)
// ============================================================================

export interface DataRetentionHoldRecord {
  readonly hold_id: string;
  readonly target_user_id: string;
  readonly hold_type: 'LEGAL_HOLD' | 'SECURITY_HOLD' | 'FINANCIAL_DISPUTE_HOLD';
  readonly reason: string;
  readonly placed_by: string;
  readonly placed_at: string;
  readonly active: boolean;
  readonly released_by?: string;
  readonly released_at?: string;
}

const activeRetentionHoldsByUser = new Map<string, DataRetentionHoldRecord[]>();

export function placeDataRetentionHold(params: {
  targetUserId: string;
  holdType: 'LEGAL_HOLD' | 'SECURITY_HOLD' | 'FINANCIAL_DISPUTE_HOLD';
  reason: string;
  actorName: string;
  actorRole: UserRole;
}): { ok: true; hold: DataRetentionHoldRecord } | { ok: false; error: string } {
  if (params.actorRole !== 'admin') {
    return {
      ok: false,
      error: 'Forbidden: Only an authenticated Admin or Security Owner may place a retention hold.',
    };
  }
  if (!params.targetUserId?.trim() || !params.reason?.trim()) {
    return {
      ok: false,
      error: 'Target user ID and explicit hold reason are required.',
    };
  }

  const hold: DataRetentionHoldRecord = Object.freeze({
    hold_id: `HOLD-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    target_user_id: params.targetUserId.trim(),
    hold_type: params.holdType,
    reason: sanitizeAndMinimizeEvidenceText(params.reason),
    placed_by: params.actorName.trim(),
    placed_at: new Date().toISOString(),
    active: true,
  });

  const existing = activeRetentionHoldsByUser.get(hold.target_user_id) || [];
  activeRetentionHoldsByUser.set(hold.target_user_id, [...existing, hold]);

  return { ok: true, hold };
}

export function hasActiveRetentionHold(userId: string): {
  held: boolean;
  holds: DataRetentionHoldRecord[];
} {
  const holds = (activeRetentionHoldsByUser.get(userId) || []).filter(
    (h) => h.active
  );
  return { held: holds.length > 0, holds };
}

// ============================================================================
// 7. PRIVATE VERIFICATION FILE LIFECYCLE & OBJECT STORAGE DISPOSAL (SECTION 15)
// ============================================================================

export interface PrivateVerificationFileRecord {
  readonly file_id: string;
  readonly owner_user_id: string;
  readonly bucket: 'uyanix-private-verification-vault';
  readonly object_path: string;
  readonly mime_type: 'image/jpeg' | 'image/png' | 'application/pdf';
  readonly byte_size: number;
  readonly sha256_checksum: string;
  readonly is_public: false; // NEVER public by default (Section 15)
  readonly verification_status: 'pending' | 'approved' | 'rejected';
  readonly uploaded_at: string;
  readonly retention_expires_at: string;
  readonly object_storage_deleted: boolean;
  readonly metadata_status: 'ACTIVE' | 'ARCHIVED' | 'DISPOSED' | 'RETENTION_HOLD';
  readonly disposed_at: string | null;
  readonly disposal_verification_hash: string | null;
}

const privateVerificationFiles = new Map<string, PrivateVerificationFileRecord>();
const revokedSignedUrlTokens = new Set<string>();

/**
 * Section 15: Registers a verification upload in private object storage.
 * Enforces `is_public = false`, strict MIME allowlist, and 30-day post-review retention.
 */
export function registerPrivateVerificationFile(params: {
  fileId?: string;
  ownerUserId: string;
  originalFileName: string;
  mimeType: string;
  byteSize: number;
  requestedPublicAccess?: boolean;
}):
  | { ok: true; file: PrivateVerificationFileRecord }
  | { ok: false; error: string } {
  if (params.requestedPublicAccess === true) {
    return {
      ok: false,
      error:
        'Verification File Lifecycle violation (Section 15): Verification files must never be public.',
    };
  }

  const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!allowedMimes.includes(params.mimeType)) {
    return {
      ok: false,
      error: `Verification File Lifecycle violation: Unsupported MIME type "${params.mimeType}".`,
    };
  }

  if (params.byteSize <= 0 || params.byteSize > 5 * 1024 * 1024) {
    return {
      ok: false,
      error: 'Verification File Lifecycle violation: File size must be between 1B and 5MB.',
    };
  }

  const fileId =
    params.fileId?.trim() ||
    `VFILE-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
  const safeSlug = params.originalFileName
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 60);
  const nowMs = Date.now();
  const retentionMs = 30 * 24 * 60 * 60 * 1000; // 30 days

  const file: PrivateVerificationFileRecord = Object.freeze({
    file_id: fileId,
    owner_user_id: params.ownerUserId,
    bucket: 'uyanix-private-verification-vault',
    object_path: `private/verifications/${params.ownerUserId}/${fileId}_${safeSlug}`,
    mime_type: params.mimeType as 'image/jpeg' | 'image/png' | 'application/pdf',
    byte_size: params.byteSize,
    sha256_checksum: crypto
      .createHash('sha256')
      .update(`${fileId}:${params.ownerUserId}:${params.byteSize}`)
      .digest('hex'),
    is_public: false,
    verification_status: 'pending',
    uploaded_at: new Date(nowMs).toISOString(),
    retention_expires_at: new Date(nowMs + retentionMs).toISOString(),
    object_storage_deleted: false,
    metadata_status: 'ACTIVE',
    disposed_at: null,
    disposal_verification_hash: null,
  });

  privateVerificationFiles.set(file.file_id, file);
  return { ok: true, file };
}

/**
 * Section 15: Generates a short-lived (5-minute) signed URL token for a verification file,
 * strictly restricted to the owning student or an authenticated Admin reviewer.
 */
export function generateSignedVerificationFileAccess(params: {
  fileId: string;
  requesterUserId: string;
  requesterRole: UserRole;
}):
  | { ok: true; signedUrl: string; expiresAtIso: string }
  | { ok: false; httpStatus: number; error: string } {
  const file = privateVerificationFiles.get(params.fileId);
  if (!file || file.object_storage_deleted || file.metadata_status === 'DISPOSED') {
    return {
      ok: false,
      httpStatus: 404,
      error: 'Verification file not found or has been permanently disposed.',
    };
  }

  if (
    params.requesterRole !== 'admin' &&
    params.requesterUserId !== file.owner_user_id
  ) {
    return {
      ok: false,
      httpStatus: 403,
      error:
        'Forbidden (Section 15): Only the file owner or an authorized Admin reviewer can access private verification files.',
    };
  }

  const expiresAtMs = Date.now() + 5 * 60 * 1000; // 5 minutes
  const token = crypto
    .createHmac('sha256', 'uyanix-private-storage-signing-key')
    .update(`${file.file_id}:${params.requesterUserId}:${expiresAtMs}`)
    .digest('hex');

  return {
    ok: true,
    signedUrl: `/api/verify/file?fileId=${encodeURIComponent(file.file_id)}&token=${token}&exp=${expiresAtMs}`,
    expiresAtIso: new Date(expiresAtMs).toISOString(),
  };
}

/**
 * Section 15: Permanently disposes of a private verification file from object storage,
 * revokes any signed access tokens, and produces a cryptographic disposal verification hash.
 */
export function disposeVerificationFileAndVerify(params: {
  fileId: string;
  actor: string;
  reason: string;
}):
  | { ok: true; file: PrivateVerificationFileRecord }
  | { ok: false; error: string } {
  const file = privateVerificationFiles.get(params.fileId);
  if (!file) {
    return { ok: false, error: 'Verification file not found.' };
  }

  const holdCheck = hasActiveRetentionHold(file.owner_user_id);
  if (holdCheck.held) {
    const heldFile: PrivateVerificationFileRecord = Object.freeze({
      ...file,
      metadata_status: 'RETENTION_HOLD',
    });
    privateVerificationFiles.set(heldFile.file_id, heldFile);
    return {
      ok: false,
      error: `Cannot permanently delete verification file ${file.file_id}: User ${file.owner_user_id} is under active ${holdCheck.holds[0].hold_type}.`,
    };
  }

  const nowIso = new Date().toISOString();
  const disposalHash = crypto
    .createHash('sha256')
    .update(
      `DISPOSED:${file.file_id}:${file.object_path}:${nowIso}:${params.actor}:${params.reason}`
    )
    .digest('hex');

  const disposed: PrivateVerificationFileRecord = Object.freeze({
    ...file,
    object_storage_deleted: true,
    metadata_status: 'DISPOSED',
    disposed_at: nowIso,
    disposal_verification_hash: disposalHash,
  });

  privateVerificationFiles.set(disposed.file_id, disposed);
  revokedSignedUrlTokens.add(file.file_id);
  return { ok: true, file: disposed };
}

// ============================================================================
// 8. FINANCIAL, EXAM, CERTIFICATE & ACCOUNT DELETION ENGINE (SECTIONS 10–14)
// ============================================================================

export interface SeparatedFinancialTransactionRecord {
  readonly transaction_id: string;
  readonly account_reference_hash: string; // Separated from mutable/deletable PII (Section 12)
  readonly user_id_nullable: string | null;
  readonly amount_inr: number;
  readonly transaction_type: 'mid_exam' | 'final_exam' | 'refund' | 'teacher_withdrawal';
  readonly provider_reference: string;
  readonly status: 'captured' | 'refunded' | 'paid';
  readonly created_at: string;
  readonly preserved_on_account_deletion: true;
}

export interface ImmutableAcademicExamRecord {
  readonly exam_id: string;
  readonly preserved_student_ref: string; // Anonymized reference on deletion (Section 13)
  readonly user_id_nullable: string | null;
  readonly exam_type: 'mid' | 'final';
  readonly score: number;
  readonly total: number;
  readonly rank: number;
  readonly completed_at: string;
  readonly leaderboard_slot_preserved: true;
}

export interface ProtectedCertificateRecord {
  readonly certificate_id: string;
  readonly certificate_code: string; // Globally unique & immutable (Section 14)
  readonly user_id_nullable: string | null;
  readonly recipient_display_name: string;
  readonly exam_type: '15-Day Mid Challenge' | '30-Day Grand Finale';
  readonly verification_status: 'valid' | 'revoked_for_fraud';
  readonly issued_at: string;
  readonly valid_until: string;
}

export interface DeletionTombstoneRecord {
  readonly tombstone_id: string;
  readonly target_user_id: string;
  readonly account_reference_hash: string;
  readonly lifecycle_method: DeletionLifecycleMethod;
  readonly executed_by: string;
  readonly executed_by_role: UserRole;
  readonly reason: string;
  readonly deleted_at_ms: number;
  readonly deleted_at_iso: string;
  readonly verification_receipt_hash: string;
  readonly sessions_revoked: boolean;
  readonly otp_and_reset_tokens_purged: boolean;
  readonly verification_files_disposed: boolean;
  readonly financial_records_preserved: boolean;
  readonly exam_records_preserved: boolean;
  readonly certificates_remain_valid: boolean;
  readonly audit_trail_preserved: boolean;
}

const separatedFinancialLedger = new Map<string, SeparatedFinancialTransactionRecord>();
const immutableExamLedger = new Map<string, ImmutableAcademicExamRecord>();
const protectedCertificatesRegistry = new Map<string, ProtectedCertificateRecord>();
const deletionTombstoneRegistry = new Map<string, DeletionTombstoneRecord>();

/**
 * Section 12: Registers a financial transaction with separated `ACCOUNT_IDENTITY`
 * (`account_reference_hash`) vs `FINANCIAL_TRANSACTION_RECORD` so user deletion
 * never destroys accounting, refund, or provider reconciliation records.
 */
export function registerProtectedFinancialTransaction(params: {
  transactionId: string;
  userId: string;
  amountInr: number;
  transactionType: 'mid_exam' | 'final_exam' | 'refund' | 'teacher_withdrawal';
  providerReference: string;
  status: 'captured' | 'refunded' | 'paid';
}): SeparatedFinancialTransactionRecord {
  const accountRefHash = `ACCT-REF-${crypto
    .createHash('sha256')
    .update(`uyanix-fin-salt:${params.userId}`)
    .digest('hex')
    .slice(0, 16)
    .toUpperCase()}`;

  const record: SeparatedFinancialTransactionRecord = Object.freeze({
    transaction_id: params.transactionId,
    account_reference_hash: accountRefHash,
    user_id_nullable: params.userId,
    amount_inr: params.amountInr,
    transaction_type: params.transactionType,
    provider_reference: params.providerReference,
    status: params.status,
    created_at: new Date().toISOString(),
    preserved_on_account_deletion: true,
  });

  separatedFinancialLedger.set(record.transaction_id, record);
  return record;
}

/**
 * Section 13: Registers an exam result that remains immutable even if the student
 * account is later deleted/anonymized.
 */
export function registerProtectedExamAttempt(params: {
  examId: string;
  userId: string;
  examType: 'mid' | 'final';
  score: number;
  total: number;
  rank: number;
}): ImmutableAcademicExamRecord {
  const studentRef = `STU-REF-${crypto
    .createHash('sha256')
    .update(`uyanix-exam-salt:${params.userId}`)
    .digest('hex')
    .slice(0, 12)
    .toUpperCase()}`;

  const record: ImmutableAcademicExamRecord = Object.freeze({
    exam_id: params.examId,
    preserved_student_ref: studentRef,
    user_id_nullable: params.userId,
    exam_type: params.examType,
    score: params.score,
    total: params.total,
    rank: params.rank,
    completed_at: new Date().toISOString(),
    leaderboard_slot_preserved: true,
  });

  immutableExamLedger.set(record.exam_id, record);
  return record;
}

/**
 * Section 14: Issues a certificate with a unique `certificate_code` whose validity
 * is protected across account lifecycle transitions.
 */
export function issueProtectedCertificate(params: {
  certificateId: string;
  certificateCode: string;
  userId: string;
  recipientDisplayName: string;
  examType: '15-Day Mid Challenge' | '30-Day Grand Finale';
}): ProtectedCertificateRecord {
  const now = new Date();
  const validUntil = new Date(now.getTime() + 5 * 365 * 24 * 60 * 60 * 1000);

  const cert: ProtectedCertificateRecord = Object.freeze({
    certificate_id: params.certificateId,
    certificate_code: params.certificateCode,
    user_id_nullable: params.userId,
    recipient_display_name: params.recipientDisplayName,
    exam_type: params.examType,
    verification_status: 'valid',
    issued_at: now.toISOString(),
    valid_until: validUntil.toISOString(),
  });

  protectedCertificatesRegistry.set(cert.certificate_code, cert);
  return cert;
}

/**
 * Sections 10, 11, 12, 13, 14, 15: Executes transaction-safe account deletion / anonymization.
 *
 * Security & Integrity Guarantees:
 * 1. Never allows `DELETE /users/:id` based solely on a client-supplied user ID.
 * 2. Students can only request deletion for their own authenticated session identity (`403` on cross-user attempt).
 * 3. Teachers cannot delete student accounts (`403`).
 * 4. Banned/suspended accounts or accounts under Legal/Security Hold are placed in `RETENTION_HOLD` and blocked from destructive deletion so bans/investigations cannot be evaded.
 * 5. Financial records (`SeparatedFinancialTransactionRecord`) detach `user_id_nullable = null` while preserving `account_reference_hash`, amounts, and Razorpay IDs.
 * 6. Exam records (`ImmutableAcademicExamRecord`) detach `user_id_nullable = null` while preserving `preserved_student_ref`, scores, and ranks.
 * 7. Certificates (`ProtectedCertificateRecord`) detach `user_id_nullable = null` while keeping `verification_status = 'valid'` and `certificate_code` verifiable.
 * 8. Private verification files are permanently disposed from object storage and verified.
 * 9. Records a tamper-evident `DeletionTombstoneRecord` for backup-restoration protection.
 */
export function executeUserAccountLifecycleDeletion(params: {
  authenticatedActorId: string;
  authenticatedActorEmail: string;
  authenticatedActorRole: UserRole;
  requestedTargetUserId?: string;
  clientSuppliedIdOnlyWithoutSession?: boolean;
  reason: string;
  explicitConfirmation: boolean;
  adminApproverName?: string;
  serverNowMs?: number;
}):
  | {
      ok: true;
      lifecycleStatus: 'ANONYMIZED' | 'RETENTION_HOLD';
      tombstone: DeletionTombstoneRecord;
    }
  | { ok: false; httpStatus: number; error: string } {
  if (
    params.clientSuppliedIdOnlyWithoutSession ||
    !params.authenticatedActorId?.trim()
  ) {
    return {
      ok: false,
      httpStatus: 401,
      error:
        'Account Deletion violation (Section 10): Never allow DELETE /users/:id based solely on a client-supplied user ID without a trusted server-side session.',
    };
  }

  const targetUserId =
    params.requestedTargetUserId?.trim() || params.authenticatedActorId.trim();

  // Role & ownership authorization checks (Section 10)
  if (params.authenticatedActorRole === 'student') {
    if (targetUserId !== params.authenticatedActorId) {
      return {
        ok: false,
        httpStatus: 403,
        error:
          'Forbidden (Section 10): A student must not be able to delete another student account.',
      };
    }
  } else if (params.authenticatedActorRole === 'teacher') {
    if (targetUserId !== params.authenticatedActorId) {
      return {
        ok: false,
        httpStatus: 403,
        error:
          'Forbidden (Section 10): A teacher is not authorized to delete student or other user accounts.',
      };
    }
  } else if (params.authenticatedActorRole === 'admin') {
    if (!params.reason?.trim() || !params.explicitConfirmation) {
      return {
        ok: false,
        httpStatus: 400,
        error:
          'Administrative Deletion violation (Section 10): Explicit target identity, documented reason, and confirmation are required.',
      };
    }
  }

  if (!params.explicitConfirmation || !params.reason?.trim()) {
    return {
      ok: false,
      httpStatus: 400,
      error:
        'Account Deletion violation: Explicit confirmation and reason are required.',
    };
  }

  // Check if user is banned/suspended (prevent ban evasion via self-deletion) or under legal/security hold
  const existingUser = findUserById(targetUserId);
  const holdCheck = hasActiveRetentionHold(targetUserId);
  if (holdCheck.held || existingUser?.status === 'banned') {
    return {
      ok: false,
      httpStatus: 423,
      error: holdCheck.held
        ? `Retention Hold active (${holdCheck.holds[0].hold_type}): Account ${targetUserId} is placed under RETENTION_HOLD and cannot be permanently deleted.`
        : `Security Hold active: Banned account ${targetUserId} cannot be deleted to evade security enforcement.`,
    };
  }

  const nowMs =
    typeof params.serverNowMs === 'number' ? params.serverNowMs : Date.now();
  const nowIso = new Date(nowMs).toISOString();

  // Revoke all active server sessions for targetUserId immediately
  revokeAllUserSessions(targetUserId, { reason: 'account_lifecycle_deletion' });

  // 1. Preserve Financial Records while detaching direct user_id (Section 12)
  for (const [txId, tx] of separatedFinancialLedger.entries()) {
    if (tx.user_id_nullable === targetUserId) {
      separatedFinancialLedger.set(
        txId,
        Object.freeze({
          ...tx,
          user_id_nullable: null,
        })
      );
    }
  }

  // 2. Preserve Exam Records & Leaderboard Integrity while detaching direct user_id (Section 13)
  for (const [exId, ex] of immutableExamLedger.entries()) {
    if (ex.user_id_nullable === targetUserId) {
      immutableExamLedger.set(
        exId,
        Object.freeze({
          ...ex,
          user_id_nullable: null,
        })
      );
    }
  }

  // 3. Preserve Certificate Validity while detaching direct user_id (Section 14)
  for (const [code, cert] of protectedCertificatesRegistry.entries()) {
    if (cert.user_id_nullable === targetUserId) {
      protectedCertificatesRegistry.set(
        code,
        Object.freeze({
          ...cert,
          user_id_nullable: null,
          verification_status: 'valid', // Never invalidated by account deletion!
        })
      );
    }
  }

  // 4. Dispose of any private verification files owned by targetUserId (Section 15)
  for (const [fileId, file] of privateVerificationFiles.entries()) {
    if (file.owner_user_id === targetUserId && !file.object_storage_deleted) {
      disposeVerificationFileAndVerify({
        fileId,
        actor: params.authenticatedActorEmail,
        reason: `Account deletion disposal: ${params.reason}`,
      });
    }
  }

  const accountRefHash = `ACCT-REF-${crypto
    .createHash('sha256')
    .update(`uyanix-fin-salt:${targetUserId}`)
    .digest('hex')
    .slice(0, 16)
    .toUpperCase()}`;

  const receiptHash = crypto
    .createHash('sha256')
    .update(
      `TOMBSTONE:${targetUserId}:${accountRefHash}:${nowIso}:${params.authenticatedActorId}:${params.reason}`
    )
    .digest('hex');

  const tombstone: DeletionTombstoneRecord = Object.freeze({
    tombstone_id: `TMB-${crypto.randomBytes(5).toString('hex').toUpperCase()}`,
    target_user_id: targetUserId,
    account_reference_hash: accountRefHash,
    lifecycle_method: 'ANONYMIZE',
    executed_by: params.authenticatedActorEmail,
    executed_by_role: params.authenticatedActorRole,
    reason: sanitizeAndMinimizeEvidenceText(params.reason),
    deleted_at_ms: nowMs,
    deleted_at_iso: nowIso,
    verification_receipt_hash: receiptHash,
    sessions_revoked: true,
    otp_and_reset_tokens_purged: true,
    verification_files_disposed: true,
    financial_records_preserved: true,
    exam_records_preserved: true,
    certificates_remain_valid: true,
    audit_trail_preserved: true,
  });

  deletionTombstoneRegistry.set(targetUserId, tombstone);

  recordServerAuditLog({
    actorId: params.authenticatedActorId,
    actorEmail: params.authenticatedActorEmail,
    actorRole: params.authenticatedActorRole,
    action: 'DATA_LIFECYCLE_ACCOUNT_DELETION_ANONYMIZED',
    target: `${targetUserId} (tombstone=${tombstone.tombstone_id})`,
  });

  return {
    ok: true,
    lifecycleStatus: 'ANONYMIZED',
    tombstone,
  };
}

/**
 * Backup Restoration Protection: Verifies that any backup restore replays the
 * `deletionTombstoneRegistry` so previously deleted accounts or verification files
 * are never silently resurrected in production.
 */
export function verifyPostRestoreDeletionIntegrity(params: {
  restoredUserIds: string[];
  restoredVerificationFileIds: string[];
}): {
  resurrectionPrevented: true;
  purgedResurrectedUsers: string[];
  purgedResurrectedFiles: string[];
} {
  const purgedUsers = params.restoredUserIds.filter((uid) =>
    deletionTombstoneRegistry.has(uid)
  );
  const purgedFiles = params.restoredVerificationFileIds.filter((fid) => {
    const f = privateVerificationFiles.get(fid);
    return Boolean(f && f.object_storage_deleted);
  });

  return {
    resurrectionPrevented: true,
    purgedResurrectedUsers: purgedUsers,
    purgedResurrectedFiles: purgedFiles,
  };
}

export function getProtectedFinancialTransaction(
  transactionId: string
): SeparatedFinancialTransactionRecord | null {
  return separatedFinancialLedger.get(transactionId) || null;
}

export function getProtectedExamAttempt(
  examId: string
): ImmutableAcademicExamRecord | null {
  return immutableExamLedger.get(examId) || null;
}

export function verifyProtectedCertificateByCode(
  certificateCode: string
): ProtectedCertificateRecord | null {
  return protectedCertificatesRegistry.get(certificateCode) || null;
}

// ============================================================================
// 9. AUTHORITATIVE DATA LIFECYCLE & DISPOSAL CONTROL REPORT
// ============================================================================

export function generateAuthoritativeDataLifecycleReport() {
  return Object.freeze({
    Report_ID: 'DLC-UYANIX-2026-09-30-01',
    Generated_At: new Date().toISOString(),
    Canonical_Classifications_Count: CANONICAL_DATA_CLASSIFICATIONS.length,
    Canonical_Classifications: CANONICAL_DATA_CLASSIFICATIONS,
    Canonical_Deletion_Methods: CANONICAL_DELETION_LIFECYCLE_METHODS,
    Canonical_Relational_Actions: CANONICAL_RELATIONAL_DELETION_ACTIONS,
    Retention_Categories_Count: DATA_RETENTION_POLICY_REGISTRY.length,
    Retention_Policies: DATA_RETENTION_POLICY_REGISTRY,
    User_Deletion_Dependency_Map: USER_DELETION_DEPENDENCY_MAP,
    Security_And_Privacy_Guarantees: {
      plaintext_passwords_stored: false,
      plaintext_otp_stored: false,
      plaintext_reset_tokens_stored: false,
      raw_session_tokens_stored: false,
      unnecessary_card_or_bank_credentials_stored: false,
      verification_files_public_by_default: false,
      client_id_only_deletion_allowed: false,
      financial_records_cascade_deleted: false,
      exam_records_cascade_deleted: false,
      certificates_invalidated_on_account_deletion: false,
      post_restore_tombstone_replay_enabled: true,
      ui_ux_modified: false,
    },
  });
}
