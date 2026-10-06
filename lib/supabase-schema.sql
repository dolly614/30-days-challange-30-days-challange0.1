-- ============================================================================
-- UYANIX 30 DAYS CHALLENGE — COMPLETE SUPABASE POSTGRESQL SCHEMA + HARDENED RLS
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. USERS TABLE
CREATE TABLE public.users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 2 AND 100),
  email TEXT UNIQUE,
  phone TEXT UNIQUE CHECK (phone IS NULL OR phone ~ '^[6-9][0-9]{9}$'),
  class INTEGER CHECK (class IS NULL OR (class BETWEEN 1 AND 12)),
  school TEXT CHECK (school IS NULL OR (char_length(trim(school)) BETWEEN 2 AND 160)),
  city TEXT DEFAULT 'Jaipur',
  role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'teacher', 'admin')),
  avatar TEXT,
  id_card_url TEXT,
  id_verification_status TEXT NOT NULL DEFAULT 'pending' CHECK (id_verification_status IN ('pending', 'verified', 'rejected')),
  phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'banned', 'suspended')),
  terms_accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 1B. OTP CHALLENGES TABLE (SERVER-ONLY, NO PLAINTEXT OTP)
CREATE TABLE public.otp_challenges (
  challenge_id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  phone TEXT NOT NULL CHECK (phone ~ '^[6-9][0-9]{9}$'),
  otp_salt TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts = 5),
  resend_count INTEGER NOT NULL DEFAULT 0 CHECK (resend_count >= 0),
  used BOOLEAN NOT NULL DEFAULT FALSE,
  used_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'used', 'expired', 'invalidated', 'superseded')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE public.otp_challenges ENABLE ROW LEVEL SECURITY;

-- 1C. PASSWORD RESET TOKENS TABLE (SERVER-ONLY, NO PLAINTEXT TOKENS OR PASSWORDS)
CREATE TABLE public.password_reset_tokens (
  reset_id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  token_salt TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts = 5),
  used BOOLEAN NOT NULL DEFAULT FALSE,
  used_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'used', 'expired', 'invalidated', 'superseded')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE public.password_reset_tokens ENABLE ROW LEVEL SECURITY;

-- 1D. SERVER SESSIONS TABLE (ROTATION, REUSE DETECTION, IDLE & ABSOLUTE TIMEOUTS)
CREATE TABLE public.user_sessions (
  jti TEXT PRIMARY KEY,
  family_id TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  auth_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  idle_expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'revoked', 'expired', 'compromised')),
  replaced_by_jti TEXT,
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;

-- 1E. AUTH IDENTITIES / CREDENTIALS TABLE (AUTHORITATIVE SERVER-ONLY STORAGE FOR PASSWORD HASH & SALT)
CREATE TABLE IF NOT EXISTS public.auth_identities (
  user_id UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  normalized_email TEXT,
  normalized_phone TEXT,
  password_salt TEXT,
  password_hash TEXT,
  password_changed_at TIMESTAMPTZ,
  sessions_revoked_before TIMESTAMPTZ,
  google_uid TEXT UNIQUE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.auth_identities ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Auth identities are server-only access"
  ON public.auth_identities FOR ALL
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

-- 2. CHAPTERS TABLE
CREATE TABLE public.chapters (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  class INTEGER NOT NULL CHECK (class BETWEEN 1 AND 12),
  day INTEGER NOT NULL CHECK (day BETWEEN 1 AND 30),
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  pdf_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(class, day)
);

-- 3. DAILY PROGRESS TABLE
CREATE TABLE public.daily_progress (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  day INTEGER NOT NULL CHECK (day BETWEEN 1 AND 30),
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 5),
  completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, day)
);

-- 4. EXAMS TABLE (PRESERVE ACADEMIC INTEGRITY ON ACCOUNT DELETION — SECTION 13 & 15)
CREATE TABLE public.exams (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  preserved_student_ref TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('mid', 'final')),
  score INTEGER NOT NULL DEFAULT 0 CHECK (score >= 0),
  total INTEGER NOT NULL DEFAULT 150 CHECK (total > 0 AND total <= 150),
  answers JSONB NOT NULL DEFAULT '{}'::jsonb,
  question_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
  paid BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT exams_score_within_total_chk CHECK (score <= total)
);

-- 5. PAYMENTS TABLE (SEPARATE ACCOUNT_IDENTITY FROM FINANCIAL_TRANSACTION_RECORD — SECTION 12 & 14)
CREATE TABLE public.payments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  account_reference_hash TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 199 CHECK (amount >= 0),
  type TEXT NOT NULL CHECK (type IN ('mid_exam', 'final_exam')),
  razorpay_id TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'captured' CHECK (status IN ('created', 'captured', 'refunded', 'failed')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. TEACHERS TABLE
CREATE TABLE public.teachers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID UNIQUE REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  referral_code TEXT UNIQUE NOT NULL,
  tier TEXT NOT NULL DEFAULT 'Beginner Teacher' CHECK (tier IN ('Beginner Teacher', 'Active Mentor', 'Super Educator')),
  balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
  total_earned INTEGER NOT NULL DEFAULT 0 CHECK (total_earned >= 0),
  kyc_pan TEXT,
  kyc_verified BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT teachers_balance_le_total_earned_chk CHECK (balance <= total_earned)
);

-- 7. REFERRALS TABLE (PRESERVE COMMISSION INTEGRITY — SECTION 11 & 12)
CREATE TABLE public.referrals (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  teacher_id UUID NOT NULL REFERENCES public.teachers(id) ON DELETE RESTRICT ON UPDATE CASCADE,
  student_id UUID UNIQUE REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  anonymized_student_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'flagged_fraud')),
  commission INTEGER NOT NULL DEFAULT 10 CHECK (commission >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. WITHDRAWALS TABLE (PRESERVE PAYOUT FINANCIAL RECORDS — SECTION 12 & 14)
CREATE TABLE public.withdrawals (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  teacher_id UUID NOT NULL REFERENCES public.teachers(id) ON DELETE RESTRICT ON UPDATE CASCADE,
  amount INTEGER NOT NULL CHECK (amount >= 500),
  method TEXT NOT NULL CHECK (method IN ('UPI', 'Bank')),
  upi_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'rejected')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. CERTIFICATES TABLE (PRESERVE CERTIFICATE VALIDITY ON ACCOUNT DELETION — SECTION 12 & 14)
CREATE TABLE public.certificates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  certificate_code TEXT UNIQUE NOT NULL,
  public_certificate_id TEXT UNIQUE NOT NULL,
  verification_token TEXT UNIQUE NOT NULL,
  user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
  exam_id TEXT NOT NULL DEFAULT 'EXAM-UYANIX-2026-MID',
  attempt_id TEXT NOT NULL,
  result_id TEXT UNIQUE NOT NULL,
  recipient_display_name TEXT NOT NULL,
  exam_type TEXT NOT NULL CHECK (exam_type IN ('15-Day Mid Challenge', '30-Day Grand Finale')),
  score_snapshot INTEGER NOT NULL DEFAULT 0 CHECK (score_snapshot >= 0),
  percentage_snapshot INTEGER NOT NULL DEFAULT 0 CHECK (percentage_snapshot BETWEEN 0 AND 100),
  status TEXT NOT NULL DEFAULT 'AVAILABLE' CHECK (status IN ('PENDING', 'ISSUED', 'AVAILABLE', 'REVOKED', 'REPLACED', 'EXPIRED')),
  verification_status TEXT NOT NULL DEFAULT 'valid' CHECK (verification_status IN ('valid', 'revoked_for_fraud')),
  artifact_storage_key TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  verification_version INTEGER NOT NULL DEFAULT 1 CHECK (verification_version >= 1),
  url TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  revocation_reason TEXT CHECK (revocation_reason IS NULL OR revocation_reason IN ('RESULT_INVALIDATED', 'FRAUD_CONFIRMED', 'ADMIN_CORRECTION', 'DUPLICATE_ISSUANCE', 'DATA_CORRECTION', 'OTHER'))
);

-- 10. NOTIFICATIONS TABLE
CREATE TABLE public.notifications (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. SETTINGS TABLE
CREATE TABLE public.settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 12. AUDIT LOGS TABLE
CREATE TABLE public.audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  actor_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  meta JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- PHASE 4: PRODUCTION EXAM ENGINE TABLES & STATE MACHINE
-- ============================================================================

-- 13. EXAM DEFINITIONS TABLE
CREATE TABLE IF NOT EXISTS public.exam_definitions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  type TEXT NOT NULL UNIQUE CHECK (type IN ('mid', 'final')),
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'LIVE' CHECK (status IN ('DRAFT', 'SCHEDULED', 'LIVE', 'PAUSED', 'ENDED', 'ARCHIVED')),
  allowed_classes INTEGER[] NOT NULL DEFAULT ARRAY[1,2,3,4,5,6,7,8,9,10,11,12],
  duration_seconds INTEGER NOT NULL DEFAULT 2700 CHECK (duration_seconds > 0),
  total_questions INTEGER NOT NULL DEFAULT 150 CHECK (total_questions > 0),
  maximum_marks INTEGER NOT NULL DEFAULT 150 CHECK (maximum_marks > 0),
  marking_scheme JSONB NOT NULL DEFAULT '{"correct": 1, "incorrect": 0, "unanswered": 0}'::jsonb,
  start_at TIMESTAMPTZ,
  end_at TIMESTAMPTZ,
  attempt_limit INTEGER NOT NULL DEFAULT 1 CHECK (attempt_limit >= 1),
  requires_payment BOOLEAN NOT NULL DEFAULT TRUE,
  minimum_completed_days INTEGER NOT NULL DEFAULT 0,
  question_version INTEGER NOT NULL DEFAULT 1,
  published_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 14. EXAM QUESTIONS TABLE (Authoritative Question Bank)
CREATE TABLE IF NOT EXISTS public.exam_questions (
  id TEXT PRIMARY KEY,
  exam_type TEXT NOT NULL CHECK (exam_type IN ('mid', 'final')),
  question_text TEXT NOT NULL,
  option_a TEXT NOT NULL,
  option_b TEXT NOT NULL,
  option_c TEXT NOT NULL,
  option_d TEXT NOT NULL,
  correct_option INTEGER NOT NULL CHECK (correct_option BETWEEN 0 AND 3),
  explanation TEXT NOT NULL,
  topic TEXT NOT NULL DEFAULT 'General',
  class_num INTEGER DEFAULT 12,
  question_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 15. EXAM ATTEMPTS TABLE (Authoritative Attempts, Snapshot & Evaluated Results)
CREATE TABLE IF NOT EXISTS public.exam_attempts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  exam_type TEXT NOT NULL CHECK (exam_type IN ('mid', 'final')),
  student_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  student_class INTEGER NOT NULL CHECK (student_class BETWEEN 1 AND 12),
  student_name TEXT NOT NULL,
  attempt_number INTEGER NOT NULL DEFAULT 1 CHECK (attempt_number >= 1),
  status TEXT NOT NULL DEFAULT 'IN_PROGRESS' CHECK (status IN ('NOT_STARTED', 'IN_PROGRESS', 'SUBMITTED', 'AUTO_SUBMITTED', 'EVALUATED', 'CANCELLED', 'EXPIRED', 'INVALIDATED')),
  question_version INTEGER NOT NULL DEFAULT 1,
  question_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
  marking_scheme_snapshot JSONB NOT NULL DEFAULT '{"correct": 1, "incorrect": 0}'::jsonb,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deadline_at TIMESTAMPTZ NOT NULL,
  submitted_at TIMESTAMPTZ,
  finalized_at TIMESTAMPTZ,
  score INTEGER NOT NULL DEFAULT 0 CHECK (score >= 0),
  maximum_score INTEGER NOT NULL DEFAULT 150 CHECK (maximum_score > 0),
  percentage NUMERIC(5, 2) NOT NULL DEFAULT 0.00 CHECK (percentage BETWEEN 0 AND 100),
  correct_count INTEGER NOT NULL DEFAULT 0 CHECK (correct_count >= 0),
  wrong_count INTEGER NOT NULL DEFAULT 0 CHECK (wrong_count >= 0),
  unanswered_count INTEGER NOT NULL DEFAULT 0 CHECK (unanswered_count >= 0),
  rank INTEGER,
  certificate_eligible BOOLEAN NOT NULL DEFAULT FALSE,
  result_version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(student_id, exam_type, attempt_number)
);

-- 16. EXAM ATTEMPT ANSWERS TABLE (Autosaved Answers per Question)
CREATE TABLE IF NOT EXISTS public.exam_attempt_answers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  attempt_id UUID NOT NULL REFERENCES public.exam_attempts(id) ON DELETE CASCADE,
  question_id TEXT NOT NULL,
  selected_option INTEGER NOT NULL CHECK (selected_option BETWEEN 0 AND 3),
  saved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(attempt_id, question_id)
);

-- 17. EXAM IDEMPOTENCY KEYS TABLE
CREATE TABLE IF NOT EXISTS public.exam_idempotency_keys (
  key TEXT PRIMARY KEY,
  user_id UUID NOT NULL,
  attempt_id UUID,
  operation TEXT NOT NULL,
  response_payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

-- 18. EXAM VIOLATION EVENTS TABLE
CREATE TABLE IF NOT EXISTS public.exam_violation_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  attempt_id UUID NOT NULL REFERENCES public.exam_attempts(id) ON DELETE CASCADE,
  student_id UUID NOT NULL,
  event_type TEXT NOT NULL,
  metadata JSONB DEFAULT '{}'::jsonb,
  server_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  request_id TEXT
);

-- 19. EXAM RESULT EVENTS TABLE (Audit Trail for Evaluations & Admin Corrections)
CREATE TABLE IF NOT EXISTS public.exam_result_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  attempt_id UUID NOT NULL REFERENCES public.exam_attempts(id) ON DELETE CASCADE,
  student_id UUID NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  reason TEXT,
  old_result JSONB,
  new_result JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- TRUSTED SERVER-SIDE ROLE HELPER
-- ============================================================================

CREATE OR REPLACE FUNCTION public.get_my_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT role FROM public.users WHERE id = auth.uid();
$$;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES — ZERO-TRUST RBAC
-- ============================================================================

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chapters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.daily_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.referrals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.withdrawals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- USERS: Owner or Admin read; self-registration strictly forced to 'student'; role immutable for non-admins
CREATE POLICY "Users can view own profile or admin can view all"
  ON public.users FOR SELECT
  USING (auth.uid() = id OR public.get_my_role() = 'admin');

CREATE POLICY "Students can self-register only with student role"
  ON public.users FOR INSERT
  WITH CHECK (
    (auth.uid() = id AND role = 'student' AND status = 'active' AND id_verification_status = 'pending')
    OR public.get_my_role() = 'admin'
  );

CREATE POLICY "Users can update own profile without escalating role"
  ON public.users FOR UPDATE
  USING (auth.uid() = id OR public.get_my_role() = 'admin')
  WITH CHECK (
    public.get_my_role() = 'admin'
    OR (
      auth.uid() = id
      AND role = (SELECT u.role FROM public.users u WHERE u.id = auth.uid())
      AND status = (SELECT u.status FROM public.users u WHERE u.id = auth.uid())
      AND id_verification_status = (SELECT u.id_verification_status FROM public.users u WHERE u.id = auth.uid())
    )
  );

-- CHAPTERS: Readable by authenticated users, writable only by Admin
CREATE POLICY "Chapters are viewable by authenticated users"
  ON public.chapters FOR SELECT
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "Only admins can insert update or delete chapters"
  ON public.chapters FOR ALL
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

-- DAILY PROGRESS: Students view own progress only (read-only); Admin manages all; Server inserts via service-role
CREATE POLICY "Students view own daily progress"
  ON public.daily_progress FOR SELECT
  USING (auth.uid() = user_id OR public.get_my_role() = 'admin');

CREATE POLICY "Admin manages daily progress"
  ON public.daily_progress FOR ALL
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

-- EXAMS: Students view and create own exams; Admin manages all
CREATE POLICY "Students view own exams"
  ON public.exams FOR SELECT
  USING (auth.uid() = user_id OR public.get_my_role() = 'admin');

CREATE POLICY "Students insert own exam attempt"
  ON public.exams FOR INSERT
  WITH CHECK (auth.uid() = user_id OR public.get_my_role() = 'admin');

CREATE POLICY "Only admin can update completed exams"
  ON public.exams FOR UPDATE
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

-- PAYMENTS: Students view own payments; Admin manages payments & refunds
CREATE POLICY "Students view own payments"
  ON public.payments FOR SELECT
  USING (auth.uid() = user_id OR public.get_my_role() = 'admin');

CREATE POLICY "Only admin can update payment status or refund"
  ON public.payments FOR UPDATE
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

-- TEACHERS: Teachers view own record; only Admin can approve/reject or modify balances
CREATE POLICY "Teachers view own teacher profile or admin views all"
  ON public.teachers FOR SELECT
  USING (auth.uid() = user_id OR public.get_my_role() = 'admin');

CREATE POLICY "Only admin can approve or update teacher records"
  ON public.teachers FOR ALL
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

-- REFERRALS: Teachers view own referrals; Admin manages referrals
CREATE POLICY "Teachers view own referrals"
  ON public.referrals FOR SELECT
  USING (
    public.get_my_role() = 'admin'
    OR teacher_id IN (SELECT id FROM public.teachers WHERE user_id = auth.uid())
  );

-- WITHDRAWALS: Teachers view & request own pending withdrawals; only Admin can mark paid/rejected
CREATE POLICY "Teachers view own withdrawals"
  ON public.withdrawals FOR SELECT
  USING (
    public.get_my_role() = 'admin'
    OR teacher_id IN (SELECT id FROM public.teachers WHERE user_id = auth.uid())
  );

CREATE POLICY "Teachers request pending withdrawals for own teacher account"
  ON public.withdrawals FOR INSERT
  WITH CHECK (
    (status = 'pending' AND teacher_id IN (SELECT id FROM public.teachers WHERE user_id = auth.uid()))
    OR public.get_my_role() = 'admin'
  );

CREATE POLICY "Only admin can approve or reject withdrawals"
  ON public.withdrawals FOR UPDATE
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

-- SETTINGS & AUDIT LOGS: Admin only
CREATE POLICY "Only admin can manage settings"
  ON public.settings FOR ALL
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

CREATE POLICY "Only admin can view audit logs"
  ON public.audit_logs FOR SELECT
  USING (public.get_my_role() = 'admin');

-- ============================================================================
-- CANONICAL INCIDENT STATUS ENUM & IMMUTABLE AUDIT TRAIL (INCIDENT_STATUS_ENUM_V1)
-- ============================================================================

CREATE TYPE public.incident_status_enum AS ENUM (
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
  'REOPENED'
);

CREATE TABLE public.production_incidents (
  incident_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  incident_status public.incident_status_enum NOT NULL DEFAULT 'DETECTED',
  severity TEXT NOT NULL CHECK (severity IN ('SEV-1', 'SEV-2', 'SEV-3', 'SEV-4')) DEFAULT 'SEV-1',
  priority TEXT NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3')) DEFAULT 'P0',
  rollback_status TEXT NOT NULL CHECK (rollback_status IN ('NOT_STARTED', 'INITIATED', 'ACTION_COMPLETE', 'ACTION_FAILED')) DEFAULT 'NOT_STARTED',
  recovery_status TEXT NOT NULL CHECK (recovery_status IN ('NOT_STARTED', 'VERIFICATION_RUNNING', 'VERIFIED', 'SIGN_OFF_COMPLETE')) DEFAULT 'NOT_STARTED',
  monitoring_status TEXT NOT NULL CHECK (monitoring_status IN ('NOT_STARTED', 'ACTIVE', 'STABLE', 'FAILED')) DEFAULT 'NOT_STARTED',
  approval_status TEXT NOT NULL CHECK (approval_status IN ('PENDING', 'COMPLETE')) DEFAULT 'PENDING',
  sla_status TEXT NOT NULL CHECK (sla_status IN ('WITHIN_SLA', 'SLA_BREACHED')) DEFAULT 'WITHIN_SLA',
  primary_owner TEXT NOT NULL,
  backup_owner TEXT NOT NULL,
  security_owner TEXT NOT NULL,
  database_owner TEXT NOT NULL,
  rollback_owner TEXT NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.incident_audit_events (
  event_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES public.production_incidents(incident_id) ON DELETE RESTRICT,
  verification_id TEXT NOT NULL DEFAULT 'N/A',
  event_type TEXT NOT NULL,
  previous_status TEXT NOT NULL DEFAULT 'N/A',
  new_status TEXT NOT NULL DEFAULT 'N/A',
  actor TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  environment TEXT NOT NULL,
  reason TEXT NOT NULL,
  result TEXT NOT NULL,
  evidence_reference TEXT NOT NULL,
  related_change_id TEXT NOT NULL DEFAULT 'N/A',
  approver TEXT NOT NULL DEFAULT 'N/A',
  notes TEXT NOT NULL DEFAULT 'N/A',
  integrity_hash TEXT NOT NULL
);

ALTER TABLE public.production_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Only admins can view or manage production incidents"
  ON public.production_incidents FOR ALL
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

CREATE POLICY "Only admins can view append-only incident audit events"
  ON public.incident_audit_events FOR SELECT
  USING (public.get_my_role() = 'admin');

CREATE POLICY "Only admins can append incident audit events"
  ON public.incident_audit_events FOR INSERT
  WITH CHECK (public.get_my_role() = 'admin');

-- ============================================================================
-- 13. VERIFICATION SUBMISSIONS & PRIVATE VERIFICATION FILES (SECTIONS 16 & 20)
-- ============================================================================

CREATE TABLE public.verification_submissions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  preserved_student_ref TEXT NOT NULL,
  class INTEGER NOT NULL CHECK (class BETWEEN 1 AND 12),
  school TEXT NOT NULL CHECK (char_length(trim(school)) BETWEEN 2 AND 160),
  document_reference TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'resubmission_required')),
  reviewer_id UUID REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  rejection_reason TEXT,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1)
);
ALTER TABLE public.verification_submissions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Students view own verification submissions or admin views all"
  ON public.verification_submissions FOR SELECT
  USING (auth.uid() = user_id OR public.get_my_role() = 'admin');

CREATE POLICY "Students submit own pending verification only"
  ON public.verification_submissions FOR INSERT
  WITH CHECK (auth.uid() = user_id AND status = 'pending' AND reviewer_id IS NULL);

CREATE POLICY "Only admin can approve or reject verification submissions"
  ON public.verification_submissions FOR UPDATE
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

CREATE TABLE public.verification_files (
  file_id TEXT PRIMARY KEY,
  owner_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  bucket TEXT NOT NULL DEFAULT 'uyanix-private-verification-vault',
  object_path TEXT UNIQUE NOT NULL,
  mime_type TEXT NOT NULL CHECK (mime_type IN ('image/jpeg', 'image/png', 'application/pdf')),
  byte_size INTEGER NOT NULL CHECK (byte_size > 0 AND byte_size <= 5242880),
  sha256_checksum TEXT NOT NULL,
  is_public BOOLEAN NOT NULL DEFAULT FALSE CHECK (is_public = FALSE),
  metadata_status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (metadata_status IN ('ACTIVE', 'ARCHIVED', 'DISPOSED', 'RETENTION_HOLD')),
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retention_expires_at TIMESTAMPTZ NOT NULL,
  disposed_at TIMESTAMPTZ,
  disposal_verification_hash TEXT
);
ALTER TABLE public.verification_files ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Only owner or admin can view private verification file metadata"
  ON public.verification_files FOR SELECT
  USING (auth.uid() = owner_user_id OR public.get_my_role() = 'admin');

-- ============================================================================
-- 14. API IDEMPOTENCY KEYS & PAYMENT WEBHOOK EVENTS (SECTIONS 7, 13, 14)
-- ============================================================================

CREATE TABLE public.api_idempotency_keys (
  actor_id TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 12 AND 128),
  request_payload_hash TEXT NOT NULL,
  response_status INTEGER NOT NULL,
  response_payload JSONB NOT NULL,
  committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (actor_id, operation_type, idempotency_key)
);
ALTER TABLE public.api_idempotency_keys ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.payment_webhook_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  provider TEXT NOT NULL CHECK (provider IN ('RAZORPAY', 'GOOGLE_WORKSPACE')),
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  signature_verified BOOLEAN NOT NULL CHECK (signature_verified = TRUE),
  processing_status TEXT NOT NULL DEFAULT 'PROCESSED' CHECK (processing_status IN ('PROCESSED', 'DUPLICATE_IGNORED', 'FAILED')),
  correlation_id TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, event_id)
);
ALTER TABLE public.payment_webhook_events ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 15. ENTITY STATE HISTORY, LIFECYCLE HOLDS & VERSIONED MIGRATIONS (SECTIONS 19, 20, 24)
-- ============================================================================

CREATE TABLE public.entity_state_history (
  record_id TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_state JSONB NOT NULL DEFAULT '{}'::jsonb,
  new_state JSONB NOT NULL DEFAULT '{}'::jsonb,
  actor_id TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('student', 'teacher', 'admin', 'system')),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  request_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  source TEXT NOT NULL
);
ALTER TABLE public.entity_state_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Only admin can read entity state history"
  ON public.entity_state_history FOR SELECT
  USING (public.get_my_role() = 'admin');

CREATE TABLE public.data_lifecycle_holds (
  hold_id TEXT PRIMARY KEY,
  target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT ON UPDATE CASCADE,
  hold_type TEXT NOT NULL CHECK (hold_type IN ('LEGAL_HOLD', 'SECURITY_HOLD', 'FINANCIAL_DISPUTE_HOLD')),
  reason TEXT NOT NULL,
  placed_by TEXT NOT NULL,
  placed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  released_by TEXT,
  released_at TIMESTAMPTZ
);
ALTER TABLE public.data_lifecycle_holds ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.schema_migrations (
  migration_id TEXT PRIMARY KEY,
  version TEXT UNIQUE NOT NULL,
  purpose TEXT NOT NULL,
  rollback_classification TEXT NOT NULL CHECK (rollback_classification IN ('REVERSIBLE', 'FORWARD_ONLY', 'REVERSIBLE_WITH_DATA_RESTORE', 'REQUIRES_COMPENSATING_MIGRATION')),
  checksum_sha256 TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  owner TEXT NOT NULL
);
ALTER TABLE public.schema_migrations ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 16. IMMUTABILITY TRIGGER FOR CRITICAL AUDIT & FINALIZED RECORDS (SECTION 18)
-- ============================================================================

CREATE OR REPLACE FUNCTION public.prevent_immutable_record_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'Immutable record violation: Direct UPDATE or DELETE on % is prohibited. Use controlled reversal/correction records.', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER trg_immutable_incident_audit_events
  BEFORE UPDATE OR DELETE ON public.incident_audit_events
  FOR EACH ROW EXECUTE FUNCTION public.prevent_immutable_record_mutation();

CREATE TRIGGER trg_immutable_entity_state_history
  BEFORE UPDATE OR DELETE ON public.entity_state_history
  FOR EACH ROW EXECUTE FUNCTION public.prevent_immutable_record_mutation();

-- ============================================================================
-- 16B. CANONICAL PAYMENT ORDERS, ENTITLEMENTS, REFUNDS & APPEND-ONLY LEDGER
-- ============================================================================

CREATE TABLE public.payment_orders (
  id TEXT PRIMARY KEY,
  user_id UUID REFERENCES public.users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  product_id TEXT NOT NULL CHECK (product_id IN ('exam_mid', 'exam_final')),
  provider TEXT NOT NULL DEFAULT 'RAZORPAY' CHECK (provider IN ('RAZORPAY')),
  provider_order_id TEXT UNIQUE NOT NULL,
  base_amount_minor INTEGER NOT NULL CHECK (base_amount_minor > 0),
  discount_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK (discount_amount_minor >= 0),
  amount_minor INTEGER NOT NULL CHECK (amount_minor > 0 AND amount_minor = base_amount_minor - discount_amount_minor),
  currency TEXT NOT NULL DEFAULT 'INR' CHECK (currency = 'INR'),
  status TEXT NOT NULL DEFAULT 'ORDER_CREATED' CHECK (status IN (
    'CREATED', 'ORDER_CREATED', 'PAYMENT_PENDING', 'PAYMENT_AUTHORIZED',
    'PAYMENT_CAPTURED', 'PAYMENT_FAILED', 'PAYMENT_CANCELLED', 'REFUND_PENDING',
    'PARTIALLY_REFUNDED', 'REFUNDED', 'DISPUTED', 'EXPIRED', 'RECONCILIATION_REQUIRED'
  )),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  paid_at TIMESTAMPTZ,
  failure_reason TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
ALTER TABLE public.payment_orders ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.entitlements (
  id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE ON UPDATE CASCADE,
  product_id TEXT NOT NULL CHECK (product_id IN ('exam_mid', 'exam_final')),
  source_payment_id UUID NOT NULL REFERENCES public.payments(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'PENDING')),
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  UNIQUE (user_id, product_id)
);
ALTER TABLE public.entitlements ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.refunds (
  id TEXT PRIMARY KEY,
  payment_id UUID NOT NULL REFERENCES public.payments(id) ON DELETE RESTRICT,
  provider_refund_id TEXT UNIQUE NOT NULL,
  amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
  currency TEXT NOT NULL DEFAULT 'INR' CHECK (currency = 'INR'),
  status TEXT NOT NULL DEFAULT 'REFUND_PENDING' CHECK (status IN ('REFUND_PENDING', 'REFUND_COMPLETED', 'REFUND_FAILED')),
  reason TEXT NOT NULL,
  requested_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
ALTER TABLE public.refunds ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.financial_ledger (
  event_id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  payment_id TEXT,
  user_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
  currency TEXT NOT NULL DEFAULT 'INR' CHECK (currency = 'INR'),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'ORDER_CREATED', 'PAYMENT_CAPTURED', 'REFUND_CREATED', 'REFUND_COMPLETED',
    'REFUND_FAILED', 'COMMISSION_EARNED', 'COMMISSION_REVERSED', 'PAYMENT_ADJUSTMENT'
  )),
  source TEXT NOT NULL,
  provider_reference TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  integrity_hash TEXT NOT NULL
);
ALTER TABLE public.financial_ledger ENABLE ROW LEVEL SECURITY;

CREATE TRIGGER trg_immutable_financial_ledger
  BEFORE UPDATE OR DELETE ON public.financial_ledger
  FOR EACH ROW EXECUTE FUNCTION public.prevent_immutable_record_mutation();

CREATE TRIGGER trg_immutable_audit_logs
  BEFORE UPDATE OR DELETE ON public.audit_logs
  FOR EACH ROW EXECUTE FUNCTION public.prevent_immutable_record_mutation();

-- ============================================================================
-- 16C. CANONICAL ADMIN PERMISSIONS & FOUR-EYES APPROVAL REQUESTS (SECTIONS 7, 16, 17, 42, 43)
-- ============================================================================

CREATE TABLE public.admin_permissions (
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE ON UPDATE CASCADE,
  permission TEXT NOT NULL,
  granted_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, permission)
);
ALTER TABLE public.admin_permissions ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.admin_approval_requests (
  approval_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  requester_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  reviewer_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
  approver_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'REQUESTED' CHECK (status IN ('REQUESTED', 'UNDER_REVIEW', 'APPROVED', 'EXECUTED', 'REJECTED', 'EXPIRED')),
  risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  requires_four_eyes BOOLEAN NOT NULL DEFAULT TRUE,
  reason TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  executed_at TIMESTAMPTZ,
  CHECK (NOT requires_four_eyes OR approver_id IS NULL OR approver_id <> requester_id)
);
ALTER TABLE public.admin_approval_requests ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 16D. CANONICAL GOOGLE INTEGRATION CONNECTIONS & SYNC JOBS (SECTIONS 38, 39, 45)
-- ============================================================================

CREATE TABLE public.google_integration_connections (
  user_id UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE ON UPDATE CASCADE,
  google_sub TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'NOT_CONNECTED' CHECK (status IN ('NOT_CONNECTED', 'AUTHORIZING', 'CONNECTED', 'DEGRADED', 'REAUTH_REQUIRED', 'DISCONNECTED', 'ERROR')),
  encrypted_refresh_token TEXT,
  token_iv_hex TEXT,
  token_auth_tag_hex TEXT,
  access_token_hash TEXT,
  access_token_expires_at TIMESTAMPTZ,
  granted_scopes TEXT[] NOT NULL DEFAULT '{}'::text[],
  revoked_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.google_integration_connections ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.google_sync_jobs (
  job_id TEXT PRIMARY KEY,
  spreadsheet_id TEXT NOT NULL,
  owner_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  domain TEXT NOT NULL CHECK (domain IN ('CHAPTERS', 'EXAM_QUESTIONS', 'EXAM_RESULTS', 'PAYMENTS', 'TEACHER_BALANCES', 'CERTIFICATES')),
  status TEXT NOT NULL DEFAULT 'NOT_STARTED' CHECK (status IN ('NOT_STARTED', 'QUEUED', 'RUNNING', 'SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'RETRYING', 'BLOCKED')),
  external_revision INTEGER NOT NULL DEFAULT 1,
  records_processed INTEGER NOT NULL DEFAULT 0,
  records_succeeded INTEGER NOT NULL DEFAULT 0,
  records_failed INTEGER NOT NULL DEFAULT 0,
  retry_count INTEGER NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
ALTER TABLE public.google_sync_jobs ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 16E. CANONICAL POLICY VERSIONS, USER CONSENTS, PRIVACY EXPORTS & RETENTION HOLDS (SECTIONS 7, 8, 14, 47, 52)
-- ============================================================================

CREATE TABLE public.policy_versions (
  policy_id TEXT PRIMARY KEY,
  policy_type TEXT NOT NULL,
  version TEXT NOT NULL,
  effective_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'ACTIVE', 'SUPERSEDED', 'RETIRED')),
  requirement_level TEXT NOT NULL CHECK (requirement_level IN ('REQUIRED', 'OPTIONAL', 'NOT_APPLICABLE', 'REVIEW_REQUIRED')),
  content_reference TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (policy_type, version)
);
ALTER TABLE public.policy_versions ENABLE ROW LEVEL SECURITY;

CREATE TRIGGER trg_prevent_policy_version_delete
  BEFORE DELETE ON public.policy_versions
  FOR EACH ROW EXECUTE FUNCTION public.prevent_immutable_record_mutation();

CREATE TABLE public.user_consents (
  consent_id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE ON UPDATE CASCADE,
  consent_type TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  accepted BOOLEAN NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source TEXT NOT NULL,
  method TEXT NOT NULL,
  ip_reference TEXT NOT NULL,
  user_agent_reference TEXT NOT NULL,
  withdrawn_at TIMESTAMPTZ,
  FOREIGN KEY (consent_type, policy_version) REFERENCES public.policy_versions(policy_type, version) ON DELETE RESTRICT
);
ALTER TABLE public.user_consents ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.privacy_data_exports (
  export_id TEXT PRIMARY KEY,
  owner_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE ON UPDATE CASCADE,
  requested_by_actor_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'REQUESTED' CHECK (status IN ('REQUESTED', 'VALIDATING', 'PROCESSING', 'READY', 'EXPIRED', 'FAILED', 'CANCELLED')),
  opaque_object_key TEXT NOT NULL UNIQUE,
  download_token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  downloaded_count INTEGER NOT NULL DEFAULT 0,
  max_downloads INTEGER NOT NULL DEFAULT 1,
  CHECK (expires_at > created_at)
);
ALTER TABLE public.privacy_data_exports ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.privacy_retention_holds (
  hold_id TEXT PRIMARY KEY,
  target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  reason TEXT NOT NULL CHECK (reason IN ('LEGAL_HOLD', 'SECURITY_INVESTIGATION', 'FRAUD_REVIEW', 'PAYMENT_DISPUTE', 'EXAM_DISPUTE', 'CERTIFICATE_DISPUTE', 'AUDIT_REQUIREMENT', 'BUSINESS_RECONCILIATION', 'OTHER_APPROVED_REASON')),
  scope_categories TEXT[] NOT NULL DEFAULT '{}'::text[],
  owner_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  review_due_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'RELEASED')),
  released_at TIMESTAMPTZ,
  released_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
  CHECK (review_due_at > created_at)
);
ALTER TABLE public.privacy_retention_holds ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 17. PERFORMANCE INDEXES FOR FOREIGN KEYS, FILTERS & LEADERBOARD (SECTION 21)
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_users_role_status ON public.users(role, status);
CREATE INDEX IF NOT EXISTS idx_users_class_city ON public.users(class, city);
CREATE INDEX IF NOT EXISTS idx_otp_challenges_user_status ON public.otp_challenges(user_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_user_status ON public.password_reset_tokens(user_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_status ON public.user_sessions(user_id, status, absolute_expires_at);
CREATE INDEX IF NOT EXISTS idx_daily_progress_user_day ON public.daily_progress(user_id, day);
CREATE INDEX IF NOT EXISTS idx_exams_user_type_status ON public.exams(user_id, type, status);
CREATE INDEX IF NOT EXISTS idx_exams_leaderboard_score ON public.exams(type, status, score DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_payments_user_status ON public.payments(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_referrals_teacher_status ON public.referrals(teacher_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_withdrawals_teacher_status ON public.withdrawals(teacher_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_certificates_user_code ON public.certificates(user_id, certificate_code);
CREATE INDEX IF NOT EXISTS idx_notifications_user_read_created ON public.notifications(user_id, read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created ON public.audit_logs(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_audit_incident_ts ON public.incident_audit_events(incident_id, timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_verification_submissions_user_status ON public.verification_submissions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_entity_state_history_entity ON public.entity_state_history(entity_type, entity_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_user_consents_user_type_ts ON public.user_consents(user_id, consent_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_privacy_exports_owner_status ON public.privacy_data_exports(owner_user_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_google_sync_jobs_owner_domain ON public.google_sync_jobs(owner_id, domain, status);
CREATE INDEX IF NOT EXISTS idx_retention_holds_target_status ON public.privacy_retention_holds(target_user_id, status);
CREATE INDEX IF NOT EXISTS idx_auth_identities_email ON public.auth_identities(normalized_email);
CREATE INDEX IF NOT EXISTS idx_auth_identities_phone ON public.auth_identities(normalized_phone);
CREATE INDEX IF NOT EXISTS idx_user_sessions_family ON public.user_sessions(family_id);

-- ============================================================================
-- 18. DISTRIBUTED RATE LIMITING TABLE & ATOMIC RPC (PHASE 2 HARDENING)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.distributed_rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 1,
  reset_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.distributed_rate_limits ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Distributed rate limits are server-only access"
  ON public.distributed_rate_limits FOR ALL
  USING (public.get_my_role() = 'admin')
  WITH CHECK (public.get_my_role() = 'admin');

CREATE OR REPLACE FUNCTION public.increment_rate_limit(
  p_key TEXT,
  p_max_requests INTEGER,
  p_window_ms BIGINT,
  p_now TIMESTAMPTZ DEFAULT NOW()
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_rec public.distributed_rate_limits%ROWTYPE;
  v_new_reset TIMESTAMPTZ;
  v_retry_after INTEGER;
BEGIN
  v_new_reset := p_now + (p_window_ms || ' milliseconds')::INTERVAL;
  
  INSERT INTO public.distributed_rate_limits (key, count, reset_at, updated_at)
  VALUES (p_key, 1, v_new_reset, p_now)
  ON CONFLICT (key) DO UPDATE
    SET count = CASE
                  WHEN public.distributed_rate_limits.reset_at <= p_now THEN 1
                  ELSE public.distributed_rate_limits.count + 1
                END,
        reset_at = CASE
                     WHEN public.distributed_rate_limits.reset_at <= p_now THEN v_new_reset
                     ELSE public.distributed_rate_limits.reset_at
                   END,
        updated_at = p_now
  RETURNING * INTO v_rec;

  IF v_rec.count > p_max_requests THEN
    v_retry_after := GREATEST(1, CEIL(EXTRACT(EPOCH FROM (v_rec.reset_at - p_now)))::INTEGER);
    RETURN jsonb_build_object('allowed', FALSE, 'retry_after_sec', v_retry_after, 'count', v_rec.count);
  ELSE
    RETURN jsonb_build_object('allowed', TRUE, 'retry_after_sec', 0, 'count', v_rec.count);
  END IF;
END;
$$;

-- ============================================================================
-- 19. ATOMIC LOGIN FAILURE & LOCKOUT RPC (PHASE 2 HARDENING)
-- ============================================================================

CREATE OR REPLACE FUNCTION public.record_login_failure(
  p_user_id UUID,
  p_max_attempts INTEGER DEFAULT 5,
  p_lockout_seconds INTEGER DEFAULT 600
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_new_attempts INTEGER;
  v_locked_until TIMESTAMPTZ := NULL;
  v_now TIMESTAMPTZ := NOW();
BEGIN
  SELECT failed_login_attempts + 1 INTO v_new_attempts
  FROM public.auth_identities
  WHERE user_id = p_user_id;

  IF NOT FOUND THEN
    v_new_attempts := 1;
  END IF;

  IF v_new_attempts >= p_max_attempts THEN
    v_locked_until := v_now + (p_lockout_seconds || ' seconds')::INTERVAL;
  END IF;

  UPDATE public.auth_identities
  SET failed_login_attempts = v_new_attempts,
      locked_until = v_locked_until,
      updated_at = v_now
  WHERE user_id = p_user_id;

  RETURN jsonb_build_object(
    'attempts', v_new_attempts,
    'locked', (v_locked_until IS NOT NULL),
    'locked_until', v_locked_until
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.reset_login_failures(
  p_user_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.auth_identities
  SET failed_login_attempts = 0,
      locked_until = NULL,
      updated_at = NOW()
  WHERE user_id = p_user_id;
END;
$$;

-- ============================================================================
-- PHASE 4: INDEXES & RLS POLICIES FOR EXAM TABLES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_exam_attempts_student_exam ON public.exam_attempts(student_id, exam_type);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_status ON public.exam_attempts(status);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_deadline ON public.exam_attempts(deadline_at);
CREATE INDEX IF NOT EXISTS idx_exam_attempt_answers_attempt ON public.exam_attempt_answers(attempt_id);
CREATE INDEX IF NOT EXISTS idx_exam_violation_events_attempt ON public.exam_violation_events(attempt_id);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_ranking ON public.exam_attempts(exam_type, status, score DESC, finalized_at ASC);
CREATE INDEX IF NOT EXISTS idx_exam_questions_type ON public.exam_questions(exam_type, status);

ALTER TABLE public.exam_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_attempt_answers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_violation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.exam_result_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Students view exam definitions" ON public.exam_definitions
  FOR SELECT USING (status = 'LIVE' OR public.get_my_role() = 'admin');

CREATE POLICY "Admin manage exam definitions" ON public.exam_definitions
  FOR ALL USING (public.get_my_role() = 'admin') WITH CHECK (public.get_my_role() = 'admin');

CREATE POLICY "Admin manage questions" ON public.exam_questions
  FOR ALL USING (public.get_my_role() = 'admin') WITH CHECK (public.get_my_role() = 'admin');

CREATE POLICY "Students view own exam attempts" ON public.exam_attempts
  FOR SELECT USING (auth.uid() = student_id OR public.get_my_role() = 'admin');

CREATE POLICY "Admin manage exam attempts" ON public.exam_attempts
  FOR ALL USING (public.get_my_role() = 'admin') WITH CHECK (public.get_my_role() = 'admin');

CREATE POLICY "Students view own attempt answers" ON public.exam_attempt_answers
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.exam_attempts WHERE exam_attempts.id = exam_attempt_answers.attempt_id AND exam_attempts.student_id = auth.uid()) OR public.get_my_role() = 'admin');

CREATE POLICY "Admin manage attempt answers" ON public.exam_attempt_answers
  FOR ALL USING (public.get_my_role() = 'admin') WITH CHECK (public.get_my_role() = 'admin');

CREATE POLICY "Students view own violations" ON public.exam_violation_events
  FOR SELECT USING (auth.uid() = student_id OR public.get_my_role() = 'admin');

CREATE POLICY "Admin manage violations" ON public.exam_violation_events
  FOR ALL USING (public.get_my_role() = 'admin') WITH CHECK (public.get_my_role() = 'admin');

CREATE POLICY "Admin manage result events" ON public.exam_result_events
  FOR ALL USING (public.get_my_role() = 'admin') WITH CHECK (public.get_my_role() = 'admin');

-- Seed standard exam definitions
INSERT INTO public.exam_definitions (type, title, status, duration_seconds, total_questions, maximum_marks, attempt_limit, requires_payment)
VALUES 
  ('mid', '15-Day Mid Challenge Exam', 'LIVE', 2700, 150, 150, 1, TRUE),
  ('final', '30-Day Grand Finale Exam', 'LIVE', 2700, 150, 150, 1, TRUE)
ON CONFLICT (type) DO NOTHING;




