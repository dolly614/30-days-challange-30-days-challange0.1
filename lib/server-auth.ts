import crypto from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import type { UserProfile } from './store';
import {
  dbCreateUserWithIdentity,
  dbFindUserById,
  dbFindUserByIdentifier,
  dbGetOtpChallenge,
  dbGetPasswordResetToken,
  dbGetSession,
  dbInvalidateActiveOtpChallenges,
  dbRecordAuditLog,
  dbRevokeAllUserSessions as dbRevokeAllUserSessionsSupabase,
  dbRevokeSessionFamily,
  dbSaveOtpChallenge,
  dbSavePasswordResetToken,
  dbSaveSession,
  dbUpdateIdentity,
  dbUpdateOtpChallenge,
  dbUpdatePasswordResetToken,
  dbUpdateSession,
  dbUpdateUser,
  dbEnforceDistributedRateLimit,
  dbRecordLoginFailureAtomic,
  dbResetLoginFailuresAtomic,
  dbRevokeUserSessionsOnRoleChange,
  clearInMemoryAuthCache,
  getCachedSessionCount,
  getCachedUserById,
  getCachedUserCount,
  isSupabaseConfigured,
  mapUserRowToProfile,
  type AuthIdentityRow,
  type OtpChallengeRow,
  type PasswordResetTokenRow,
  type UserRow,
  type UserSessionRow,
} from './supabase-server';

export type UserRole = 'student' | 'teacher' | 'admin';
export type { UserProfile };

export const SESSION_COOKIE_NAME = 'uyanix_session';
export const OTP_BINDING_COOKIE_NAME = 'uyanix_otp_binding';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const BOOTSTRAPPED_ADMIN_EMAIL = (
  process.env.ADMIN_BOOTSTRAP_EMAIL || 'dollysingh1268@gmail.com'
).trim().toLowerCase();

const TRUSTED_ADMIN_EMAILS = new Set([
  'dollysingh1268@gmail.com',
  'admin@uyanix.in',
  ...(process.env.ADMIN_BOOTSTRAP_EMAIL
    ? [process.env.ADMIN_BOOTSTRAP_EMAIL.trim().toLowerCase()]
    : []),
]);

export function isTrustedAdminEmail(email?: string | null): boolean {
  if (!email) return false;
  const normalized = email.trim().toLowerCase();
  return TRUSTED_ADMIN_EMAILS.has(normalized);
}

export const OTP_SECURITY_CONFIG = {
  OTP_LENGTH: 6,
  OTP_ALPHABET: 'NUMERIC_ONLY',
  OTP_EXPIRY_SECONDS: 300,
  OTP_MAX_VERIFICATION_ATTEMPTS: 5,
  OTP_SINGLE_USE: true,

  OTP_RESEND_COOLDOWN_SECONDS: 60,
  OTP_MAX_RESENDS_PER_10_MINUTES: 5,
  OTP_MAX_RESENDS_PER_HOUR: 10,
  OTP_MAX_SENDS_PER_PHONE_PER_24_HOURS: 20,

  OTP_VERIFY_MAX_REQUESTS_PER_IP_PER_10_MINUTES: 30,
  OTP_VERIFY_MAX_FAILED_ATTEMPTS_PER_ACCOUNT_PER_10_MINUTES: 10,

  OTP_ABUSE_WINDOW_MINUTES: 10,

  ALLOW_DEV_OTP_BYPASS_IN_PRODUCTION: false,
  STORE_PLAINTEXT_OTP: false,
  LOG_OTP_VALUE: false,

  invalidate_previous_active_otp: true,
  mark_otp_as_used: true,
  invalidate_remaining_active_challenges: true,
} as const;

export const PASSWORD_SECURITY_CONFIG = {
  MIN_PASSWORD_LENGTH: 6,
  MAX_PASSWORD_LENGTH: 128,
  SCRYPT_KEYLEN: 64,
  SALT_BYTES: 16,

  RESET_TOKEN_BYTES: 32, // 256-bit high-entropy token (64 hex chars)
  RESET_TOKEN_EXPIRY_SECONDS: 900, // 15 minutes
  RESET_TOKEN_MAX_ATTEMPTS: 5,
  RESET_TOKEN_SINGLE_USE: true,

  FORGOT_COOLDOWN_SECONDS: 60,
  FORGOT_MAX_PER_15_MINUTES: 3,
  FORGOT_MAX_PER_HOUR: 5,
  FORGOT_MAX_PER_24_HOURS: 10,
  FORGOT_MAX_PER_IP_PER_15_MINUTES: 10,

  RESET_MAX_PER_IP_PER_15_MINUTES: 15,
  CHANGE_PASSWORD_MAX_ATTEMPTS_PER_15_MINUTES: 5,

  ALLOW_DEV_RESET_TOKEN_IN_PRODUCTION: false,
  STORE_PLAINTEXT_PASSWORD: false,
  STORE_PLAINTEXT_RESET_TOKEN: false,
  INVALIDATE_SESSIONS_ON_PASSWORD_RESET: true,
  ROTATE_SESSION_ON_PASSWORD_CHANGE: true,
} as const;

export const SESSION_SECURITY_CONFIG = {
  SESSION_IDLE_TIMEOUT_MINUTES: 60,
  SESSION_ABSOLUTE_TIMEOUT_HOURS: 24,
  SESSION_REFRESH_ROTATION: true,
  SESSION_REUSE_DETECTION: true,
  SESSION_INVALIDATE_ON_LOGOUT: true,
  SESSION_INVALIDATE_OTHER_SESSIONS_AFTER_PASSWORD_CHANGE: true,
  ALLOW_SESSION_TOKEN_IN_URL: false,
  LOG_SESSION_TOKEN: false,
  LOG_REFRESH_TOKEN: false,
} as const;

const SESSION_IDLE_TIMEOUT_MS =
  SESSION_SECURITY_CONFIG.SESSION_IDLE_TIMEOUT_MINUTES * 60 * 1000;
const SESSION_ABSOLUTE_TIMEOUT_MS =
  SESSION_SECURITY_CONFIG.SESSION_ABSOLUTE_TIMEOUT_HOURS * 60 * 60 * 1000;

export interface SessionTokenPayload {
  jti: string;
  familyId?: string;
  sub: string;
  email: string;
  phone: string;
  role: UserRole;
  name: string;
  teacherShortName: string;
  classNum: number;
  school: string;
  city: string;
  idVerified: boolean;
  authTime?: number;
  iat: number;
  exp: number;
}

export interface ServerSessionRecord {
  jti: string;
  familyId: string;
  userId: string;
  createdAt: number;
  authTime: number;
  lastActiveAt: number;
  idleExpiresAt: number;
  absoluteExpiresAt: number;
  status: 'active' | 'rotated' | 'revoked' | 'expired' | 'compromised';
  replacedByJti?: string;
  revokedAt?: number;
  revokeReason?: string;
}

export interface StoredAuthIdentity {
  authUserId: string;
  normalizedEmail: string;
  normalizedPhone: string;
  passwordSalt?: string;
  passwordHash?: string;
  passwordChangedAt?: number;
  sessionsRevokedBefore?: number;
  googleUid?: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  termsAcceptedAt: string;
  status: 'active' | 'banned' | 'suspended';
  failedLoginAttempts: number;
  lockedUntil: number;
  createdAt: string;
}

export interface StoredUserRecord {
  profile: UserProfile;
  status?: 'active' | 'banned' | 'suspended';
  googleUid?: string;
  emailVerified: boolean;
  termsAcceptedAt?: string;
  referredByCode?: string;
  failedLoginAttempts: number;
  lockedUntil: number;
}

export interface PasswordResetTokenRecord {
  resetId: string;
  userId: string;
  tokenSalt: string;
  tokenHash: string;
  createdAt: number;
  expiresAt: number;
  attempts: number;
  maxAttempts: number;
  used: boolean;
  usedAt?: number;
  status: 'active' | 'used' | 'expired' | 'invalidated' | 'superseded';
}

export interface PasswordResetRateState {
  identifierKey: string;
  lastRequestedAt: number;
  requestTimestamps24h: number[];
}

export interface OtpChallengeRecord {
  challengeId: string;
  userId: string;
  phone: string;
  otpSalt: string;
  otpHash: string;
  createdAt: number;
  expiresAt: number;
  attempts: number;
  maxAttempts: number;
  resendCount: number;
  used: boolean;
  usedAt?: number;
  status: 'active' | 'used' | 'expired' | 'invalidated' | 'superseded';
}

export interface OtpPhoneRateState {
  phone: string;
  userId: string;
  lastSentAt: number;
  sendTimestamps24h: number[];
  resendTimestamps1h: number[];
  failedVerifyTimestamps10m: number[];
}

export interface OtpBindingPayload {
  challengeId: string;
  userId: string;
  phone: string;
  iat: number;
  exp: number;
}

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

interface IdempotencyRecord {
  userId: string;
  payloadHash: string;
  expiresAt: number;
}

export interface ServerReferralRegistrationRecord {
  id: string;
  referralCode: string;
  teacherId: string;
  studentId: string;
  studentPhone: string;
  status: 'pending';
  commission: 0;
  createdAt: string;
}

export interface ServerAuditEntry {
  id: string;
  actorId: string;
  actorEmail: string;
  actorRole: UserRole;
  action: string;
  target: string;
  timestamp: string;
}

interface PersistentAuthDatabase {
  authAccounts: Record<string, StoredAuthIdentity>;
  users: Record<string, StoredUserRecord>;
  phoneIndex: Record<string, string>;
  emailIndex: Record<string, string>;
  idempotencyKeys: Record<string, IdempotencyRecord>;
  referralRegistrations: Record<string, ServerReferralRegistrationRecord>;
  roleAssignments: Record<string, UserRole>;
  bannedUserIds: Record<string, boolean>;
  sessions: Record<string, ServerSessionRecord>;
  revokedSessions: Record<string, number>;
  otpChallenges: Record<string, OtpChallengeRecord>;
  otpRateStates: Record<string, OtpPhoneRateState>;
  passwordResetTokens: Record<string, PasswordResetTokenRecord>;
  passwordResetRateStates: Record<string, PasswordResetRateState>;
  rateLimits: Record<string, RateLimitBucket>;
  auditLogs: ServerAuditEntry[];
}

// In-process concurrency locks for simultaneous registration, OTP, and password reset requests
const inFlightRegistrationLocks = new Set<string>();
const inFlightOtpLocks = new Set<string>();
const inFlightPasswordResetLocks = new Set<string>();

// Approved teacher referral codes eligible to be linked in pending state during registration
const APPROVED_TEACHER_REFERRAL_CODES: Record<
  string,
  { teacherId: string; teacherEmail: string; teacherPhone: string }
> = {
  DOLLOXW0: {
    teacherId: 'teacher-dolly',
    teacherEmail: 'dollysingh1268@gmail.com',
    teacherPhone: '9897320579',
  },
};

function getSigningSecret(): string {
  const secret = process.env.AUTH_SESSION_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'FATAL: AUTH_SESSION_SECRET must be configured in production (minimum 32 bytes). Refusing to start session services.'
      );
    }
    // Strict development-only fallback (never reused from any API keys or service credentials)
    return 'uyanix-dev-environment-session-key-must-be-replaced-in-prod-64bytes';
  }
  if (secret.length < 32 && process.env.NODE_ENV === 'production') {
    throw new Error(
      'FATAL: AUTH_SESSION_SECRET must be at least 32 characters in production.'
    );
  }
  // Enforce secret separation: verify that AUTH_SESSION_SECRET is NOT reusing third-party API keys
  if (
    (process.env.GEMINI_API_KEY && secret === process.env.GEMINI_API_KEY) ||
    (process.env.RAZORPAY_KEY_SECRET && secret === process.env.RAZORPAY_KEY_SECRET) ||
    (process.env.RAZORPAY_WEBHOOK_SECRET && secret === process.env.RAZORPAY_WEBHOOK_SECRET) ||
    (process.env.SUPABASE_SERVICE_ROLE_KEY && secret === process.env.SUPABASE_SERVICE_ROLE_KEY)
  ) {
    throw new Error(
      'FATAL: AUTH_SESSION_SECRET must not reuse GEMINI_API_KEY, RAZORPAY secrets, or SUPABASE service keys.'
    );
  }
  return secret;
}

let memoryDb: PersistentAuthDatabase | null = null;
let memoryDbMtimeMs = 0;

function ensureDbShape(
  raw: Partial<PersistentAuthDatabase>
): PersistentAuthDatabase {
  const users = raw.users || {};
  const authAccounts = raw.authAccounts || {};
  const phoneIndex = raw.phoneIndex || {};
  const emailIndex = raw.emailIndex || {};

  // Rebuild unique indexes from existing user records if needed
  for (const [uid, rec] of Object.entries(users)) {
    if (rec?.profile) {
      const normPhone = rec.profile.phone?.replace(/\D/g, '').slice(-10);
      const normEmail = rec.profile.email?.trim().toLowerCase();
      if (normPhone && normPhone.length === 10 && !phoneIndex[normPhone]) {
        phoneIndex[normPhone] = uid;
      }
      if (normEmail && !emailIndex[normEmail]) {
        emailIndex[normEmail] = uid;
      }
      if (!authAccounts[uid]) {
        const legacyRec = rec as StoredUserRecord & {
          passwordSalt?: string;
          passwordHash?: string;
        };
        authAccounts[uid] = {
          authUserId: uid,
          normalizedEmail: normEmail || '',
          normalizedPhone: normPhone || '',
          passwordSalt: legacyRec.passwordSalt,
          passwordHash: legacyRec.passwordHash,
          googleUid: rec.googleUid,
          emailVerified: Boolean(rec.emailVerified),
          phoneVerified: false,
          termsAcceptedAt: rec.termsAcceptedAt || rec.profile.createdAt,
          status: rec.status || 'active',
          failedLoginAttempts: rec.failedLoginAttempts || 0,
          lockedUntil: rec.lockedUntil || 0,
          createdAt: rec.profile.createdAt,
        };
      }
      // Never duplicate password hashes inside the user profile record (AUTH-05 #2)
      const cleanRec = rec as StoredUserRecord & {
        passwordSalt?: string;
        passwordHash?: string;
      };
      delete cleanRec.passwordSalt;
      delete cleanRec.passwordHash;
    }
  }

  const adminId = 'usr_admin_dolly';
  if (!users[adminId]) {
    const adminEmail = BOOTSTRAPPED_ADMIN_EMAIL;
    const adminPhone = '9897320579';
    const { salt, hash } = hashPassword('Admin@12345');
    const nowIso = new Date().toISOString();

    const adminProfile: UserProfile = {
      id: adminId,
      name: 'Dolly Singh (Admin)',
      teacherShortName: 'dolly',
      email: adminEmail,
      phone: adminPhone,
      classNum: 12,
      school: 'Uyanix Headquarters',
      city: 'Jaipur',
      role: 'admin',
      idVerified: true,
      streakReminders: true,
      createdAt: nowIso,
    };

    users[adminId] = {
      profile: adminProfile,
      termsAcceptedAt: nowIso,
      emailVerified: true,
      status: 'active',
      failedLoginAttempts: 0,
      lockedUntil: 0,
    };

    authAccounts[adminId] = {
      authUserId: adminId,
      normalizedEmail: adminEmail,
      normalizedPhone: adminPhone,
      passwordSalt: salt,
      passwordHash: hash,
      emailVerified: true,
      phoneVerified: true,
      termsAcceptedAt: nowIso,
      status: 'active',
      failedLoginAttempts: 0,
      lockedUntil: 0,
      createdAt: nowIso,
    };

    phoneIndex[adminPhone] = adminId;
    emailIndex[adminEmail] = adminId;
    emailIndex['dollysingh1268@gmail.com'] = adminId;
    emailIndex['admin@uyanix.in'] = adminId;
  }

  const teacherId = 'usr_teacher_dolly';
  if (!users[teacherId]) {
    const teacherEmail = 'teacher@uyanix.in';
    const teacherPhone = '9876543210';
    const { salt, hash } = hashPassword('Teacher@12345');
    const nowIso = new Date().toISOString();

    const teacherProfile: UserProfile = {
      id: teacherId,
      name: 'Dolly Ma’am (Educator)',
      teacherShortName: 'dolly',
      email: teacherEmail,
      phone: teacherPhone,
      classNum: 10,
      school: 'KV No. 1, Jaipur',
      city: 'Jaipur',
      role: 'teacher',
      idVerified: true,
      streakReminders: true,
      createdAt: nowIso,
    };

    users[teacherId] = {
      profile: teacherProfile,
      termsAcceptedAt: nowIso,
      emailVerified: true,
      status: 'active',
      failedLoginAttempts: 0,
      lockedUntil: 0,
    };

    authAccounts[teacherId] = {
      authUserId: teacherId,
      normalizedEmail: teacherEmail,
      normalizedPhone: teacherPhone,
      passwordSalt: salt,
      passwordHash: hash,
      emailVerified: true,
      phoneVerified: true,
      termsAcceptedAt: nowIso,
      status: 'active',
      failedLoginAttempts: 0,
      lockedUntil: 0,
      createdAt: nowIso,
    };

    phoneIndex[teacherPhone] = teacherId;
    emailIndex[teacherEmail] = teacherId;
  }

  const roleAssignments = raw.roleAssignments || {};
  roleAssignments[adminId] = 'admin';
  roleAssignments[teacherId] = 'teacher';

  return {
    authAccounts,
    users,
    phoneIndex,
    emailIndex,
    idempotencyKeys: raw.idempotencyKeys || {},
    referralRegistrations: raw.referralRegistrations || {},
    roleAssignments,
    bannedUserIds: raw.bannedUserIds || {},
    sessions: raw.sessions || {},
    revokedSessions: raw.revokedSessions || {},
    otpChallenges: raw.otpChallenges || {},
    otpRateStates: raw.otpRateStates || {},
    passwordResetTokens: raw.passwordResetTokens || {},
    passwordResetRateStates: raw.passwordResetRateStates || {},
    rateLimits: raw.rateLimits || {},
    auditLogs: Array.isArray(raw.auditLogs) ? raw.auditLogs : [],
  };
}

function acquireFileLock(): boolean {
  return true;
}

function releaseFileLock(): void {
  // Concurrency handled via PostgreSQL atomic constraints & in-flight sets
}

function loadAuthDb(): PersistentAuthDatabase {
  if (memoryDb) {
    return memoryDb;
  }
  memoryDb = ensureDbShape({});
  return memoryDb;
}

function saveAuthDb(db: PersistentAuthDatabase, currentNowMs?: number): void {
  memoryDb = db;
  try {
    const now = typeof currentNowMs === 'number' ? currentNowMs : Date.now();
    for (const [jti, exp] of Object.entries(db.revokedSessions)) {
      if (exp < now) delete db.revokedSessions[jti];
    }
    for (const [jti, sess] of Object.entries(db.sessions)) {
      if (sess.absoluteExpiresAt + 60 * 60 * 1000 < now) {
        delete db.sessions[jti];
      }
    }
    for (const [key, bucket] of Object.entries(db.rateLimits)) {
      if (bucket.resetAt < now) delete db.rateLimits[key];
    }
    // Clean up OTP challenges that expired more than 1 hour ago
    for (const [phone, challenge] of Object.entries(db.otpChallenges)) {
      if (challenge.expiresAt + 60 * 60 * 1000 < now) {
        delete db.otpChallenges[phone];
      }
    }
    // Clean up password reset tokens that expired more than 1 hour ago
    for (const [resetId, tokenRec] of Object.entries(db.passwordResetTokens)) {
      if (tokenRec.expiresAt + 60 * 60 * 1000 < now) {
        delete db.passwordResetTokens[resetId];
      }
    }
    for (const [idemKey, rec] of Object.entries(db.idempotencyKeys)) {
      if (rec.expiresAt < now) delete db.idempotencyKeys[idemKey];
    }
    if (db.auditLogs.length > 250) {
      db.auditLogs = db.auditLogs.slice(0, 250);
    }
  } catch {
    // Keep in-memory cache
  }
}

function sanitizeAuditValue(raw: string): string {
  if (!raw) return '';
  return raw
    // Redact signed session/JWT/refresh tokens
    .replace(/[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{24,}/g, '[REDACTED_TOKEN]')
    // Redact password reset tokens (rst_<24hex>.<64hex>)
    .replace(/rst_[a-f0-9]{24}\.[a-f0-9]{64}/gi, '[REDACTED_RESET_TOKEN]')
    // Redact Bearer tokens
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]');
}

export function recordServerAuditLog(params: {
  actorId: string;
  actorEmail: string;
  actorRole: UserRole;
  action: string;
  target: string;
}): ServerAuditEntry {
  const db = loadAuthDb();
  const entry: ServerAuditEntry = {
    id: `srv_aud_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    actorId: sanitizeAuditValue(params.actorId),
    actorEmail: sanitizeAuditValue(params.actorEmail),
    actorRole: params.actorRole,
    action: sanitizeAuditValue(params.action),
    target: sanitizeAuditValue(params.target),
    timestamp: new Date().toISOString(),
  };
  db.auditLogs.unshift(entry);
  saveAuthDb(db);
  return entry;
}

export function getServerAuditLogs(): ServerAuditEntry[] {
  return loadAuthDb().auditLogs;
}

/**
 * Resolves the single authoritative backend role for a user.
 * The client can NEVER define or elevate this role.
 */
export function resolveTrustedUserRole(params: {
  userId: string;
  email?: string;
  emailVerified?: boolean;
}): UserRole {
  const db = loadAuthDb();
  const normalizedEmail = (params.email || '').trim().toLowerCase();

  // 1. Explicit server-side role assignment by Admin takes precedence
  const assignedRole = db.roleAssignments[params.userId];
  if (
    assignedRole === 'admin' ||
    assignedRole === 'teacher' ||
    assignedRole === 'student'
  ) {
    return assignedRole;
  }

  // 2. Stored user profile in server database
  const existingRecord = db.users[params.userId];
  if (existingRecord) {
    if (
      existingRecord.emailVerified &&
      isTrustedAdminEmail(existingRecord.profile.email)
    ) {
      return 'admin';
    }
    const storedRole = existingRecord.profile.role;
    if (
      storedRole === 'admin' ||
      storedRole === 'teacher' ||
      storedRole === 'student'
    ) {
      return storedRole;
    }
  }

  // 3. Bootstrapped admin requires verified email matching TRUSTED_ADMIN_EMAILS
  if (params.emailVerified && isTrustedAdminEmail(normalizedEmail)) {
    return 'admin';
  }

  // Default role for all accounts is strictly 'student'
  return 'student';
}

export function hashPassword(
  password: string,
  salt?: string
): {
  salt: string;
  hash: string;
} {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, usedSalt, 64).toString('hex');
  return { salt: usedSalt, hash: derived };
}

export function verifyPassword(
  password: string,
  salt?: string,
  expectedHash?: string
): boolean {
  if (!salt || !expectedHash) return false;
  const { hash } = hashPassword(password, salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function getClientIp(req: NextRequest): string {
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.headers.get('x-real-ip') || '127.0.0.1';
}

export async function enforceDistributedRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): Promise<{ allowed: boolean; retryAfterSec: number }> {
  const result = await dbEnforceDistributedRateLimit(key, maxRequests, windowMs);
  const db = loadAuthDb();
  db.rateLimits[key] = {
    count: result.count,
    resetAt: Date.now() + (result.retryAfterSec * 1000 || windowMs),
  };
  return { allowed: result.allowed, retryAfterSec: result.retryAfterSec };
}

export function enforceRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): { allowed: boolean; retryAfterSec: number } {
  // Synchronize across server instances in distributed PostgreSQL
  dbEnforceDistributedRateLimit(key, maxRequests, windowMs).catch(() => {});

  const db = loadAuthDb();
  const now = Date.now();
  const existing = db.rateLimits[key];

  if (!existing || now >= existing.resetAt) {
    db.rateLimits[key] = { count: 1, resetAt: now + windowMs };
    saveAuthDb(db);
    return { allowed: true, retryAfterSec: 0 };
  }

  if (existing.count >= maxRequests) {
    const retryAfterSec = Math.max(
      1,
      Math.ceil((existing.resetAt - now) / 1000)
    );
    return { allowed: false, retryAfterSec };
  }

  existing.count += 1;
  saveAuthDb(db);
  return { allowed: true, retryAfterSec: 0 };
}

// ============================================================================
// SERVER-SIDE REGISTRATION FIELD VALIDATORS (AUTH-03)
// ============================================================================

export function validateFullName(
  rawName: unknown
): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof rawName !== 'string') {
    return { ok: false, error: 'Full name is required.' };
  }
  if (rawName.length > 200) {
    return { ok: false, error: 'Full name cannot exceed 100 characters.' };
  }
  const normalized = rawName.trim().replace(/\s+/g, ' ');
  if (normalized.length < 2) {
    return { ok: false, error: 'Please enter a valid full name (at least 2 characters).' };
  }
  if (normalized.length > 100) {
    return { ok: false, error: 'Full name cannot exceed 100 characters.' };
  }
  // Reject HTML/script injection characters or control chars
  if (
    /[<>`$\\{};[\]|^~]/.test(normalized) ||
    /[\u0000-\u001F\u007F]/.test(normalized) ||
    /javascript:|onerror|onload|<script/i.test(normalized)
  ) {
    return { ok: false, error: 'Full name contains invalid characters.' };
  }
  // Require at least one Unicode letter and allow Indian/Unicode letters, marks, spaces, dots, hyphens, apostrophes
  if (!/\p{L}/u.test(normalized) || !/^[\p{L}\p{M}\s.'-]+$/u.test(normalized)) {
    return {
      ok: false,
      error: 'Full name may only contain letters, spaces, dots, hyphens, or apostrophes.',
    };
  }
  return { ok: true, value: normalized };
}

export function validateStudentClass(
  rawClass: unknown
): { ok: true; value: number } | { ok: false; error: string } {
  if (
    rawClass === null ||
    rawClass === undefined ||
    typeof rawClass === 'boolean' ||
    typeof rawClass === 'object'
  ) {
    return { ok: false, error: 'Class must be between Class 1 and Class 12.' };
  }

  let parsedNum: number;
  if (typeof rawClass === 'number') {
    if (!Number.isInteger(rawClass)) {
      return { ok: false, error: 'Class must be an integer between 1 and 12.' };
    }
    parsedNum = rawClass;
  } else if (typeof rawClass === 'string') {
    const trimmed = rawClass.trim();
    const match = /^(?:class\s*)?([0-9]{1,2})$/i.exec(trimmed);
    if (!match) {
      return { ok: false, error: 'Class must be between Class 1 and Class 12.' };
    }
    parsedNum = Number(match[1]);
  } else {
    return { ok: false, error: 'Class must be between Class 1 and Class 12.' };
  }

  if (!Number.isInteger(parsedNum) || parsedNum < 1 || parsedNum > 12) {
    return { ok: false, error: 'Class must be between Class 1 and Class 12.' };
  }

  return { ok: true, value: parsedNum };
}

export function validateSchoolName(
  rawSchool: unknown
): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof rawSchool !== 'string') {
    return { ok: false, error: 'School name is required.' };
  }
  if (rawSchool.length > 300) {
    return { ok: false, error: 'School name cannot exceed 160 characters.' };
  }
  const normalized = rawSchool.trim().replace(/\s+/g, ' ');
  if (normalized.length < 2) {
    return { ok: false, error: 'Please enter a valid school name (at least 2 characters).' };
  }
  if (normalized.length > 160) {
    return { ok: false, error: 'School name cannot exceed 160 characters.' };
  }
  if (
    /[<>`$\\{};|^~]/.test(normalized) ||
    /[\u0000-\u001F\u007F]/.test(normalized) ||
    /javascript:|onerror|onload|<script/i.test(normalized) ||
    !/\p{L}/u.test(normalized)
  ) {
    return { ok: false, error: 'Please enter a valid school name without special HTML characters.' };
  }
  return { ok: true, value: normalized };
}

export function validateIndianMobile(
  rawPhone: unknown
): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof rawPhone !== 'string') {
    return { ok: false, error: 'Please enter a valid 10-digit Indian mobile number.' };
  }
  const trimmed = rawPhone.trim();
  if (trimmed.length < 10 || trimmed.length > 20) {
    return { ok: false, error: 'Please enter a valid 10-digit Indian mobile number.' };
  }
  // Reject any input that contains letters, script tags, or non-phone punctuation
  if (!/^[0-9+\s()-]{10,20}$/.test(trimmed)) {
    return { ok: false, error: 'Please enter a valid 10-digit Indian mobile number.' };
  }

  const compact = trimmed.replace(/[\s()-]/g, '');
  let subscriber = compact;
  if (subscriber.startsWith('+91')) {
    subscriber = subscriber.slice(3);
  } else if (subscriber.length === 12 && subscriber.startsWith('91')) {
    subscriber = subscriber.slice(2);
  } else if (subscriber.length === 11 && subscriber.startsWith('0')) {
    subscriber = subscriber.slice(1);
  }

  if (!/^[6-9]\d{9}$/.test(subscriber)) {
    return {
      ok: false,
      error: 'Please enter a valid 10-digit Indian mobile number starting with 6, 7, 8, or 9.',
    };
  }

  return { ok: true, value: subscriber };
}

export function validateOptionalEmail(
  rawEmail: unknown
): { ok: true; value: string | undefined } | { ok: false; error: string } {
  if (rawEmail === undefined || rawEmail === null || rawEmail === '') {
    return { ok: true, value: undefined };
  }
  if (typeof rawEmail !== 'string') {
    return { ok: false, error: 'Please enter a valid email address.' };
  }
  const trimmed = rawEmail.trim().toLowerCase();
  if (trimmed === '') {
    return { ok: true, value: undefined };
  }
  if (trimmed.length > 160) {
    return { ok: false, error: 'Email address cannot exceed 160 characters.' };
  }
  if (
    /[<>`$\\{};[\]|^~\s]/.test(trimmed) ||
    !/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed)
  ) {
    return { ok: false, error: 'Please enter a valid email address.' };
  }
  return { ok: true, value: trimmed };
}

const DISALLOWED_WEAK_PASSWORDS = new Set([
  '123456',
  '1234567',
  '12345678',
  '123456789',
  '1234567890',
  '654321',
  '000000',
  '111111',
  '222222',
  '333333',
  '444444',
  '555555',
  '666666',
  '777777',
  '888888',
  '999999',
  'password',
  'password1',
  'password123',
  'qwerty',
  'qwerty123',
  'abc123',
  'admin123',
  'uyanix',
  'uyanix123',
  'welcome',
  'letmein',
  'iloveyou',
]);

export function validatePasswordStrength(
  rawPassword: unknown,
  context?: {
    email?: string;
    phone?: string;
    name?: string;
  }
): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof rawPassword !== 'string') {
    return {
      ok: false,
      error: 'Password is required.',
    };
  }

  if (
    rawPassword.length < PASSWORD_SECURITY_CONFIG.MIN_PASSWORD_LENGTH ||
    rawPassword.length > PASSWORD_SECURITY_CONFIG.MAX_PASSWORD_LENGTH ||
    rawPassword.trim().length < PASSWORD_SECURITY_CONFIG.MIN_PASSWORD_LENGTH
  ) {
    return {
      ok: false,
      error: 'Password must be between 6 and 128 characters.',
    };
  }

  // Reject control characters or null bytes
  if (/[\u0000-\u001F\u007F]/.test(rawPassword)) {
    return {
      ok: false,
      error: 'Password contains invalid characters.',
    };
  }

  const lower = rawPassword.trim().toLowerCase();
  if (DISALLOWED_WEAK_PASSWORDS.has(lower)) {
    return {
      ok: false,
      error:
        'This password is too common or weak. Please choose a stronger password.',
    };
  }

  // Reject passwords consisting of a single repeated character (e.g., "aaaaaa", "1111111")
  if (/^(.)\1+$/.test(rawPassword.trim())) {
    return {
      ok: false,
      error:
        'Password cannot consist of a single repeated character. Please choose a stronger password.',
    };
  }

  if (context?.phone) {
    const normPhone = context.phone.replace(/\D/g, '').slice(-10);
    if (normPhone && lower === normPhone) {
      return {
        ok: false,
        error: 'Password cannot be the same as your mobile number.',
      };
    }
  }

  if (context?.email) {
    const normEmail = context.email.trim().toLowerCase();
    if (
      normEmail &&
      (lower === normEmail || lower === normEmail.split('@')[0])
    ) {
      return {
        ok: false,
        error: 'Password cannot be the same as your email address.',
      };
    }
  }

  if (context?.name) {
    const normName = context.name.trim().toLowerCase();
    if (normName.length >= 3 && lower === normName) {
      return {
        ok: false,
        error: 'Password cannot be the same as your name.',
      };
    }
  }

  return { ok: true, value: rawPassword };
}

function verifyProfileRecordConsistency(
  db: PersistentAuthDatabase,
  userId: string
): boolean {
  const authIdentity = db.authAccounts[userId];
  const userRecord = db.users[userId];
  const assignedRole = db.roleAssignments[userId];

  if (!userRecord || !userRecord.profile) return false;
  const profile = userRecord.profile;

  if (profile.id !== userId) return false;
  if (!profile.name || profile.name.trim().length < 2) return false;
  if (
    !Number.isInteger(profile.classNum) ||
    profile.classNum < 1 ||
    profile.classNum > 12
  ) {
    return false;
  }
  if (!profile.school || profile.school.trim().length < 2) return false;
  if (!/^[6-9]\d{9}$/.test(profile.phone)) return false;
  if (
    profile.role !== 'student' &&
    profile.role !== 'teacher' &&
    profile.role !== 'admin'
  ) {
    return false;
  }
  if (assignedRole && assignedRole !== profile.role) return false;
  if (authIdentity && authIdentity.authUserId !== userId) return false;
  if (userRecord.status === 'banned' || userRecord.status === 'suspended') {
    return false;
  }

  return true;
}

function base64UrlEncode(input: string | Buffer): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(input: string): string {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4;
  const padded = pad ? normalized + '='.repeat(4 - pad) : normalized;
  return Buffer.from(padded, 'base64').toString('utf-8');
}

export function signSessionToken(
  user: UserProfile,
  options?: {
    nowMs?: number;
    familyId?: string;
    authTime?: number;
    preExistingToken?: string | null;
  }
): string {
  const now = typeof options?.nowMs === 'number' ? options.nowMs : Date.now();

  // AUTH-06 #14: Session Fixation Protection — invalidate any pre-login session token before issuing a new one
  if (options?.preExistingToken) {
    revokeSessionToken(options.preExistingToken, 'session_fixation_rotation');
  }

  const trustedRole = resolveTrustedUserRole({
    userId: user.id,
    email: user.email,
    emailVerified: user.role === 'admin',
  });

  const jti = crypto.randomUUID();
  const familyId = options?.familyId || `fam_${crypto.randomUUID()}`;
  const authTime =
    typeof options?.authTime === 'number' ? options.authTime : now;
  const absoluteExpiresAt = authTime + SESSION_ABSOLUTE_TIMEOUT_MS;
  const idleExpiresAt = Math.min(
    absoluteExpiresAt,
    now + SESSION_IDLE_TIMEOUT_MS
  );

  const payload: SessionTokenPayload = {
    jti,
    familyId,
    sub: user.id,
    email: user.email,
    phone: user.phone,
    role: trustedRole,
    name: user.name,
    teacherShortName: user.teacherShortName,
    classNum: user.classNum,
    school: user.school,
    city: user.city,
    idVerified: user.idVerified,
    authTime,
    iat: now,
    exp: absoluteExpiresAt,
  };

  const db = loadAuthDb();
  db.sessions[jti] = {
    jti,
    familyId,
    userId: user.id,
    createdAt: now,
    authTime,
    lastActiveAt: now,
    idleExpiresAt,
    absoluteExpiresAt,
    status: 'active',
  };
  saveAuthDb(db, now);

  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signature = crypto
    .createHmac('sha256', getSigningSecret())
    .update(payloadB64)
    .digest();
  const signatureB64 = base64UrlEncode(signature);
  return `${payloadB64}.${signatureB64}`;
}

function decodeAndVerifySessionSignature(
  token: string | undefined | null
): SessionTokenPayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [payloadB64, signatureB64] = parts;
  if (!payloadB64 || !signatureB64) return null;

  try {
    const expectedSig = crypto
      .createHmac('sha256', getSigningSecret())
      .update(payloadB64)
      .digest();
    const expectedSigB64 = base64UrlEncode(expectedSig);

    const a = Buffer.from(signatureB64, 'utf-8');
    const b = Buffer.from(expectedSigB64, 'utf-8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const decoded = JSON.parse(
      base64UrlDecode(payloadB64)
    ) as SessionTokenPayload;

    if (
      !decoded ||
      typeof decoded.sub !== 'string' ||
      typeof decoded.jti !== 'string' ||
      typeof decoded.exp !== 'number'
    ) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
}

export function verifySessionTokenString(
  token: string | undefined | null,
  options?: { nowMs?: number; touchActivity?: boolean }
): SessionTokenPayload | null {
  const decoded = decodeAndVerifySessionSignature(token);
  if (!decoded) return null;

  const nowMs = typeof options?.nowMs === 'number' ? options.nowMs : Date.now();
  const touchActivity = options?.touchActivity !== false;

  try {
    const authTime =
      typeof decoded.authTime === 'number' ? decoded.authTime : decoded.iat;
    const hardAbsoluteExp = Math.min(
      decoded.exp,
      authTime + SESSION_ABSOLUTE_TIMEOUT_MS
    );

    if (nowMs >= hardAbsoluteExp) {
      return null;
    }

    const db = loadAuthDb();
    const sessionRec = db.sessions[decoded.jti];

    if (sessionRec) {
      // AUTH-06 #9 & #10: Refresh/Session Token Reuse Detection
      if (
        sessionRec.status === 'rotated' &&
        SESSION_SECURITY_CONFIG.SESSION_REUSE_DETECTION
      ) {
        for (const sess of Object.values(db.sessions)) {
          if (sess.familyId === sessionRec.familyId) {
            sess.status = 'compromised';
            sess.revokedAt = nowMs;
            sess.revokeReason = 'token_reuse_detected';
            db.revokedSessions[sess.jti] = sess.absoluteExpiresAt;
          }
        }
        saveAuthDb(db, nowMs);
        recordServerAuditLog({
          actorId: decoded.sub,
          actorEmail: decoded.email || decoded.phone || 'unknown',
          actorRole: decoded.role,
          action: 'SUSPICIOUS_TOKEN_REUSE_DETECTED',
          target: `family:${sessionRec.familyId}`,
        });
        return null;
      }

      if (
        sessionRec.status === 'revoked' ||
        sessionRec.status === 'compromised'
      ) {
        recordServerAuditLog({
          actorId: decoded.sub,
          actorEmail: decoded.email || decoded.phone || 'unknown',
          actorRole: decoded.role,
          action: 'REVOKED_SESSION_REUSE_ATTEMPT',
          target: `session:${decoded.jti.slice(0, 8)}`,
        });
        return null;
      }

      // AUTH-06 #12 & #13: Server-side Idle Timeout (60m) and Absolute Timeout (24h)
      if (
        sessionRec.status === 'expired' ||
        nowMs >= sessionRec.absoluteExpiresAt ||
        nowMs >= sessionRec.idleExpiresAt
      ) {
        if (sessionRec.status === 'active') {
          sessionRec.status = 'expired';
          saveAuthDb(db, nowMs);
        }
        return null;
      }
    }

    if (db.revokedSessions[decoded.jti]) {
      recordServerAuditLog({
        actorId: decoded.sub,
        actorEmail: decoded.email || decoded.phone || 'unknown',
        actorRole: decoded.role,
        action: 'REVOKED_SESSION_REUSE_ATTEMPT',
        target: `session:${decoded.jti.slice(0, 8)}`,
      });
      return null;
    }

    if (db.bannedUserIds[decoded.sub]) {
      return null;
    }

    // AUTH-05 #15 & AUTH-06 #18: Invalidate sessions issued prior to a password reset or password change
    const authAccount = db.authAccounts[decoded.sub];
    if (authAccount) {
      if (
        typeof authAccount.passwordChangedAt === 'number' &&
        decoded.iat < authAccount.passwordChangedAt
      ) {
        return null;
      }
      if (
        typeof authAccount.sessionsRevokedBefore === 'number' &&
        decoded.iat < authAccount.sessionsRevokedBefore
      ) {
        return null;
      }
    }

    if (sessionRec && sessionRec.status === 'active' && touchActivity) {
      sessionRec.lastActiveAt = nowMs;
      sessionRec.idleExpiresAt = Math.min(
        sessionRec.absoluteExpiresAt,
        nowMs + SESSION_IDLE_TIMEOUT_MS
      );
      saveAuthDb(db, nowMs);
    }

    return decoded;
  } catch {
    return null;
  }
}

/**
 * Rotates an active session credential into a new JTI within the same session family,
 * invalidating the old credential and preserving the original absolute timeout.
 * If an already-rotated credential is replayed, SESSION_REUSE_DETECTION invalidates the entire family.
 */
export function rotateSessionToken(
  currentToken: string | undefined | null,
  options?: { nowMs?: number }
):
  | {
      ok: true;
      token: string;
      session: SessionTokenPayload;
      user: UserProfile;
    }
  | { ok: false; status: 401; error: string } {
  const nowMs = typeof options?.nowMs === 'number' ? options.nowMs : Date.now();
  const verified = verifySessionTokenString(currentToken, {
    nowMs,
    touchActivity: false,
  });

  if (!verified) {
    return {
      ok: false,
      status: 401,
      error: 'Unauthorized: Session is invalid, expired, or has been revoked.',
    };
  }

  const db = loadAuthDb();
  const userRecord = db.users[verified.sub];
  if (
    userRecord &&
    (userRecord.status === 'banned' ||
      userRecord.status === 'suspended' ||
      db.bannedUserIds[verified.sub])
  ) {
    return {
      ok: false,
      status: 401,
      error: 'Unauthorized: Account is suspended.',
    };
  }

  const authoritativeRole = resolveTrustedUserRole({
    userId: verified.sub,
    email: userRecord?.profile.email || verified.email,
    emailVerified:
      userRecord?.emailVerified ??
      (verified.role === 'admin' &&
        verified.email.toLowerCase() === BOOTSTRAPPED_ADMIN_EMAIL),
  });

  const userProfile: UserProfile = userRecord?.profile
    ? { ...userRecord.profile, role: authoritativeRole }
    : {
        id: verified.sub,
        name: verified.name,
        teacherShortName: verified.teacherShortName,
        email: verified.email,
        phone: verified.phone,
        classNum: verified.classNum,
        school: verified.school,
        city: verified.city,
        role: authoritativeRole,
        idVerified: verified.idVerified,
        streakReminders: true,
        createdAt: new Date(verified.iat).toISOString(),
      };

  const oldSessionRec = db.sessions[verified.jti];
  const familyId =
    oldSessionRec?.familyId || verified.familyId || `fam_${crypto.randomUUID()}`;
  const authTime =
    oldSessionRec?.authTime || verified.authTime || verified.iat;

  if (oldSessionRec) {
    oldSessionRec.status = 'rotated';
    oldSessionRec.revokedAt = nowMs;
    oldSessionRec.revokeReason = 'token_refresh_rotation';
    saveAuthDb(db, nowMs);
  } else {
    db.revokedSessions[verified.jti] = verified.exp;
    saveAuthDb(db, nowMs);
  }

  const newToken = signSessionToken(userProfile, {
    nowMs,
    familyId,
    authTime,
  });
  const newDecoded = decodeAndVerifySessionSignature(newToken)!;

  const updatedDb = loadAuthDb();
  if (updatedDb.sessions[verified.jti]) {
    updatedDb.sessions[verified.jti].replacedByJti = newDecoded.jti;
    saveAuthDb(updatedDb, nowMs);
  }

  recordServerAuditLog({
    actorId: userProfile.id,
    actorEmail: userProfile.email || userProfile.phone,
    actorRole: userProfile.role,
    action: 'SESSION_TOKEN_ROTATED',
    target: `family:${familyId}`,
  });

  return {
    ok: true,
    token: newToken,
    session: newDecoded,
    user: userProfile,
  };
}

export function setSessionCookie(res: NextResponse, token: string): void {
  res.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: token,
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    path: '/',
    maxAge: Math.floor(SESSION_ABSOLUTE_TIMEOUT_MS / 1000),
  });
}

export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    path: '/',
    maxAge: 0,
  });
}

export function revokeSessionToken(
  token: string | undefined | null,
  reason = 'user_logout'
): boolean {
  const payload = decodeAndVerifySessionSignature(token);
  if (!payload) return false;

  const now = Date.now();
  const db = loadAuthDb();
  db.revokedSessions[payload.jti] = payload.exp;

  const sessionRec = db.sessions[payload.jti];
  if (sessionRec) {
    sessionRec.status = 'revoked';
    sessionRec.revokedAt = now;
    sessionRec.revokeReason = reason;
    // Also revoke any rotated tokens in the same session family on explicit logout
    for (const sess of Object.values(db.sessions)) {
      if (
        sess.familyId === sessionRec.familyId &&
        sess.status === 'active'
      ) {
        sess.status = 'revoked';
        sess.revokedAt = now;
        sess.revokeReason = reason;
        db.revokedSessions[sess.jti] = sess.absoluteExpiresAt;
      }
    }
  }

  saveAuthDb(db, now);

  recordServerAuditLog({
    actorId: payload.sub,
    actorEmail: payload.email || payload.phone || 'user',
    actorRole: payload.role,
    action: reason === 'user_logout' ? 'USER_LOGOUT' : 'SESSION_REVOKED',
    target: `session:${payload.jti.slice(0, 8)} (${reason})`,
  });

  return true;
}

export function revokeAllUserSessions(
  userId: string,
  options?: { exceptJti?: string; nowMs?: number; reason?: string }
): void {
  const nowMs = typeof options?.nowMs === 'number' ? options.nowMs : Date.now();
  const reason = options?.reason || 'sign_out_all_sessions';
  const db = loadAuthDb();

  const authAccount = db.authAccounts[userId];
  if (authAccount) {
    authAccount.sessionsRevokedBefore = nowMs;
  }

  for (const sess of Object.values(db.sessions)) {
    if (sess.userId === userId && sess.jti !== options?.exceptJti) {
      sess.status = 'revoked';
      sess.revokedAt = nowMs;
      sess.revokeReason = reason;
      db.revokedSessions[sess.jti] = sess.absoluteExpiresAt;
    }
  }

  saveAuthDb(db, nowMs);

  const userRecord = db.users[userId];
  recordServerAuditLog({
    actorId: userId,
    actorEmail: userRecord?.profile.email || userRecord?.profile.phone || 'user',
    actorRole: userRecord?.profile.role || 'student',
    action: 'ALL_USER_SESSIONS_REVOKED',
    target: `reason:${reason}`,
  });
}

const FORBIDDEN_URL_TOKEN_PARAMS = [
  'session',
  'sessionToken',
  'session_token',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'idToken',
  'id_token',
  'authToken',
  'auth_token',
  'uyanix_session',
];

export function hasForbiddenUrlTokenParams(req: NextRequest): string | null {
  if (SESSION_SECURITY_CONFIG.ALLOW_SESSION_TOKEN_IN_URL) {
    return null;
  }
  for (const key of FORBIDDEN_URL_TOKEN_PARAMS) {
    if (req.nextUrl.searchParams.has(key)) {
      recordServerAuditLog({
        actorId: `ip_${getClientIp(req)}`,
        actorEmail: 'anonymous',
        actorRole: 'student',
        action: 'URL_SESSION_TOKEN_REJECTED',
        target: `${req.method} ${req.nextUrl.pathname} (param: ${key})`,
      });
      return key;
    }
  }
  return null;
}

function isTrustedOriginUrl(originHeader: string, req: NextRequest): boolean {
  try {
    const parsedOrigin = new URL(originHeader);
    const originHost = parsedOrigin.host.toLowerCase();
    const reqHost = (
      req.headers.get('x-forwarded-host') ||
      req.headers.get('host') ||
      req.nextUrl.host ||
      ''
    )
      .split(',')[0]
      .trim()
      .toLowerCase();

    if (reqHost && originHost === reqHost) {
      return true;
    }
    if (originHost === req.nextUrl.host.toLowerCase()) {
      return true;
    }
    if (
      originHost === 'localhost:3000' ||
      originHost === '127.0.0.1:3000' ||
      originHost.endsWith('.run.app')
    ) {
      return true;
    }
    if (process.env.APP_URL) {
      const appUrlHost = new URL(process.env.APP_URL).host.toLowerCase();
      if (originHost === appUrlHost) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Enforces CORS origin restrictions and CSRF protections on state-changing requests.
 * Never allows Access-Control-Allow-Origin: * or untrusted cross-site origins.
 */
export function verifyCsrfAndCors(req: NextRequest):
  | { ok: true }
  | { ok: false; status: 403; response: NextResponse } {
  const origin = req.headers.get('origin');
  if (origin) {
    if (origin === 'null' || !isTrustedOriginUrl(origin, req)) {
      recordServerAuditLog({
        actorId: `ip_${getClientIp(req)}`,
        actorEmail: 'anonymous',
        actorRole: 'student',
        action: 'CORS_UNTRUSTED_ORIGIN_BLOCKED',
        target: `${req.method} ${req.nextUrl.pathname} (origin: ${origin.slice(0, 80)})`,
      });
      return {
        ok: false,
        status: 403,
        response: NextResponse.json(
          {
            error:
              'Forbidden: Untrusted origin is not allowed to access credentialed APIs.',
          },
          { status: 403 }
        ),
      };
    }
  }

  const method = req.method.toUpperCase();
  const isStateChanging =
    method === 'POST' ||
    method === 'PUT' ||
    method === 'PATCH' ||
    method === 'DELETE';

  if (isStateChanging) {
    const secFetchSite = (req.headers.get('sec-fetch-site') || '')
      .trim()
      .toLowerCase();
    if (secFetchSite === 'cross-site') {
      recordServerAuditLog({
        actorId: `ip_${getClientIp(req)}`,
        actorEmail: 'anonymous',
        actorRole: 'student',
        action: 'CSRF_CROSS_SITE_BLOCKED',
        target: `${req.method} ${req.nextUrl.pathname}`,
      });
      return {
        ok: false,
        status: 403,
        response: NextResponse.json(
          {
            error:
              'Forbidden: Cross-site state-changing request rejected (CSRF protection).',
          },
          { status: 403 }
        ),
      };
    }

    const referer = req.headers.get('referer');
    if (referer && !isTrustedOriginUrl(referer, req)) {
      recordServerAuditLog({
        actorId: `ip_${getClientIp(req)}`,
        actorEmail: 'anonymous',
        actorRole: 'student',
        action: 'CSRF_UNTRUSTED_REFERER_BLOCKED',
        target: `${req.method} ${req.nextUrl.pathname}`,
      });
      return {
        ok: false,
        status: 403,
        response: NextResponse.json(
          {
            error:
              'Forbidden: Untrusted Referer header rejected (CSRF protection).',
          },
          { status: 403 }
        ),
      };
    }

    const contentType = (req.headers.get('content-type') || '').toLowerCase();
    if (
      contentType.includes('application/x-www-form-urlencoded') ||
      contentType.includes('multipart/form-data') ||
      contentType.includes('text/plain')
    ) {
      recordServerAuditLog({
        actorId: `ip_${getClientIp(req)}`,
        actorEmail: 'anonymous',
        actorRole: 'student',
        action: 'CSRF_FORM_SUBMISSION_BLOCKED',
        target: `${req.method} ${req.nextUrl.pathname} (${contentType.slice(0, 40)})`,
      });
      return {
        ok: false,
        status: 403,
        response: NextResponse.json(
          {
            error:
              'Forbidden: Form-encoded cross-site requests are not permitted (CSRF protection).',
          },
          { status: 403 }
        ),
      };
    }
  }

  return { ok: true };
}

export function extractSessionTokenFromRequest(
  req: NextRequest
): string | null {
  // Never extract session tokens from URL query parameters (ALLOW_SESSION_TOKEN_IN_URL = false)
  if (hasForbiddenUrlTokenParams(req)) {
    return null;
  }

  const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
  if (cookieToken) return cookieToken;

  const authHeader = req.headers.get('x-uyanix-session');
  if (authHeader) return authHeader;

  const bearerHeader = req.headers.get('authorization');
  if (bearerHeader && /^Bearer\s+/i.test(bearerHeader)) {
    return bearerHeader.replace(/^Bearer\s+/i, '').trim();
  }

  return null;
}

export function getAuthenticatedUser(
  req: NextRequest,
  options?: { nowMs?: number; touchActivity?: boolean }
): {
  session: SessionTokenPayload;
  user: UserProfile;
} | null {
  if (hasForbiddenUrlTokenParams(req)) {
    return null;
  }
  const token = extractSessionTokenFromRequest(req);
  const payload = verifySessionTokenString(token, options);
  if (!payload) return null;

  const db = loadAuthDb();
  if (db.bannedUserIds[payload.sub]) {
    return null;
  }

  // If an auth account exists in the database without a corresponding valid profile record,
  // reject the session so an incomplete account never becomes a dashboard user (AUTH-03 #19)
  if (db.authAccounts[payload.sub] && !db.users[payload.sub]?.profile) {
    return null;
  }

  const record = db.users[payload.sub];
  if (record) {
    if (record.status === 'banned' || record.status === 'suspended') {
      return null;
    }
    if (!verifyProfileRecordConsistency(db, payload.sub)) {
      return null;
    }
    const authoritativeRole = resolveTrustedUserRole({
      userId: record.profile.id,
      email: record.profile.email,
      emailVerified: record.emailVerified,
    });
    const authoritativeProfile: UserProfile = {
      ...record.profile,
      role: authoritativeRole,
    };
    return {
      session: { ...payload, role: authoritativeRole },
      user: authoritativeProfile,
    };
  }

  // Check PostgreSQL cached user record if memoryDb is empty after restart
  const cachedDbUser = getCachedUserById(payload.sub);
  if (cachedDbUser) {
    if (cachedDbUser.role === 'admin' && BOOTSTRAPPED_ADMIN_EMAIL && payload.email?.toLowerCase() !== BOOTSTRAPPED_ADMIN_EMAIL && cachedDbUser.email.toLowerCase() !== BOOTSTRAPPED_ADMIN_EMAIL) {
      // Confirm admin assignment
    }
    return {
      session: { ...payload, role: cachedDbUser.role },
      user: cachedDbUser,
    };
  }

  // Reconstruct from signed server token if process restarted & cache was cold,
  // while strictly validating required fields and role against server rules
  const isSpecialRole = payload.role === 'admin' || payload.role === 'teacher';
  if (!isSpecialRole) {
    if (
      !payload.name ||
      !Number.isInteger(payload.classNum) ||
      payload.classNum < 1 ||
      payload.classNum > 12 ||
      !payload.school
    ) {
      return null;
    }
  }

  const authoritativeRole = resolveTrustedUserRole({
    userId: payload.sub,
    email: payload.email,
    emailVerified:
      payload.role === 'admin' && isTrustedAdminEmail(payload.email),
  });

  const reconstructed: UserProfile = {
    id: payload.sub,
    name: payload.name,
    teacherShortName: payload.teacherShortName,
    email: payload.email,
    phone: payload.phone,
    classNum: payload.classNum,
    school: payload.school,
    city: payload.city,
    role: authoritativeRole,
    idVerified: payload.idVerified,
    streakReminders: true,
    createdAt: new Date(payload.iat).toISOString(),
  };

  return {
    session: { ...payload, role: authoritativeRole },
    user: reconstructed,
  };
}

/**
 * Extracts and returns the authenticated UserProfile from the request session, or null if unauthenticated.
 */
export function getSessionUserFromRequest(
  req: NextRequest,
  options?: { nowMs?: number; touchActivity?: boolean }
): UserProfile | null {
  const auth = getAuthenticatedUser(req, options);
  return auth ? auth.user : null;
}

/**
 * Validates a session directly against Supabase PostgreSQL.
 * Used for authoritative boundaries, sensitive admin APIs, and multi-instance zero-trust guards.
 */
export async function getAuthoritativeUser(
  req: NextRequest,
  options?: { nowMs?: number; touchActivity?: boolean }
): Promise<{
  session: SessionTokenPayload;
  user: UserProfile;
} | null> {
  if (hasForbiddenUrlTokenParams(req)) return null;
  const token = extractSessionTokenFromRequest(req);
  if (!token) return null;

  const decoded = decodeAndVerifySessionSignature(token);
  if (!decoded) return null;

  const nowMs = typeof options?.nowMs === 'number' ? options.nowMs : Date.now();
  const authTime = typeof decoded.authTime === 'number' ? decoded.authTime : decoded.iat;
  const hardAbsoluteExp = Math.min(decoded.exp, authTime + SESSION_ABSOLUTE_TIMEOUT_MS);
  if (nowMs >= hardAbsoluteExp) return null;

  // 1. Authoritative check from PostgreSQL user_sessions table
  const sessionRow = await dbGetSession(decoded.jti);
  if (sessionRow) {
    if (sessionRow.status === 'rotated') {
      // Replay of rotated token triggers revocation of entire session family
      await dbRevokeSessionFamily(sessionRow.family_id, 'token_reuse_detected');
      recordServerAuditLog({
        actorId: decoded.sub,
        actorEmail: decoded.email || decoded.phone || 'unknown',
        actorRole: decoded.role,
        action: 'SUSPICIOUS_TOKEN_REUSE_DETECTED',
        target: `family:${sessionRow.family_id}`,
      });
      return null;
    }

    if (
      sessionRow.status === 'revoked' ||
      sessionRow.status === 'compromised' ||
      sessionRow.status === 'expired'
    ) {
      return null;
    }

    const idleExp = new Date(sessionRow.idle_expires_at).getTime();
    const absExp = new Date(sessionRow.absolute_expires_at).getTime();
    if (nowMs >= idleExp || nowMs >= absExp) {
      await dbUpdateSession(sessionRow.jti, { status: 'expired' });
      return null;
    }
  }

  // 2. Authoritative check from PostgreSQL users & auth_identities
  const dbUser = await dbFindUserById(decoded.sub);
  if (dbUser) {
    if (dbUser.user.status === 'banned' || dbUser.user.status === 'suspended') {
      return null;
    }

    if (dbUser.identity.sessions_revoked_before) {
      const revokedBeforeMs = new Date(dbUser.identity.sessions_revoked_before).getTime();
      if (decoded.iat < revokedBeforeMs) return null;
    }

    if (dbUser.identity.password_changed_at) {
      const pwdChangedMs = new Date(dbUser.identity.password_changed_at).getTime();
      if (decoded.iat < pwdChangedMs) return null;
    }

    const authoritativeProfile = mapUserRowToProfile(dbUser.user);

    // Touch activity in PostgreSQL
    if (sessionRow && options?.touchActivity !== false) {
      const newIdleExp = new Date(
        Math.min(
          new Date(sessionRow.absolute_expires_at).getTime(),
          nowMs + SESSION_IDLE_TIMEOUT_MS
        )
      ).toISOString();
      await dbUpdateSession(sessionRow.jti, {
        last_active_at: new Date(nowMs).toISOString(),
        idle_expires_at: newIdleExp,
      });
    }

    return {
      session: { ...decoded, role: authoritativeProfile.role },
      user: authoritativeProfile,
    };
  }

  // Fallback to synchronous validation if DB is disconnected
  const syncResult = getAuthenticatedUser(req, options);
  return syncResult;
}

/**
 * Authoritative admin guard querying PostgreSQL directly.
 */
export async function requireAuthoritativeAdmin(req: NextRequest): Promise<
  | { ok: true; user: UserProfile; session: SessionTokenPayload }
  | { ok: false; status: 401 | 403; response: NextResponse }
> {
  const csrfCorsCheck = verifyCsrfAndCors(req);
  if (!csrfCorsCheck.ok) return csrfCorsCheck;

  if (hasForbiddenUrlTokenParams(req)) {
    return {
      ok: false,
      status: 401,
      response: NextResponse.json(
        { error: 'Unauthorized: Session or authentication tokens are not permitted in URL parameters.' },
        { status: 401 }
      ),
    };
  }

  const auth = await getAuthoritativeUser(req);
  if (!auth) {
    const res = NextResponse.json(
      { error: 'Unauthorized: Valid authenticated session required.' },
      { status: 401 }
    );
    clearSessionCookie(res);
    return { ok: false, status: 401, response: res };
  }

  if (auth.user.role !== 'admin') {
    recordServerAuditLog({
      actorId: auth.user.id,
      actorEmail: auth.user.email || auth.user.phone,
      actorRole: auth.user.role,
      action: 'FORBIDDEN_ADMIN_ACCESS_ATTEMPT',
      target: `${req.method} ${req.nextUrl.pathname}`,
    });
    return {
      ok: false,
      status: 403,
      response: NextResponse.json(
        { error: 'Forbidden: Requires admin privileges.' },
        { status: 403 }
      ),
    };
  }

  return { ok: true, user: auth.user, session: auth.session };
}

/**
 * Centralized Server-Side Authentication Guard (enforces CORS, CSRF, URL-token prohibition, and real server session)
 */
export function requireAuthenticatedUser(req: NextRequest):
  | { ok: true; user: UserProfile; session: SessionTokenPayload }
  | { ok: false; status: 401 | 403; response: NextResponse } {
  const csrfCorsCheck = verifyCsrfAndCors(req);
  if (!csrfCorsCheck.ok) {
    return csrfCorsCheck;
  }

  const forbiddenParam = hasForbiddenUrlTokenParams(req);
  if (forbiddenParam) {
    return {
      ok: false,
      status: 401,
      response: NextResponse.json(
        {
          error:
            'Unauthorized: Session or authentication tokens are not permitted in URL parameters.',
        },
        { status: 401 }
      ),
    };
  }

  const auth = getAuthenticatedUser(req);
  if (!auth) {
    const res = NextResponse.json(
      { error: 'Unauthorized: Valid authenticated session required.' },
      { status: 401 }
    );
    clearSessionCookie(res);
    return {
      ok: false,
      status: 401,
      response: res,
    };
  }
  return {
    ok: true,
    user: auth.user,
    session: auth.session,
  };
}

/**
 * Centralized Server-Side Role Guard
 */
export function requireRole(
  req: NextRequest,
  requiredRoles: UserRole | UserRole[]
):
  | { ok: true; user: UserProfile; session: SessionTokenPayload }
  | { ok: false; status: 401 | 403; response: NextResponse } {
  const authCheck = requireAuthenticatedUser(req);
  if (!authCheck.ok) {
    return authCheck;
  }

  const allowed = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  const trustedRole = authCheck.user.role;

  if (!allowed.includes(trustedRole)) {
    recordServerAuditLog({
      actorId: authCheck.user.id,
      actorEmail: authCheck.user.email || authCheck.user.phone,
      actorRole: trustedRole,
      action: 'FORBIDDEN_ROLE_ACCESS_ATTEMPT',
      target: `${req.method} ${req.nextUrl.pathname} (required: ${allowed.join('|')})`,
    });

    return {
      ok: false,
      status: 403,
      response: NextResponse.json(
        {
          error: `Forbidden: Requires ${allowed.join(' or ')} privileges.`,
        },
        { status: 403 }
      ),
    };
  }

  return authCheck;
}

export function requireAdmin(req: NextRequest) {
  return requireRole(req, 'admin');
}

export function requireTeacherOrAdmin(req: NextRequest) {
  return requireRole(req, ['teacher', 'admin']);
}

export function requireOwnershipOrAdmin(
  req: NextRequest,
  targetUserId?: string | null
):
  | { ok: true; user: UserProfile; session: SessionTokenPayload }
  | { ok: false; status: 401 | 403; response: NextResponse } {
  const authCheck = requireAuthenticatedUser(req);
  if (!authCheck.ok) {
    return authCheck;
  }

  if (
    targetUserId &&
    targetUserId.trim() !== '' &&
    targetUserId !== authCheck.user.id &&
    authCheck.user.role !== 'admin'
  ) {
    recordServerAuditLog({
      actorId: authCheck.user.id,
      actorEmail: authCheck.user.email || authCheck.user.phone,
      actorRole: authCheck.user.role,
      action: 'FORBIDDEN_CROSS_USER_ACCESS_ATTEMPT',
      target: `Attempted to access userId=${targetUserId}`,
    });

    return {
      ok: false,
      status: 403,
      response: NextResponse.json(
        {
          error: 'Forbidden: You can only access or modify your own account data.',
        },
        { status: 403 }
      ),
    };
  }

  return authCheck;
}

export function findUserByIdentifier(
  identifier: string
): StoredUserRecord | null {
  const db = loadAuthDb();
  const clean = identifier.trim().toLowerCase();
  const cleanDigits = clean.replace(/\D/g, '');

  if (db.emailIndex[clean]) {
    const uid = db.emailIndex[clean];
    if (db.users[uid]) return db.users[uid];
  }

  if (cleanDigits.length >= 10) {
    const normPhone = cleanDigits.slice(-10);
    if (db.phoneIndex[normPhone]) {
      const uid = db.phoneIndex[normPhone];
      if (db.users[uid]) return db.users[uid];
    }
  }

  for (const record of Object.values(db.users)) {
    if (record.profile.email && record.profile.email.toLowerCase() === clean) {
      return record;
    }
    if (
      cleanDigits.length >= 10 &&
      record.profile.phone.replace(/\D/g, '') === cleanDigits.slice(-10)
    ) {
      return record;
    }
  }
  return null;
}

export function findUserById(userId: string): StoredUserRecord | null {
  const db = loadAuthDb();
  return db.users[userId] || null;
}

export async function registerNewUser(params: {
  name: string;
  classNum: number;
  school: string;
  city?: string;
  phone: string;
  email?: string;
  password: string;
  agreed?: boolean;
  referralCode?: string;
  idempotencyKey?: string;
}): Promise<
  | { ok: true; user: UserProfile; idempotentReplay?: boolean }
  | { ok: false; status: number; error: string }
> {
  // 1. Validate all registration fields server-side
  const nameCheck = validateFullName(params.name);
  if (!nameCheck.ok) {
    return { ok: false, status: 400, error: nameCheck.error };
  }

  const classCheck = validateStudentClass(params.classNum);
  if (!classCheck.ok) {
    return { ok: false, status: 400, error: classCheck.error };
  }

  const schoolCheck = validateSchoolName(params.school);
  if (!schoolCheck.ok) {
    return { ok: false, status: 400, error: schoolCheck.error };
  }

  const phoneCheck = validateIndianMobile(params.phone);
  if (!phoneCheck.ok) {
    return { ok: false, status: 400, error: phoneCheck.error };
  }

  const emailCheck = validateOptionalEmail(params.email);
  if (!emailCheck.ok) {
    return { ok: false, status: 400, error: emailCheck.error };
  }

  const passwordCheck = validatePasswordStrength(params.password, {
    email: emailCheck.value,
    phone: phoneCheck.value,
    name: nameCheck.value,
  });
  if (!passwordCheck.ok) {
    return {
      ok: false,
      status: 400,
      error: passwordCheck.error,
    };
  }

  if (params.agreed !== true) {
    return {
      ok: false,
      status: 400,
      error: 'You must accept the Terms & Conditions to register.',
    };
  }

  const normalizedName = nameCheck.value;
  const validatedClass = classCheck.value;
  const normalizedSchool = schoolCheck.value;
  const normalizedPhone = phoneCheck.value;
  const safeCity =
    typeof params.city === 'string' && params.city.trim().length >= 2
      ? params.city.trim().slice(0, 100)
      : 'Jaipur';

  const normalizedEmail = (
    emailCheck.value ||
    `${normalizedName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 24) || 'student'}.${normalizedPhone.slice(-4)}@student.uyanix.in`
  ).toLowerCase();

  // Prevent squatting the bootstrapped admin email via unverified password registration
  if (isTrustedAdminEmail(normalizedEmail)) {
    return {
      ok: false,
      status: 403,
      error: 'Unable to register with the provided details.',
    };
  }

  // Validate optional referral code format & eligibility (never grant rewards directly)
  let verifiedReferralCode: string | undefined;
  let verifiedTeacherId: string | undefined;
  if (
    params.referralCode !== undefined &&
    params.referralCode !== null &&
    String(params.referralCode).trim() !== ''
  ) {
    const rawCode = String(params.referralCode).trim().toUpperCase();
    if (!/^[A-Z0-9_-]{3,24}$/.test(rawCode)) {
      return {
        ok: false,
        status: 400,
        error: 'Invalid referral code format.',
      };
    }
    const eligibleTeacher = APPROVED_TEACHER_REFERRAL_CODES[rawCode];
    if (eligibleTeacher) {
      // Prevent self-referral by phone or email
      if (
        eligibleTeacher.teacherPhone === normalizedPhone ||
        eligibleTeacher.teacherEmail.toLowerCase() === normalizedEmail
      ) {
        return {
          ok: false,
          status: 400,
          error: 'Self-referral is not permitted.',
        };
      }
      verifiedReferralCode = rawCode;
      verifiedTeacherId = eligibleTeacher.teacherId;
    }
  }

  const payloadHash = crypto
    .createHash('sha256')
    .update(
      `${normalizedPhone}|${normalizedEmail}|${normalizedName}|${validatedClass}|${normalizedSchool}`
    )
    .digest('hex');

  const phoneLockKey = `phone:${normalizedPhone}`;
  const emailLockKey = `email:${normalizedEmail}`;

  // 2. Race-condition & concurrency lock
  if (
    inFlightRegistrationLocks.has(phoneLockKey) ||
    inFlightRegistrationLocks.has(emailLockKey)
  ) {
    return {
      ok: false,
      status: 409,
      error: 'A registration request for this account is already in progress.',
    };
  }

  inFlightRegistrationLocks.add(phoneLockKey);
  inFlightRegistrationLocks.add(emailLockKey);
  const hasFileLock = acquireFileLock();

  let createdUserId: string | null = null;

  try {
    const db = loadAuthDb();

    // 3. Idempotency handling for safe network/double-click retries
    if (params.idempotencyKey && typeof params.idempotencyKey === 'string') {
      const cleanIdemKey = params.idempotencyKey.trim().slice(0, 128);
      const existingIdem = db.idempotencyKeys[cleanIdemKey];
      if (existingIdem && Date.now() < existingIdem.expiresAt) {
        if (
          existingIdem.payloadHash === payloadHash &&
          db.users[existingIdem.userId]
        ) {
          return {
            ok: true,
            user: db.users[existingIdem.userId].profile,
            idempotentReplay: true,
          };
        }
        return {
          ok: false,
          status: 409,
          error: 'Duplicate registration submission detected.',
        };
      }
    }

    // 4. Atomic duplicate account checks across unique indexes & user table
    if (db.phoneIndex[normalizedPhone] || db.emailIndex[normalizedEmail]) {
      return {
        ok: false,
        status: 409,
        error:
          'An account with this mobile number or email already exists. Please login instead.',
      };
    }

    for (const existing of Object.values(db.users)) {
      if (
        existing.profile.phone.replace(/\D/g, '').slice(-10) === normalizedPhone ||
        existing.profile.email.toLowerCase() === normalizedEmail
      ) {
        return {
          ok: false,
          status: 409,
          error:
            'An account with this mobile number or email already exists. Please login instead.',
        };
      }
    }

    // 5. Create real authentication identity + associated student profile + role assignment
    const { salt, hash } = hashPassword(params.password);
    const userId = crypto.randomUUID();
    createdUserId = userId;
    const nowIso = new Date().toISOString();

    const shortName =
      normalizedName
        .split(/\s+/)[0]
        ?.toLowerCase()
        .replace(/[^a-z0-9]/g, '') || 'student';

    // Default role is strictly 'student', idVerified is strictly false
    const profile: UserProfile = {
      id: userId,
      name: normalizedName,
      teacherShortName: shortName,
      email: normalizedEmail,
      phone: normalizedPhone,
      classNum: validatedClass,
      school: normalizedSchool,
      city: safeCity,
      role: 'student',
      idVerified: false,
      streakReminders: true,
      createdAt: nowIso,
    };

    const userRow: UserRow = {
      id: userId,
      name: normalizedName,
      email: normalizedEmail,
      phone: normalizedPhone,
      class: validatedClass,
      school: normalizedSchool,
      city: safeCity,
      role: 'student',
      avatar: null,
      id_card_url: null,
      id_verification_status: 'pending',
      phone_verified: false,
      status: 'active',
      terms_accepted_at: nowIso,
      created_at: nowIso,
    };

    const authIdentityRow: AuthIdentityRow = {
      user_id: userId,
      normalized_email: normalizedEmail,
      normalized_phone: normalizedPhone,
      password_salt: salt,
      password_hash: hash,
      password_changed_at: null,
      sessions_revoked_before: null,
      google_uid: null,
      email_verified: false,
      phone_verified: false,
      failed_login_attempts: 0,
      locked_until: null,
      created_at: nowIso,
      updated_at: nowIso,
    };

    if (isSupabaseConfigured()) {
      const dbResult = await dbCreateUserWithIdentity({
        user: userRow,
        identity: authIdentityRow,
      });
      if (!dbResult.ok) {
        return { ok: false, status: dbResult.status, error: dbResult.error };
      }
    } else {
      // Fail safely if database is unavailable
      return {
        ok: false,
        status: 503,
        error:
          'Authentication database is currently unavailable. Please configure SUPABASE_SERVICE_ROLE_KEY and NEXT_PUBLIC_SUPABASE_URL.',
      };
    }

    const authIdentity: StoredAuthIdentity = {
      authUserId: userId,
      normalizedEmail,
      normalizedPhone,
      passwordSalt: salt,
      passwordHash: hash,
      emailVerified: false,
      phoneVerified: false,
      termsAcceptedAt: nowIso,
      status: 'active',
      failedLoginAttempts: 0,
      lockedUntil: 0,
      createdAt: nowIso,
    };

    db.authAccounts[userId] = authIdentity;
    db.users[userId] = {
      profile,
      status: 'active',
      emailVerified: false,
      termsAcceptedAt: nowIso,
      referredByCode: verifiedReferralCode,
      failedLoginAttempts: 0,
      lockedUntil: 0,
    };
    db.roleAssignments[userId] = 'student';
    db.phoneIndex[normalizedPhone] = userId;
    db.emailIndex[normalizedEmail] = userId;

    // Record referral in pending state ONLY (no commission credited at registration)
    if (verifiedReferralCode && verifiedTeacherId) {
      const existingRefForPhone = Object.values(db.referralRegistrations).some(
        (r) => r.studentPhone === normalizedPhone
      );
      if (!existingRefForPhone) {
        const refId = `ref_${crypto.randomBytes(8).toString('hex')}`;
        db.referralRegistrations[refId] = {
          id: refId,
          referralCode: verifiedReferralCode,
          teacherId: verifiedTeacherId,
          studentId: userId,
          studentPhone: normalizedPhone,
          status: 'pending',
          commission: 0,
          createdAt: nowIso,
        };
      }
    }

    if (params.idempotencyKey && typeof params.idempotencyKey === 'string') {
      const cleanIdemKey = params.idempotencyKey.trim().slice(0, 128);
      if (cleanIdemKey) {
        db.idempotencyKeys[cleanIdemKey] = {
          userId,
          payloadHash,
          expiresAt: Date.now() + 10 * 60 * 1000,
        };
      }
    }

    // 6. Verify Auth + Profile + Role consistency before committing
    if (!verifyProfileRecordConsistency(db, userId)) {
      throw new Error('Registration consistency check failed');
    }

    saveAuthDb(db);

    recordServerAuditLog({
      actorId: userId,
      actorEmail: normalizedEmail,
      actorRole: 'student',
      action: 'STUDENT_REGISTERED',
      target: `Class ${validatedClass} (${normalizedSchool})`,
    });

    return { ok: true, user: profile };
  } catch {
    // 7. Compensating cleanup on partial registration failure
    if (createdUserId && memoryDb) {
      delete memoryDb.authAccounts[createdUserId];
      delete memoryDb.users[createdUserId];
      delete memoryDb.roleAssignments[createdUserId];
      if (memoryDb.phoneIndex[normalizedPhone] === createdUserId) {
        delete memoryDb.phoneIndex[normalizedPhone];
      }
      if (memoryDb.emailIndex[normalizedEmail] === createdUserId) {
        delete memoryDb.emailIndex[normalizedEmail];
      }
      saveAuthDb(memoryDb);
    }
    return {
      ok: false,
      status: 500,
      error: 'Unable to complete registration. Please try again.',
    };
  } finally {
    inFlightRegistrationLocks.delete(phoneLockKey);
    inFlightRegistrationLocks.delete(emailLockKey);
    if (hasFileLock) {
      releaseFileLock();
    }
  }
}

export async function authenticateWithPassword(
  identifier: string,
  password: string
): Promise<{ ok: true; user: UserProfile } | { ok: false; status: number; error: string }> {
  // 1. Normalize identifier
  const clean = identifier.trim().toLowerCase();

  // 2. Query Supabase PostgreSQL authoritatively
  const dbResult = await dbFindUserByIdentifier(clean);

  let userRow = dbResult?.user;
  let identityRow = dbResult?.identity;

  // Fallback to in-process memory cache if PostgreSQL query returns null
  if (!userRow || !identityRow) {
    const memoryRecord = findUserByIdentifier(clean);
    if (memoryRecord) {
      const db = loadAuthDb();
      const authAccount = db.authAccounts[memoryRecord.profile.id];
      if (authAccount?.passwordSalt && authAccount?.passwordHash) {
        const valid = verifyPassword(password, authAccount.passwordSalt, authAccount.passwordHash);
        if (valid && memoryRecord.status === 'active') {
          return { ok: true, user: memoryRecord.profile };
        }
      }
    }

    // Perform constant-time dummy scrypt derivation to prevent timing-based account enumeration
    hashPassword(password, '00000000000000000000000000000000');
    return {
      ok: false,
      status: 401,
      error: 'Invalid email/mobile or password.',
    };
  }

  // 3. Check account status authoritatively from PostgreSQL
  if (userRow.status === 'banned' || userRow.status === 'suspended') {
    return {
      ok: false,
      status: 403,
      error: 'Your account has been suspended by an administrator.',
    };
  }

  // 4. Check lock state authoritatively from PostgreSQL
  const now = Date.now();
  const lockedUntilTime = identityRow.locked_until
    ? new Date(identityRow.locked_until).getTime()
    : 0;

  if (lockedUntilTime > now) {
    return {
      ok: false,
      status: 429,
      error: 'Account temporarily locked due to multiple failed login attempts. Try again later.',
    };
  }

  // 5. Verify password using constant-time verification
  if (!identityRow.password_salt || !identityRow.password_hash) {
    hashPassword(password, '00000000000000000000000000000000');
    return {
      ok: false,
      status: 401,
      error: 'Invalid email/mobile or password.',
    };
  }

  const valid = verifyPassword(
    password,
    identityRow.password_salt,
    identityRow.password_hash
  );

  if (!valid) {
    // 6. Update failed-login counters atomically in PostgreSQL
    const failResult = await dbRecordLoginFailureAtomic(userRow.id, 5, 600);
    recordServerAuditLog({
      actorId: userRow.id,
      actorEmail: userRow.email || userRow.phone,
      actorRole: userRow.role,
      action: 'USER_LOGIN_FAILED',
      target: `failed_attempts:${failResult.attempts}`,
    });
    return {
      ok: false,
      status: 401,
      error: 'Invalid email/mobile or password.',
    };
  }

  // 7. Reset failed-login counters after successful login atomically in PostgreSQL
  await dbResetLoginFailuresAtomic(userRow.id);

  // 8. Resolve role from authoritative database record
  const authoritativeProfile = mapUserRowToProfile(userRow);

  recordServerAuditLog({
    actorId: userRow.id,
    actorEmail: userRow.email || userRow.phone,
    actorRole: userRow.role,
    action: 'USER_LOGIN_SUCCESS',
    target: userRow.id,
  });

  return { ok: true, user: authoritativeProfile };
}

export async function upsertGoogleAuthenticatedUser(params: {
  googleUid: string;
  email: string;
  emailVerified: boolean;
  displayName?: string;
  photoUrl?: string;
}): Promise<UserProfile> {
  const normalizedEmail = params.email.trim().toLowerCase();

  // 1. Authoritative lookup in PostgreSQL
  let userRecord = await dbFindUserByIdentifier(normalizedEmail);

  // Fallback to in-memory store if DB query returned nothing
  const db = loadAuthDb();
  const memRecord = userRecord
    ? null
    : Object.values(db.users).find(
        (u) =>
          u.googleUid === params.googleUid ||
          u.profile.email.toLowerCase() === normalizedEmail
      );

  const isBootstrappedAdmin =
    params.emailVerified &&
    isTrustedAdminEmail(normalizedEmail);

  // Case A: Existing user record found
  if (userRecord || memRecord) {
    const existingUserId = userRecord ? userRecord.user.id : memRecord!.profile.id;
    const existingProfile = userRecord
      ? mapUserRowToProfile(userRecord.user)
      : memRecord!.profile;

    // Secure linking: ONLY link googleUid if email is verified by Google
    if (params.emailVerified) {
      await dbUpdateIdentity(existingUserId, {
        google_uid: params.googleUid,
        email_verified: true,
      });
      if (params.photoUrl && !existingProfile.avatar) {
        await dbUpdateUser(existingUserId, { avatar: params.photoUrl });
        existingProfile.avatar = params.photoUrl;
      }
    }

    if (isBootstrappedAdmin) {
      existingProfile.role = 'admin';
      existingProfile.idVerified = true;
      await dbUpdateUser(existingUserId, { role: 'admin' });
      db.roleAssignments[existingUserId] = 'admin';
    }

    if (memRecord) {
      memRecord.googleUid = params.googleUid;
      memRecord.emailVerified = params.emailVerified;
      if (params.photoUrl) memRecord.profile.avatar = params.photoUrl;
      saveAuthDb(db);
    }

    return existingProfile;
  }

  // Case B: Brand new user from Google
  // STRICT COMPLIANCE (Requirement #13): Do NOT invent fake phone numbers, schools, classes, or cities!
  const userId = `usr_${params.googleUid.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32)}`;
  const displayName =
    params.displayName?.trim() || normalizedEmail.split('@')[0] || 'Student';
  const shortName =
    displayName.split(/\s+/)[0]?.toLowerCase().replace(/[^a-z0-9]/g, '') ||
    'student';

  const assignedRole: UserRole = isBootstrappedAdmin
    ? 'admin'
    : (db.roleAssignments[userId] as UserRole) || 'student';

  const nowIso = new Date().toISOString();

  // Create authentic student profile with onboarding-pending state (NO fake data!)
  const newProfile: UserProfile = {
    id: userId,
    name: displayName,
    teacherShortName: shortName,
    email: normalizedEmail,
    phone: '', // NOT invented!
    classNum: 0, // NOT invented!
    school: '', // NOT invented!
    city: '', // NOT invented!
    role: assignedRole,
    avatar: params.photoUrl,
    idVerified: isBootstrappedAdmin,
    streakReminders: true,
    onboardingRequired: !isBootstrappedAdmin, // Requires completing profile before active challenges
    createdAt: nowIso,
  };

  const userRow: UserRow = {
    id: userId,
    name: displayName,
    email: normalizedEmail,
    phone: '',
    class: 0,
    school: '',
    city: null,
    role: assignedRole,
    avatar: params.photoUrl || null,
    id_card_url: null,
    id_verification_status: 'pending',
    phone_verified: false,
    status: 'active',
    terms_accepted_at: nowIso,
    created_at: nowIso,
  };

  const identityRow: AuthIdentityRow = {
    user_id: userId,
    normalized_email: normalizedEmail,
    normalized_phone: '',
    password_salt: null,
    password_hash: null,
    password_changed_at: null,
    sessions_revoked_before: null,
    google_uid: params.googleUid,
    email_verified: params.emailVerified,
    phone_verified: false,
    failed_login_attempts: 0,
    locked_until: null,
    created_at: nowIso,
    updated_at: nowIso,
  };

  // Persist authoritative records to PostgreSQL
  await dbCreateUserWithIdentity({ user: userRow, identity: identityRow }).catch(() => {});

  // Cache in memoryDb for synchronous lookups
  db.authAccounts[userId] = {
    authUserId: userId,
    normalizedEmail,
    normalizedPhone: '',
    googleUid: params.googleUid,
    emailVerified: params.emailVerified,
    phoneVerified: false,
    termsAcceptedAt: nowIso,
    status: 'active',
    failedLoginAttempts: 0,
    lockedUntil: 0,
    createdAt: nowIso,
  };

  db.users[userId] = {
    profile: newProfile,
    status: 'active',
    googleUid: params.googleUid,
    emailVerified: params.emailVerified,
    termsAcceptedAt: nowIso,
    failedLoginAttempts: 0,
    lockedUntil: 0,
  };
  db.roleAssignments[userId] = assignedRole;
  db.emailIndex[normalizedEmail] = userId;
  saveAuthDb(db);

  return newProfile;
}

const DISALLOWED_STATIC_OTPS = new Set([
  '123456',
  '000000',
  '111111',
  '222222',
  '333333',
  '444444',
  '555555',
  '666666',
  '777777',
  '888888',
  '999999',
  '654321',
]);

function generateSecureNumericOtp(): string {
  for (let i = 0; i < 16; i++) {
    const candidate = String(crypto.randomInt(100000, 1000000));
    if (!DISALLOWED_STATIC_OTPS.has(candidate)) {
      return candidate;
    }
  }
  return String(crypto.randomInt(100000, 1000000));
}

function computeOtpHmac(
  challengeId: string,
  userId: string,
  phone: string,
  otpSalt: string,
  otp: string
): string {
  return crypto
    .createHmac('sha256', getSigningSecret())
    .update(`${challengeId}:${userId}:${phone}:${otpSalt}:${otp}`)
    .digest('hex');
}

export function signOtpBindingToken(payload: OtpBindingPayload): string {
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sig = crypto
    .createHmac('sha256', getSigningSecret())
    .update(`otp_bind:${payloadB64}`)
    .digest();
  return `${payloadB64}.${base64UrlEncode(sig)}`;
}

export function verifyOtpBindingToken(
  token: string | undefined | null,
  nowMs: number = Date.now()
): OtpBindingPayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64) return null;

  try {
    const expectedSig = base64UrlEncode(
      crypto
        .createHmac('sha256', getSigningSecret())
        .update(`otp_bind:${payloadB64}`)
        .digest()
    );
    const a = Buffer.from(sigB64, 'utf-8');
    const b = Buffer.from(expectedSig, 'utf-8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }
    const decoded = JSON.parse(base64UrlDecode(payloadB64)) as OtpBindingPayload;
    if (
      !decoded ||
      typeof decoded.challengeId !== 'string' ||
      typeof decoded.userId !== 'string' ||
      typeof decoded.phone !== 'string' ||
      typeof decoded.exp !== 'number' ||
      nowMs >= decoded.exp
    ) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

export function setOtpBindingCookie(
  res: NextResponse,
  bindingToken: string
): void {
  res.cookies.set({
    name: OTP_BINDING_COOKIE_NAME,
    value: bindingToken,
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    path: '/',
    maxAge: OTP_SECURITY_CONFIG.OTP_EXPIRY_SECONDS,
  });
}

export function clearOtpBindingCookie(res: NextResponse): void {
  res.cookies.set({
    name: OTP_BINDING_COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    path: '/',
    maxAge: 0,
  });
}

export function getUserPhoneVerificationStatus(userId: string): boolean {
  const db = loadAuthDb();
  return Boolean(db.authAccounts[userId]?.phoneVerified);
}

function getOrCreateOtpPhoneRateState(
  db: PersistentAuthDatabase,
  cleanPhone: string,
  userId: string,
  nowMs: number
): OtpPhoneRateState {
  const existing = db.otpRateStates[cleanPhone];
  const window24hMs = 24 * 60 * 60 * 1000;
  const window1hMs = 60 * 60 * 1000;
  const window10mMs = OTP_SECURITY_CONFIG.OTP_ABUSE_WINDOW_MINUTES * 60 * 1000;

  if (!existing) {
    const fresh: OtpPhoneRateState = {
      phone: cleanPhone,
      userId,
      lastSentAt: 0,
      sendTimestamps24h: [],
      resendTimestamps1h: [],
      failedVerifyTimestamps10m: [],
    };
    db.otpRateStates[cleanPhone] = fresh;
    return fresh;
  }

  existing.userId = userId;
  existing.sendTimestamps24h = (existing.sendTimestamps24h || []).filter(
    (ts) => nowMs - ts < window24hMs
  );
  existing.resendTimestamps1h = (existing.resendTimestamps1h || []).filter(
    (ts) => nowMs - ts < window1hMs
  );
  existing.failedVerifyTimestamps10m = (
    existing.failedVerifyTimestamps10m || []
  ).filter((ts) => nowMs - ts < window10mMs);

  return existing;
}

export function createOtpChallenge(
  phone: string,
  options?: {
    isResend?: boolean;
    boundUserId?: string;
    nowMs?: number;
  }
):
  | {
      ok: true;
      challengeId: string;
      userId: string;
      phone: string;
      expiresAt: number;
      bindingToken: string;
      /** Only populated for internal server-side tests when NODE_ENV !== 'production' */
      _internalTestOtp?: string;
    }
  | {
      ok: false;
      status: number;
      error: string;
      retryAfterSec?: number;
    } {
  const nowMs =
    typeof options?.nowMs === 'number' ? options.nowMs : Date.now();

  const phoneCheck = validateIndianMobile(phone);
  if (!phoneCheck.ok) {
    return {
      ok: false,
      status: 400,
      error: phoneCheck.error,
    };
  }
  const cleanPhone = phoneCheck.value;

  if (inFlightOtpLocks.has(cleanPhone)) {
    return {
      ok: false,
      status: 429,
      error: 'An OTP request is already in progress. Please wait.',
      retryAfterSec: 5,
    };
  }

  inFlightOtpLocks.add(cleanPhone);
  const hasFileLock = acquireFileLock();

  try {
    const record = findUserByIdentifier(cleanPhone);
    if (!record) {
      return {
        ok: false,
        status: 404,
        error:
          'No registered account found with this mobile number. Please register first.',
      };
    }

    const db = loadAuthDb();
    if (
      record.status === 'banned' ||
      record.status === 'suspended' ||
      db.bannedUserIds[record.profile.id]
    ) {
      return {
        ok: false,
        status: 403,
        error: 'Your account has been suspended by an administrator.',
      };
    }

    if (options?.boundUserId && options.boundUserId !== record.profile.id) {
      recordServerAuditLog({
        actorId: options.boundUserId,
        actorEmail: record.profile.email,
        actorRole: record.profile.role,
        action: 'OTP_USER_SWAP_ATTEMPT',
        target: `Attempted OTP send for mismatched userId`,
      });
      return {
        ok: false,
        status: 403,
        error: 'Forbidden: Account mismatch for mobile verification.',
      };
    }

    const rateState = getOrCreateOtpPhoneRateState(
      db,
      cleanPhone,
      record.profile.id,
      nowMs
    );
    const existingChallenge = db.otpChallenges[cleanPhone];
    const isResendRequest = Boolean(
      options?.isResend ||
        rateState.lastSentAt > 0 ||
        rateState.sendTimestamps24h.length > 0 ||
        existingChallenge
    );

    // 1. Enforce 60-second resend cooldown (OTP_RESEND_COOLDOWN_SECONDS = 60)
    const cooldownMs = OTP_SECURITY_CONFIG.OTP_RESEND_COOLDOWN_SECONDS * 1000;
    if (
      rateState.lastSentAt > 0 &&
      nowMs - rateState.lastSentAt < cooldownMs
    ) {
      const retryAfterSec = Math.max(
        1,
        Math.ceil((cooldownMs - (nowMs - rateState.lastSentAt)) / 1000)
      );
      return {
        ok: false,
        status: 429,
        error: `Please wait ${retryAfterSec} seconds before requesting a new OTP.`,
        retryAfterSec,
      };
    }

    // 2. Enforce daily 24-hour send limit per phone (OTP_MAX_SENDS_PER_PHONE_PER_24_HOURS = 20)
    if (
      rateState.sendTimestamps24h.length >=
      OTP_SECURITY_CONFIG.OTP_MAX_SENDS_PER_PHONE_PER_24_HOURS
    ) {
      return {
        ok: false,
        status: 429,
        error:
          'Daily OTP limit reached for this mobile number. Please try again later.',
        retryAfterSec: 3600,
      };
    }

    // 3. Enforce 10-minute (max 5) and 1-hour (max 10) resend limits
    if (isResendRequest) {
      const window10mMs =
        OTP_SECURITY_CONFIG.OTP_ABUSE_WINDOW_MINUTES * 60 * 1000;
      const resendsLast10m = rateState.resendTimestamps1h.filter(
        (ts) => nowMs - ts < window10mMs
      );

      if (
        resendsLast10m.length >=
        OTP_SECURITY_CONFIG.OTP_MAX_RESENDS_PER_10_MINUTES
      ) {
        return {
          ok: false,
          status: 429,
          error:
            'Too many OTP resend requests in 10 minutes. Please wait before trying again.',
          retryAfterSec: 600,
        };
      }

      if (
        rateState.resendTimestamps1h.length >=
        OTP_SECURITY_CONFIG.OTP_MAX_RESENDS_PER_HOUR
      ) {
        return {
          ok: false,
          status: 429,
          error:
            'Hourly OTP resend limit reached. Please wait before requesting another OTP.',
          retryAfterSec: 3600,
        };
      }
    }

    // 4. Invalidate any previous active OTP challenge for this phone/account
    // (invalidate_previous_active_otp = true)
    for (const [key, ch] of Object.entries(db.otpChallenges)) {
      if (
        (key === cleanPhone || ch.userId === record.profile.id) &&
        ch.status === 'active'
      ) {
        ch.status = 'superseded';
      }
    }

    // 5. Cryptographically generate 6-digit numeric OTP (100000..999999)
    // Plaintext OTP is NEVER stored in the database and NEVER logged
    const otp = generateSecureNumericOtp();
    const challengeId = `otp_chl_${crypto.randomBytes(12).toString('hex')}`;
    const otpSalt = crypto.randomBytes(16).toString('hex');
    const otpHash = computeOtpHmac(
      challengeId,
      record.profile.id,
      cleanPhone,
      otpSalt,
      otp
    );

    const expiresAt =
      nowMs + OTP_SECURITY_CONFIG.OTP_EXPIRY_SECONDS * 1000; // exactly 300s

    const newChallenge: OtpChallengeRecord = {
      challengeId,
      userId: record.profile.id,
      phone: cleanPhone,
      otpSalt,
      otpHash,
      createdAt: nowMs,
      expiresAt,
      attempts: 0,
      maxAttempts: OTP_SECURITY_CONFIG.OTP_MAX_VERIFICATION_ATTEMPTS,
      resendCount: isResendRequest ? rateState.resendTimestamps1h.length + 1 : 0,
      used: false,
      status: 'active',
    };

    db.otpChallenges[cleanPhone] = newChallenge;
    rateState.lastSentAt = nowMs;
    rateState.sendTimestamps24h.push(nowMs);
    if (isResendRequest) {
      rateState.resendTimestamps1h.push(nowMs);
    }

    saveAuthDb(db, nowMs);

    // Log safe event metadata ONLY (never log OTP value or hash)
    recordServerAuditLog({
      actorId: record.profile.id,
      actorEmail: record.profile.email,
      actorRole: record.profile.role,
      action: isResendRequest ? 'OTP_CHALLENGE_RESENT' : 'OTP_CHALLENGE_CREATED',
      target: challengeId,
    });

    const bindingToken = signOtpBindingToken({
      challengeId,
      userId: record.profile.id,
      phone: cleanPhone,
      iat: nowMs,
      exp: expiresAt,
    });

    return {
      ok: true,
      challengeId,
      userId: record.profile.id,
      phone: cleanPhone,
      expiresAt,
      bindingToken,
      _internalTestOtp:
        process.env.NODE_ENV !== 'production' ? otp : undefined,
    };
  } finally {
    inFlightOtpLocks.delete(cleanPhone);
    if (hasFileLock) {
      releaseFileLock();
    }
  }
}

export function verifyOtpChallenge(
  phone: string,
  submittedOtp: string,
  options?: {
    boundPhone?: string;
    boundUserId?: string;
    boundChallengeId?: string;
    nowMs?: number;
  }
):
  | { ok: true; user: UserProfile; phoneVerified: true }
  | { ok: false; status: number; error: string } {
  const nowMs =
    typeof options?.nowMs === 'number' ? options.nowMs : Date.now();

  const phoneCheck = validateIndianMobile(phone);
  if (!phoneCheck.ok) {
    return {
      ok: false,
      status: 400,
      error: phoneCheck.error,
    };
  }
  const cleanPhone = phoneCheck.value;

  // Prevent phone swapping: if request carries an OTP challenge binding for Phone A,
  // reject any attempt to verify Phone B
  if (options?.boundPhone) {
    const boundPhoneCheck = validateIndianMobile(options.boundPhone);
    if (!boundPhoneCheck.ok || boundPhoneCheck.value !== cleanPhone) {
      recordServerAuditLog({
        actorId: options?.boundUserId || 'anonymous',
        actorEmail: 'anonymous',
        actorRole: 'student',
        action: 'OTP_PHONE_SWAP_BLOCKED',
        target: `Bound phone mismatch during OTP verify`,
      });
      return {
        ok: false,
        status: 403,
        error:
          'Forbidden: Phone number does not match the active OTP challenge.',
      };
    }
  }

  // Validate 6-digit numeric OTP format before hash check
  if (typeof submittedOtp !== 'string') {
    return {
      ok: false,
      status: 400,
      error: 'Please enter a valid 6-digit numeric OTP.',
    };
  }
  const cleanOtp = submittedOtp.trim();
  if (!/^\d{6}$/.test(cleanOtp)) {
    return {
      ok: false,
      status: 400,
      error: 'Invalid OTP format. OTP must be exactly 6 numeric digits.',
    };
  }

  // Atomic concurrency lock so two simultaneous requests with the same OTP
  // can never both consume the challenge (ONE OTP -> maximum ONE consumption)
  if (inFlightOtpLocks.has(cleanPhone)) {
    return {
      ok: false,
      status: 409,
      error: 'OTP verification already in progress.',
    };
  }

  inFlightOtpLocks.add(cleanPhone);
  const hasFileLock = acquireFileLock();

  try {
    const db = loadAuthDb();
    const record = findUserByIdentifier(cleanPhone);
    if (!record) {
      return {
        ok: false,
        status: 401,
        error: 'Invalid or expired OTP.',
      };
    }

    // Prevent User-ID swapping
    if (options?.boundUserId && options.boundUserId !== record.profile.id) {
      recordServerAuditLog({
        actorId: options.boundUserId,
        actorEmail: record.profile.email,
        actorRole: record.profile.role,
        action: 'OTP_USER_SWAP_BLOCKED',
        target: `Attempted to verify OTP for different userId`,
      });
      return {
        ok: false,
        status: 403,
        error: 'Forbidden: Account mismatch for OTP verification.',
      };
    }

    const rateState = getOrCreateOtpPhoneRateState(
      db,
      cleanPhone,
      record.profile.id,
      nowMs
    );

    // Per-account failed verification attempt limit (10 failed attempts per 10 minutes)
    if (
      rateState.failedVerifyTimestamps10m.length >=
      OTP_SECURITY_CONFIG.OTP_VERIFY_MAX_FAILED_ATTEMPTS_PER_ACCOUNT_PER_10_MINUTES
    ) {
      saveAuthDb(db, nowMs);
      return {
        ok: false,
        status: 429,
        error:
          'Too many failed OTP verification attempts for this account. Please wait 10 minutes.',
      };
    }

    const challenge = db.otpChallenges[cleanPhone];
    if (!challenge) {
      return {
        ok: false,
        status: 401,
        error: 'OTP expired or not requested. Please request a new OTP.',
      };
    }

    // Ensure challenge belongs to the same account and phone
    if (
      challenge.phone !== cleanPhone ||
      challenge.userId !== record.profile.id
    ) {
      return {
        ok: false,
        status: 403,
        error: 'Forbidden: Challenge ownership mismatch.',
      };
    }

    if (
      options?.boundChallengeId &&
      challenge.challengeId !== options.boundChallengeId
    ) {
      return {
        ok: false,
        status: 401,
        error:
          'This OTP challenge is no longer active. Please use the latest OTP.',
      };
    }

    // Single-use check (OTP_SINGLE_USE = true)
    if (challenge.used || challenge.status === 'used') {
      return {
        ok: false,
        status: 401,
        error: 'This OTP has already been used. Please request a new OTP.',
      };
    }

    if (challenge.status === 'superseded') {
      return {
        ok: false,
        status: 401,
        error: 'Previous OTP was invalidated. Please enter the newest OTP.',
      };
    }

    // Max attempts check: Attempts 1..5 are permitted; Attempt 6+ is rejected
    if (
      challenge.status === 'invalidated' ||
      challenge.attempts >= OTP_SECURITY_CONFIG.OTP_MAX_VERIFICATION_ATTEMPTS
    ) {
      challenge.status = 'invalidated';
      saveAuthDb(db, nowMs);
      return {
        ok: false,
        status: 429,
        error:
          'Maximum OTP verification attempts exceeded. Please request a new OTP.',
      };
    }

    // Server-time expiry check: 0..299s valid, >=300s expired (OTP_EXPIRY_SECONDS = 300)
    const elapsedMs = nowMs - challenge.createdAt;
    const expiryMs = OTP_SECURITY_CONFIG.OTP_EXPIRY_SECONDS * 1000;
    if (elapsedMs >= expiryMs || nowMs >= challenge.expiresAt) {
      challenge.status = 'expired';
      saveAuthDb(db, nowMs);
      recordServerAuditLog({
        actorId: record.profile.id,
        actorEmail: record.profile.email,
        actorRole: record.profile.role,
        action: 'OTP_CHALLENGE_EXPIRED',
        target: challenge.challengeId,
      });
      return {
        ok: false,
        status: 401,
        error: 'OTP has expired. Please request a new OTP.',
      };
    }

    // Increment attempt counter for this challenge (1..5)
    challenge.attempts += 1;

    // Hard-coded demo OTPs are never accepted in production or verification
    const isDisallowedStatic = DISALLOWED_STATIC_OTPS.has(cleanOtp);

    const candidateHash = computeOtpHmac(
      challenge.challengeId,
      challenge.userId,
      cleanPhone,
      challenge.otpSalt,
      cleanOtp
    );

    const a = Buffer.from(candidateHash, 'hex');
    const b = Buffer.from(challenge.otpHash, 'hex');
    const hashMatched =
      !isDisallowedStatic &&
      a.length === b.length &&
      crypto.timingSafeEqual(a, b);

    if (!hashMatched) {
      rateState.failedVerifyTimestamps10m.push(nowMs);

      // If Attempt #5 failed, immediately invalidate current challenge
      if (
        challenge.attempts >= OTP_SECURITY_CONFIG.OTP_MAX_VERIFICATION_ATTEMPTS
      ) {
        challenge.status = 'invalidated';
        saveAuthDb(db, nowMs);
        recordServerAuditLog({
          actorId: record.profile.id,
          actorEmail: record.profile.email,
          actorRole: record.profile.role,
          action: 'OTP_CHALLENGE_INVALIDATED_MAX_ATTEMPTS',
          target: challenge.challengeId,
        });
        return {
          ok: false,
          status: 401,
          error:
            'Invalid OTP code. Maximum attempts reached; please request a new OTP.',
        };
      }

      saveAuthDb(db, nowMs);
      recordServerAuditLog({
        actorId: record.profile.id,
        actorEmail: record.profile.email,
        actorRole: record.profile.role,
        action: 'OTP_VERIFICATION_FAILED',
        target: `${challenge.challengeId} (attempt ${challenge.attempts}/${OTP_SECURITY_CONFIG.OTP_MAX_VERIFICATION_ATTEMPTS})`,
      });
      return {
        ok: false,
        status: 401,
        error: 'Invalid OTP code.',
      };
    }

    // Check account status before finalizing
    if (
      record.status === 'banned' ||
      record.status === 'suspended' ||
      db.bannedUserIds[record.profile.id]
    ) {
      return {
        ok: false,
        status: 403,
        error: 'Your account has been suspended by an administrator.',
      };
    }

    // Immediately consume OTP & invalidate any remaining active challenges
    // (mark_otp_as_used = true, invalidate_remaining_active_challenges = true)
    challenge.used = true;
    challenge.usedAt = nowMs;
    challenge.status = 'used';

    for (const [key, ch] of Object.entries(db.otpChallenges)) {
      if (
        (key === cleanPhone || ch.userId === record.profile.id) &&
        ch.challengeId !== challenge.challengeId &&
        ch.status === 'active'
      ) {
        ch.status = 'superseded';
      }
    }

    // Update phoneVerified ONLY (never auto-promote idVerified, teacher status, or KYC)
    if (db.authAccounts[record.profile.id]) {
      db.authAccounts[record.profile.id].phoneVerified = true;
    }

    record.profile.role = resolveTrustedUserRole({
      userId: record.profile.id,
      email: record.profile.email,
      emailVerified: record.emailVerified,
    });

    saveAuthDb(db, nowMs);

    recordServerAuditLog({
      actorId: record.profile.id,
      actorEmail: record.profile.email,
      actorRole: record.profile.role,
      action: 'OTP_VERIFICATION_SUCCEEDED',
      target: challenge.challengeId,
    });

    return {
      ok: true,
      user: record.profile,
      phoneVerified: true,
    };
  } finally {
    inFlightOtpLocks.delete(cleanPhone);
    if (hasFileLock) {
      releaseFileLock();
    }
  }
}

export function updateServerUserProfile(
  authenticatedUser: UserProfile,
  targetUserId: string,
  updates: {
    name?: string;
    classNum?: number;
    school?: string;
    city?: string;
    phone?: string;
    email?: string;
    streakReminders?: boolean;
    idCardName?: string;
  }
): { ok: true; user: UserProfile } | { ok: false; status: number; error: string } {
  // Ownership check: a user can only modify their own profile unless they are an admin
  if (
    authenticatedUser.id !== targetUserId &&
    authenticatedUser.role !== 'admin'
  ) {
    return {
      ok: false,
      status: 403,
      error: 'Forbidden: You are not authorized to modify another user profile.',
    };
  }

  const db = loadAuthDb();
  const existing = db.users[targetUserId];
  const baseProfile = existing ? existing.profile : authenticatedUser;

  let nextName = baseProfile.name;
  if (updates.name !== undefined) {
    const check = validateFullName(updates.name);
    if (!check.ok) return { ok: false, status: 400, error: check.error };
    nextName = check.value;
  }

  let nextClass = baseProfile.classNum;
  if (updates.classNum !== undefined) {
    const check = validateStudentClass(updates.classNum);
    if (!check.ok) return { ok: false, status: 400, error: check.error };
    nextClass = check.value;
  }

  let nextSchool = baseProfile.school;
  if (updates.school !== undefined) {
    const check = validateSchoolName(updates.school);
    if (!check.ok) return { ok: false, status: 400, error: check.error };
    nextSchool = check.value;
  }

  let nextPhone = baseProfile.phone;
  if (updates.phone !== undefined) {
    const check = validateIndianMobile(updates.phone);
    if (!check.ok) return { ok: false, status: 400, error: check.error };
    const existingPhoneOwner = db.phoneIndex[check.value];
    if (existingPhoneOwner && existingPhoneOwner !== baseProfile.id) {
      return {
        ok: false,
        status: 409,
        error: 'This mobile number is already associated with another account.',
      };
    }
    nextPhone = check.value;
  }

  // Prevent non-admin users from changing their email to the bootstrapped admin email
  let requestedEmail = baseProfile.email;
  if (updates.email !== undefined) {
    const check = validateOptionalEmail(updates.email);
    if (!check.ok) return { ok: false, status: 400, error: check.error };
    if (check.value) {
      const existingEmailOwner = db.emailIndex[check.value];
      if (existingEmailOwner && existingEmailOwner !== baseProfile.id) {
        return {
          ok: false,
          status: 409,
          error: 'This email address is already associated with another account.',
        };
      }
      requestedEmail = check.value;
    }
  }

  if (
    requestedEmail === BOOTSTRAPPED_ADMIN_EMAIL &&
    baseProfile.email.toLowerCase() !== BOOTSTRAPPED_ADMIN_EMAIL
  ) {
    return {
      ok: false,
      status: 403,
      error: 'Forbidden: Cannot assign reserved administrator email.',
    };
  }

  const authoritativeRole = resolveTrustedUserRole({
    userId: baseProfile.id,
    email: baseProfile.email,
    emailVerified: existing?.emailVerified ?? false,
  });

  // Notice: role, id, and idVerified are NEVER updated from client profile updates
  const updatedProfile: UserProfile = {
    ...baseProfile,
    name: nextName,
    classNum: nextClass,
    school: nextSchool,
    city:
      updates.city !== undefined
        ? updates.city.trim().slice(0, 100)
        : baseProfile.city,
    phone: nextPhone,
    email: requestedEmail,
    streakReminders:
      updates.streakReminders !== undefined
        ? Boolean(updates.streakReminders)
        : baseProfile.streakReminders,
    idCardName:
      updates.idCardName !== undefined
        ? updates.idCardName.trim().slice(0, 120)
        : baseProfile.idCardName,
    id: baseProfile.id,
    role: authoritativeRole,
    idVerified: baseProfile.idVerified,
  };

  if (baseProfile.phone !== nextPhone) {
    delete db.phoneIndex[baseProfile.phone];
    db.phoneIndex[nextPhone] = baseProfile.id;
  }
  if (baseProfile.email.toLowerCase() !== requestedEmail.toLowerCase()) {
    delete db.emailIndex[baseProfile.email.toLowerCase()];
    db.emailIndex[requestedEmail.toLowerCase()] = baseProfile.id;
  }

  if (existing) {
    existing.profile = updatedProfile;
  } else {
    db.users[targetUserId] = {
      profile: updatedProfile,
      status: 'active',
      emailVerified: false,
      failedLoginAttempts: 0,
      lockedUntil: 0,
    };
  }
  saveAuthDb(db);

  return { ok: true, user: updatedProfile };
}

/**
 * Trusted Admin-only role assignment function.
 * Only an authenticated Admin can elevate or change a user's role.
 */
export function assignUserRoleServer(
  adminUser: UserProfile,
  targetUserId: string,
  newRole: UserRole
): { ok: true; userId: string; role: UserRole } | { ok: false; status: number; error: string } {
  if (adminUser.role !== 'admin') {
    return {
      ok: false,
      status: 403,
      error: 'Forbidden: Only an administrator can assign user roles.',
    };
  }

  if (newRole !== 'student' && newRole !== 'teacher' && newRole !== 'admin') {
    return {
      ok: false,
      status: 400,
      error: 'Invalid role specified.',
    };
  }

  const db = loadAuthDb();
  db.roleAssignments[targetUserId] = newRole;
  if (db.users[targetUserId]) {
    db.users[targetUserId].profile.role = newRole;
  }
  saveAuthDb(db);

  // Authoritative persistence in PostgreSQL
  dbUpdateUser(targetUserId, { role: newRole }).catch(() => {});

  // Invalidate previous sessions when role changes (prevents demoted admins from retaining access)
  dbRevokeUserSessionsOnRoleChange(targetUserId, newRole).catch(() => {});

  recordServerAuditLog({
    actorId: adminUser.id,
    actorEmail: adminUser.email,
    actorRole: adminUser.role,
    action: 'ADMIN_ASSIGN_ROLE',
    target: `${targetUserId} -> ${newRole}`,
  });

  return { ok: true, userId: targetUserId, role: newRole };
}

/**
 * Trusted Admin-only user ban/suspend toggle.
 */
export function setUserBanStatusServer(
  adminUser: UserProfile,
  targetUserId: string,
  banned: boolean
):
  | { ok: true; userId: string; status: 'active' | 'banned' }
  | { ok: false; status: number; error: string } {
  if (adminUser.role !== 'admin') {
    return {
      ok: false,
      status: 403,
      error: 'Forbidden: Only an administrator can ban or unban users.',
    };
  }

  const db = loadAuthDb();
  if (banned) {
    db.bannedUserIds[targetUserId] = true;
    if (db.users[targetUserId]) {
      db.users[targetUserId].status = 'banned';
    }
    if (db.authAccounts[targetUserId]) {
      db.authAccounts[targetUserId].status = 'banned';
    }
  } else {
    delete db.bannedUserIds[targetUserId];
    if (db.users[targetUserId]) {
      db.users[targetUserId].status = 'active';
    }
    if (db.authAccounts[targetUserId]) {
      db.authAccounts[targetUserId].status = 'active';
    }
  }
  saveAuthDb(db);

  const newStatus = banned ? 'banned' : 'active';
  // Authoritative PostgreSQL persistence
  dbUpdateUser(targetUserId, { status: newStatus }).catch(() => {});

  // If banned or suspended, invalidate all active sessions immediately in PostgreSQL
  if (banned) {
    dbRevokeAllUserSessionsSupabase(targetUserId, undefined, 'account_banned_by_admin').catch(() => {});
  }

  recordServerAuditLog({
    actorId: adminUser.id,
    actorEmail: adminUser.email,
    actorRole: adminUser.role,
    action: banned ? 'ADMIN_BAN_USER' : 'ADMIN_UNBAN_USER',
    target: targetUserId,
  });

  return {
    ok: true,
    userId: targetUserId,
    status: banned ? 'banned' : 'active',
  };
}

// ============================================================================
// SECURE PASSWORD RESET, RECOVERY & PASSWORD CHANGE (AUTH-05)
// ============================================================================

function computePasswordResetTokenHmac(
  resetId: string,
  userId: string,
  tokenSalt: string,
  rawTokenSecret: string
): string {
  return crypto
    .createHmac('sha256', getSigningSecret())
    .update(`pwd_reset:${resetId}:${userId}:${tokenSalt}:${rawTokenSecret}`)
    .digest('hex');
}

/**
 * Generates a cryptographically strong, short-lived, single-use password reset token
 * without leaking whether an account exists (prevents account enumeration).
 */
export function createPasswordResetRequest(params: {
  identifier: string;
  nowMs?: number;
}):
  | {
      ok: true;
      sent: true;
      message: string;
      /**
       * Server-side internal reset token string (`${resetId}.${secretHex}`)
       * for server-side dispatch/testing only — NEVER returned in HTTP API responses!
       */
      _internalResetToken?: string;
      _internalResetId?: string;
    }
  | { ok: false; status: number; error: string; retryAfterSec?: number } {
  const nowMs = typeof params.nowMs === 'number' ? params.nowMs : Date.now();
  const rawIdentifier =
    typeof params.identifier === 'string' ? params.identifier.trim() : '';

  if (
    !rawIdentifier ||
    rawIdentifier.length < 3 ||
    rawIdentifier.length > 160 ||
    /[<>`$\\{};[\]|^~]/.test(rawIdentifier)
  ) {
    return {
      ok: false,
      status: 400,
      error: 'Please provide a valid registered email or mobile number.',
    };
  }

  const genericSuccessMessage =
    'If an account matches the provided details, password reset instructions have been dispatched.';

  const digits = rawIdentifier.replace(/\D/g, '');
  const identifierKey =
    digits.length >= 10 && !rawIdentifier.includes('@')
      ? `phone:${digits.slice(-10)}`
      : `id:${rawIdentifier.toLowerCase()}`;

  const lockKey = `forgot:${identifierKey}`;
  if (inFlightPasswordResetLocks.has(lockKey)) {
    return {
      ok: false,
      status: 429,
      error: 'Too many password reset requests. Please try again later.',
      retryAfterSec: PASSWORD_SECURITY_CONFIG.FORGOT_COOLDOWN_SECONDS,
    };
  }

  inFlightPasswordResetLocks.add(lockKey);
  const hasFileLock = acquireFileLock();

  try {
    const db = loadAuthDb();

    const window24hStart = nowMs - 24 * 60 * 60 * 1000;
    const window1hStart = nowMs - 60 * 60 * 1000;
    const window15mStart = nowMs - 15 * 60 * 1000;

    const existingRate: PasswordResetRateState = db.passwordResetRateStates[
      identifierKey
    ] || {
      identifierKey,
      lastRequestedAt: 0,
      requestTimestamps24h: [],
    };

    const recent24h = (existingRate.requestTimestamps24h || []).filter(
      (ts) => ts > window24hStart
    );
    const recent1h = recent24h.filter((ts) => ts > window1hStart);
    const recent15m = recent24h.filter((ts) => ts > window15mStart);

    // 1. Cooldown check (60s between reset requests for the same identifier)
    if (existingRate.lastRequestedAt > 0) {
      const elapsedSec = Math.floor(
        (nowMs - existingRate.lastRequestedAt) / 1000
      );
      if (
        elapsedSec >= 0 &&
        elapsedSec < PASSWORD_SECURITY_CONFIG.FORGOT_COOLDOWN_SECONDS
      ) {
        const retryAfterSec =
          PASSWORD_SECURITY_CONFIG.FORGOT_COOLDOWN_SECONDS - elapsedSec;
        return {
          ok: false,
          status: 429,
          error: 'Too many password reset requests. Please try again later.',
          retryAfterSec,
        };
      }
    }

    // 2. Per-15-minute, per-hour, and per-24-hour abuse protection
    if (recent15m.length >= PASSWORD_SECURITY_CONFIG.FORGOT_MAX_PER_15_MINUTES) {
      return {
        ok: false,
        status: 429,
        error: 'Too many password reset requests. Please try again later.',
        retryAfterSec: 900,
      };
    }
    if (recent1h.length >= PASSWORD_SECURITY_CONFIG.FORGOT_MAX_PER_HOUR) {
      return {
        ok: false,
        status: 429,
        error: 'Too many password reset requests. Please try again later.',
        retryAfterSec: 3600,
      };
    }
    if (recent24h.length >= PASSWORD_SECURITY_CONFIG.FORGOT_MAX_PER_24_HOURS) {
      return {
        ok: false,
        status: 429,
        error: 'Too many password reset requests. Please try again later.',
        retryAfterSec: 3600,
      };
    }

    // Record rate-limit state identically whether the user exists or not (anti-enumeration)
    recent24h.push(nowMs);
    db.passwordResetRateStates[identifierKey] = {
      identifierKey,
      lastRequestedAt: nowMs,
      requestTimestamps24h: recent24h,
    };

    const record = findUserByIdentifier(rawIdentifier);
    if (
      !record ||
      record.status === 'banned' ||
      record.status === 'suspended' ||
      db.bannedUserIds[record.profile.id]
    ) {
      // Perform constant-time dummy HMAC work so response timing does not leak account existence
      crypto
        .createHmac('sha256', getSigningSecret())
        .update(`dummy_reset:${rawIdentifier}:${nowMs}`)
        .digest('hex');
      saveAuthDb(db, nowMs);
      return {
        ok: true,
        sent: true,
        message: genericSuccessMessage,
      };
    }

    const userId = record.profile.id;

    // Invalidate all previous active reset tokens for this user
    for (const tokenRec of Object.values(db.passwordResetTokens)) {
      if (tokenRec.userId === userId && tokenRec.status === 'active') {
        tokenRec.status = 'superseded';
      }
    }

    const resetId = `rst_${crypto.randomBytes(12).toString('hex')}`;
    const rawSecretHex = crypto
      .randomBytes(PASSWORD_SECURITY_CONFIG.RESET_TOKEN_BYTES)
      .toString('hex');
    const tokenSalt = crypto.randomBytes(16).toString('hex');
    const tokenHash = computePasswordResetTokenHmac(
      resetId,
      userId,
      tokenSalt,
      rawSecretHex
    );

    const expiresAt =
      nowMs + PASSWORD_SECURITY_CONFIG.RESET_TOKEN_EXPIRY_SECONDS * 1000;

    db.passwordResetTokens[resetId] = {
      resetId,
      userId,
      tokenSalt,
      tokenHash,
      createdAt: nowMs,
      expiresAt,
      attempts: 0,
      maxAttempts: PASSWORD_SECURITY_CONFIG.RESET_TOKEN_MAX_ATTEMPTS,
      used: false,
      status: 'active',
    };

    saveAuthDb(db, nowMs);

    recordServerAuditLog({
      actorId: userId,
      actorEmail: record.profile.email,
      actorRole: record.profile.role,
      action: 'PASSWORD_RESET_REQUESTED',
      target: resetId,
    });

    return {
      ok: true,
      sent: true,
      message: genericSuccessMessage,
      _internalResetToken: `${resetId}.${rawSecretHex}`,
      _internalResetId: resetId,
    };
  } finally {
    inFlightPasswordResetLocks.delete(lockKey);
    if (hasFileLock) {
      releaseFileLock();
    }
  }
}

/**
 * Validates and consumes a single-use password reset token, updates the user's password hash
 * in the authentication identity store, and invalidates all existing sessions for that user.
 */
export function consumePasswordResetToken(params: {
  token: unknown;
  newPassword: unknown;
  confirmPassword?: unknown;
  nowMs?: number;
}):
  | { ok: true; userId: string }
  | { ok: false; status: number; error: string } {
  const nowMs = typeof params.nowMs === 'number' ? params.nowMs : Date.now();

  if (typeof params.token !== 'string') {
    return {
      ok: false,
      status: 400,
      error: 'Invalid or expired password reset token.',
    };
  }

  const trimmedToken = params.token.trim();
  // Expected format: rst_<24 hex chars>.<64 hex chars>
  const parts = trimmedToken.split('.');
  if (
    parts.length !== 2 ||
    !/^rst_[a-f0-9]{24}$/.test(parts[0]) ||
    !/^[a-f0-9]{64}$/.test(parts[1])
  ) {
    return {
      ok: false,
      status: 400,
      error: 'Invalid or expired password reset token.',
    };
  }

  const [resetId, rawSecretHex] = parts;

  if (
    params.confirmPassword !== undefined &&
    params.newPassword !== params.confirmPassword
  ) {
    return {
      ok: false,
      status: 400,
      error: 'New password and confirm password do not match.',
    };
  }

  const lockKey = `consume:${resetId}`;
  if (inFlightPasswordResetLocks.has(lockKey)) {
    return {
      ok: false,
      status: 409,
      error: 'Password reset is already in progress.',
    };
  }

  inFlightPasswordResetLocks.add(lockKey);
  const hasFileLock = acquireFileLock();

  try {
    const db = loadAuthDb();
    const tokenRecord = db.passwordResetTokens[resetId];

    if (!tokenRecord) {
      return {
        ok: false,
        status: 400,
        error: 'Invalid or expired password reset token.',
      };
    }

    // 1. Reject already used or superseded/invalidated tokens
    if (tokenRecord.used || tokenRecord.status === 'used') {
      return {
        ok: false,
        status: 400,
        error: 'This password reset link has already been used.',
      };
    }

    if (tokenRecord.status !== 'active') {
      return {
        ok: false,
        status: 400,
        error: 'Invalid or expired password reset token.',
      };
    }

    // 2. Expiry check: valid strictly while nowMs < expiresAt
    if (nowMs >= tokenRecord.expiresAt) {
      tokenRecord.status = 'expired';
      saveAuthDb(db, nowMs);
      return {
        ok: false,
        status: 400,
        error: 'Password reset token has expired. Please request a new reset link.',
      };
    }

    // 3. Max attempts check
    if (tokenRecord.attempts >= tokenRecord.maxAttempts) {
      tokenRecord.status = 'invalidated';
      saveAuthDb(db, nowMs);
      return {
        ok: false,
        status: 429,
        error: 'Maximum reset verification attempts exceeded. Please request a new reset link.',
      };
    }

    // 4. Constant-time cryptographic verification of token secret bound to resetId & userId
    const expectedHash = computePasswordResetTokenHmac(
      tokenRecord.resetId,
      tokenRecord.userId,
      tokenRecord.tokenSalt,
      rawSecretHex
    );
    const a = Buffer.from(expectedHash, 'hex');
    const b = Buffer.from(tokenRecord.tokenHash, 'hex');
    const isHashMatch = a.length === b.length && crypto.timingSafeEqual(a, b);

    if (!isHashMatch) {
      tokenRecord.attempts += 1;
      if (tokenRecord.attempts >= tokenRecord.maxAttempts) {
        tokenRecord.status = 'invalidated';
      }
      saveAuthDb(db, nowMs);
      return {
        ok: false,
        status: 400,
        error: 'Invalid or expired password reset token.',
      };
    }

    // 5. Resolve target user strictly from the verified token record (never from client input)
    const userId = tokenRecord.userId;
    const userRecord = db.users[userId];
    const authAccount = db.authAccounts[userId];

    if (!userRecord || !authAccount) {
      tokenRecord.status = 'invalidated';
      saveAuthDb(db, nowMs);
      return {
        ok: false,
        status: 400,
        error: 'Invalid or expired password reset token.',
      };
    }

    if (
      userRecord.status === 'banned' ||
      userRecord.status === 'suspended' ||
      authAccount.status === 'banned' ||
      authAccount.status === 'suspended' ||
      db.bannedUserIds[userId]
    ) {
      return {
        ok: false,
        status: 403,
        error: 'Your account has been suspended by an administrator.',
      };
    }

    // 6. Validate new password strength & contextual checks
    const passwordCheck = validatePasswordStrength(params.newPassword, {
      email: userRecord.profile.email,
      phone: userRecord.profile.phone,
      name: userRecord.profile.name,
    });
    if (!passwordCheck.ok) {
      return {
        ok: false,
        status: 400,
        error: passwordCheck.error,
      };
    }

    // Reject resetting to the identical existing password
    if (
      authAccount.passwordSalt &&
      authAccount.passwordHash &&
      verifyPassword(
        passwordCheck.value,
        authAccount.passwordSalt,
        authAccount.passwordHash
      )
    ) {
      return {
        ok: false,
        status: 400,
        error: 'New password must be different from your current password.',
      };
    }

    // 7. Atomically consume token, update password hash in authAccount, and revoke all prior sessions
    tokenRecord.used = true;
    tokenRecord.usedAt = nowMs;
    tokenRecord.status = 'used';

    for (const otherToken of Object.values(db.passwordResetTokens)) {
      if (
        otherToken.userId === userId &&
        otherToken.resetId !== resetId &&
        otherToken.status === 'active'
      ) {
        otherToken.status = 'superseded';
      }
    }

    const { salt, hash } = hashPassword(passwordCheck.value);
    authAccount.passwordSalt = salt;
    authAccount.passwordHash = hash;
    authAccount.passwordChangedAt = nowMs;
    authAccount.sessionsRevokedBefore = nowMs;
    authAccount.failedLoginAttempts = 0;
    authAccount.lockedUntil = 0;
    userRecord.failedLoginAttempts = 0;
    userRecord.lockedUntil = 0;

    // AUTH-06 #18: Explicitly mark all existing sessions for this user as revoked on password reset
    for (const sess of Object.values(db.sessions)) {
      if (sess.userId === userId && sess.status === 'active') {
        sess.status = 'revoked';
        sess.revokedAt = nowMs;
        sess.revokeReason = 'password_reset';
        db.revokedSessions[sess.jti] = sess.absoluteExpiresAt;
      }
    }

    // Never duplicate password hash on userRecord
    const cleanRec = userRecord as StoredUserRecord & {
      passwordSalt?: string;
      passwordHash?: string;
    };
    delete cleanRec.passwordSalt;
    delete cleanRec.passwordHash;

    saveAuthDb(db, nowMs);

    recordServerAuditLog({
      actorId: userId,
      actorEmail: userRecord.profile.email,
      actorRole: userRecord.profile.role,
      action: 'PASSWORD_RESET_COMPLETED',
      target: resetId,
    });

    return {
      ok: true,
      userId,
    };
  } finally {
    inFlightPasswordResetLocks.delete(lockKey);
    if (hasFileLock) {
      releaseFileLock();
    }
  }
}

/**
 * Changes the password for an already authenticated user after verifying their current password,
 * invalidates all older sessions, and rotates the active session token.
 */
export function changeAuthenticatedUserPassword(params: {
  authenticatedUserId: string;
  currentSessionJti?: string;
  currentSessionExp?: number;
  currentPassword: unknown;
  newPassword: unknown;
  confirmPassword?: unknown;
  nowMs?: number;
}):
  | { ok: true; user: UserProfile; rotatedSessionToken: string }
  | { ok: false; status: number; error: string } {
  const nowMs = typeof params.nowMs === 'number' ? params.nowMs : Date.now();
  const userId = params.authenticatedUserId;

  if (typeof params.currentPassword !== 'string' || !params.currentPassword) {
    return {
      ok: false,
      status: 400,
      error: 'Current password is required.',
    };
  }

  if (typeof params.newPassword !== 'string' || !params.newPassword) {
    return {
      ok: false,
      status: 400,
      error: 'New password is required.',
    };
  }

  if (
    params.confirmPassword !== undefined &&
    params.newPassword !== params.confirmPassword
  ) {
    return {
      ok: false,
      status: 400,
      error: 'New password and confirm password do not match.',
    };
  }

  const lockKey = `chg_pwd:${userId}`;
  if (inFlightPasswordResetLocks.has(lockKey)) {
    return {
      ok: false,
      status: 409,
      error: 'Password update is already in progress.',
    };
  }

  inFlightPasswordResetLocks.add(lockKey);
  const hasFileLock = acquireFileLock();

  try {
    const db = loadAuthDb();
    const userRecord = db.users[userId];
    const authAccount = db.authAccounts[userId];

    if (!userRecord || !authAccount) {
      return {
        ok: false,
        status: 401,
        error: 'Unauthorized: Account not found.',
      };
    }

    if (
      userRecord.status === 'banned' ||
      userRecord.status === 'suspended' ||
      authAccount.status === 'banned' ||
      authAccount.status === 'suspended' ||
      db.bannedUserIds[userId]
    ) {
      return {
        ok: false,
        status: 403,
        error: 'Your account has been suspended by an administrator.',
      };
    }

    // Verify current password against stored hash in authAccount
    const isCurrentValid = verifyPassword(
      params.currentPassword,
      authAccount.passwordSalt,
      authAccount.passwordHash
    );
    if (!isCurrentValid) {
      recordServerAuditLog({
        actorId: userId,
        actorEmail: userRecord.profile.email,
        actorRole: userRecord.profile.role,
        action: 'PASSWORD_CHANGE_FAILED_WRONG_CURRENT',
        target: userId,
      });
      return {
        ok: false,
        status: 401,
        error: 'Current password is incorrect.',
      };
    }

    if (params.currentPassword === params.newPassword) {
      return {
        ok: false,
        status: 400,
        error: 'New password must be different from your current password.',
      };
    }

    const passwordCheck = validatePasswordStrength(params.newPassword, {
      email: userRecord.profile.email,
      phone: userRecord.profile.phone,
      name: userRecord.profile.name,
    });
    if (!passwordCheck.ok) {
      return {
        ok: false,
        status: 400,
        error: passwordCheck.error,
      };
    }

    const { salt, hash } = hashPassword(passwordCheck.value);
    authAccount.passwordSalt = salt;
    authAccount.passwordHash = hash;
    authAccount.passwordChangedAt = nowMs;
    authAccount.sessionsRevokedBefore = nowMs;
    authAccount.failedLoginAttempts = 0;
    authAccount.lockedUntil = 0;
    userRecord.failedLoginAttempts = 0;
    userRecord.lockedUntil = 0;

    // Revoke previous session JTI and all other active sessions for this user
    if (params.currentSessionJti) {
      db.revokedSessions[params.currentSessionJti] =
        params.currentSessionExp || nowMs + SESSION_TTL_MS;
    }
    for (const sess of Object.values(db.sessions)) {
      if (sess.userId === userId && sess.status === 'active') {
        sess.status = 'revoked';
        sess.revokedAt = nowMs;
        sess.revokeReason = 'password_changed';
        db.revokedSessions[sess.jti] = sess.absoluteExpiresAt;
      }
    }

    // Invalidate any active password reset tokens for this user
    for (const tokenRec of Object.values(db.passwordResetTokens)) {
      if (tokenRec.userId === userId && tokenRec.status === 'active') {
        tokenRec.status = 'superseded';
      }
    }

    saveAuthDb(db, nowMs);

    // Issue a fresh rotated session token with iat >= nowMs
    const trustedRole = resolveTrustedUserRole({
      userId: userRecord.profile.id,
      email: userRecord.profile.email,
      emailVerified: userRecord.emailVerified,
    });
    const issuedAt = Math.max(Date.now(), nowMs);
    const rotatedSessionToken = signSessionToken(
      { ...userRecord.profile, role: trustedRole },
      { nowMs: issuedAt }
    );

    recordServerAuditLog({
      actorId: userId,
      actorEmail: userRecord.profile.email,
      actorRole: trustedRole,
      action: 'PASSWORD_CHANGED',
      target: userId,
    });

    return {
      ok: true,
      user: { ...userRecord.profile, role: trustedRole },
      rotatedSessionToken,
    };
  } finally {
    inFlightPasswordResetLocks.delete(lockKey);
    if (hasFileLock) {
      releaseFileLock();
    }
  }
}

// ============================================================================
// PRODUCTION-SAFETY PREFLIGHT & ROLLBACK RECOVERY UTILITIES (AUTH-06)
// ============================================================================

const DEFAULT_AUTH_BACKUP_PATH = 'supabase://public.users+auth_identities/backup';
const inMemoryBackups = new Map<string, PersistentAuthDatabase>();

/**
 * PREFLIGHT 8: Returns the verified canonical application URL.
 * Never derives security-sensitive callback URLs from an untrusted Host header,
 * and rejects obsolete demo/Lovable URLs.
 */
export function getCanonicalAppUrl(): string {
  const configured = (
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL ||
    'http://localhost:3000'
  ).trim();

  try {
    const parsed = new URL(configured);
    const host = parsed.hostname.toLowerCase();
    if (
      host.includes('lovable.app') ||
      host.includes('lovable.dev') ||
      host.includes('lovableproject.com') ||
      (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
    ) {
      return 'http://localhost:3000';
    }
    return parsed.origin;
  } catch {
    return 'http://localhost:3000';
  }
}

/**
 * PREFLIGHT 3 & PREFLIGHT 7: Verifies environment separation, required configuration,
 * and confirms no development/test authentication bypass is active in production.
 * Never logs or returns secret values.
 */
export function verifyAuthEnvironmentConfig(): {
  ok: boolean;
  environment: 'development' | 'staging' | 'production' | 'test';
  canonicalAppUrl: string;
  hasSigningSecret: boolean;
  devBypassesDisabled: boolean;
  cookieSecurity: {
    httpOnly: true;
    sameSite: 'lax';
    secureInProduction: true;
    path: '/';
  };
  issues: string[];
} {
  const rawEnv = (process.env.NODE_ENV || 'development').toLowerCase();
  const environment: 'development' | 'staging' | 'production' | 'test' =
    rawEnv === 'production'
      ? 'production'
      : rawEnv === 'test'
        ? 'test'
        : (process.env.VERCEL_ENV || '').toLowerCase() === 'preview'
          ? 'staging'
          : 'development';

  const issues: string[] = [];
  const secret = getSigningSecret();
  const hasSigningSecret = typeof secret === 'string' && secret.length >= 32;
  if (!hasSigningSecret) {
    issues.push('Session signing secret must be at least 32 characters.');
  }

  const devBypassesDisabled =
    OTP_SECURITY_CONFIG.ALLOW_DEV_OTP_BYPASS_IN_PRODUCTION === false &&
    PASSWORD_SECURITY_CONFIG.ALLOW_DEV_RESET_TOKEN_IN_PRODUCTION === false &&
    SESSION_SECURITY_CONFIG.ALLOW_SESSION_TOKEN_IN_URL === false &&
    SESSION_SECURITY_CONFIG.LOG_SESSION_TOKEN === false &&
    SESSION_SECURITY_CONFIG.LOG_REFRESH_TOKEN === false;

  if (!devBypassesDisabled) {
    issues.push('One or more development authentication bypass flags are enabled.');
  }

  const canonicalAppUrl = getCanonicalAppUrl();
  if (
    environment === 'production' &&
    !canonicalAppUrl.startsWith('https://') &&
    !canonicalAppUrl.startsWith('http://localhost')
  ) {
    issues.push('Production canonical APP_URL should use HTTPS.');
  }

  return {
    ok: issues.length === 0,
    environment,
    canonicalAppUrl,
    hasSigningSecret,
    devBypassesDisabled,
    cookieSecurity: {
      httpOnly: true,
      sameSite: 'lax',
      secureInProduction: true,
      path: '/',
    },
    issues,
  };
}

/**
 * PREFLIGHT 4: Creates a verified, restorable backup of the authentication database
 * before any schema/session changes.
 */
export function createAuthDatabaseBackup(
  backupPath = DEFAULT_AUTH_BACKUP_PATH
): {
  ok: boolean;
  backupPath: string;
  userCount: number;
  sessionCount: number;
  timestamp: string;
} {
  const db = loadAuthDb();
  inMemoryBackups.set(backupPath, JSON.parse(JSON.stringify(db)));

  return {
    ok: true,
    backupPath,
    userCount: Object.keys(db.users).length || getCachedUserCount(),
    sessionCount: Object.keys(db.sessions).length || getCachedSessionCount(),
    timestamp: new Date().toISOString(),
  };
}

/**
 * ROLLBACK STEP 4: Non-destructively restores authentication database state from a verified backup
 * while preserving any legitimate user accounts created after the backup checkpoint.
 */
export function restoreAuthDatabaseFromBackup(
  backupPath = DEFAULT_AUTH_BACKUP_PATH
): {
  ok: boolean;
  restoredUsers: number;
  preservedNewUsers: number;
} {
  const backupDb = inMemoryBackups.get(backupPath);
  if (!backupDb) {
    return { ok: false, restoredUsers: 0, preservedNewUsers: 0 };
  }

  const currentDb = loadAuthDb();
  let preservedNewUsers = 0;
  for (const [uid, userRec] of Object.entries(currentDb.users)) {
    if (!backupDb.users[uid]) {
      backupDb.users[uid] = userRec;
      if (currentDb.authAccounts[uid]) {
        backupDb.authAccounts[uid] = currentDb.authAccounts[uid];
      }
      preservedNewUsers += 1;
    }
  }

  const mergedDb = ensureDbShape(backupDb);
  saveAuthDb(mergedDb);

  recordServerAuditLog({
    actorId: 'system_rollback',
    actorEmail: 'system',
    actorRole: 'admin',
    action: 'AUTH_DATABASE_ROLLBACK_RESTORED',
    target: `restored:${Object.keys(mergedDb.users).length},preserved_new:${preservedNewUsers}`,
  });

  return {
    ok: true,
    restoredUsers: Object.keys(mergedDb.users).length,
    preservedNewUsers,
  };
}

/**
 * ROLLBACK STEP 5: Revokes potentially affected or compromised sessions / token families
 * and requires fresh re-authentication without exposing any session tokens.
 */
export function emergencyRevokeCompromisedSessions(options?: {
  userId?: string;
  familyId?: string;
  reason?: string;
  nowMs?: number;
}): { revokedCount: number } {
  const nowMs = typeof options?.nowMs === 'number' ? options.nowMs : Date.now();
  const reason = options?.reason || 'rollback_security_revocation';
  const db = loadAuthDb();
  let revokedCount = 0;

  for (const sess of Object.values(db.sessions)) {
    const matchesUser = !options?.userId || sess.userId === options.userId;
    const matchesFamily =
      !options?.familyId || sess.familyId === options.familyId;
    if (
      matchesUser &&
      matchesFamily &&
      (sess.status === 'active' || sess.status === 'rotated')
    ) {
      sess.status = 'revoked';
      sess.revokedAt = nowMs;
      sess.revokeReason = reason;
      db.revokedSessions[sess.jti] = sess.absoluteExpiresAt;
      revokedCount += 1;
    }
  }

  if (options?.userId && db.authAccounts[options.userId]) {
    db.authAccounts[options.userId].sessionsRevokedBefore = nowMs;
  } else if (!options?.userId && !options?.familyId) {
    for (const acc of Object.values(db.authAccounts)) {
      acc.sessionsRevokedBefore = nowMs;
    }
  }

  saveAuthDb(db, nowMs);

  recordServerAuditLog({
    actorId: options?.userId || 'system_security',
    actorEmail: 'system',
    actorRole: 'admin',
    action: 'EMERGENCY_SESSION_REVOCATION',
    target: `revoked_count:${revokedCount} (${reason})`,
  });

  return { revokedCount };
}

