import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { UserProfile } from './store';
import type { UserRole } from './server-auth';

// ============================================================================
// SERVER-ONLY SUPABASE PERSISTENCE LAYER FOR UYANIX AUTHENTICATION
// The service-role key is STRICTLY server-side and never exposed to the client.
// ============================================================================

export interface UserRow {
  id: string; // UUID primary key
  name: string;
  email: string | null;
  phone: string;
  class: number;
  school: string;
  city: string | null;
  role: 'student' | 'teacher' | 'admin';
  avatar: string | null;
  id_card_url: string | null;
  id_verification_status: 'pending' | 'verified' | 'rejected';
  phone_verified: boolean;
  status: 'active' | 'banned' | 'suspended';
  terms_accepted_at: string;
  created_at: string;
}

export interface AuthIdentityRow {
  user_id: string; // UUID references public.users(id)
  normalized_email: string | null;
  normalized_phone: string;
  password_salt: string | null;
  password_hash: string | null;
  password_changed_at: string | null;
  sessions_revoked_before: string | null;
  google_uid: string | null;
  email_verified: boolean;
  phone_verified: boolean;
  failed_login_attempts: number;
  locked_until: string | null;
  created_at: string;
  updated_at: string;
}

export interface OtpChallengeRow {
  challenge_id: string; // TEXT primary key
  user_id: string; // UUID references public.users(id)
  phone: string;
  otp_salt: string;
  otp_hash: string;
  attempts: number;
  max_attempts: number;
  resend_count: number;
  used: boolean;
  used_at: string | null;
  status: 'active' | 'used' | 'expired' | 'invalidated' | 'superseded';
  created_at: string;
  expires_at: string;
}

export interface PasswordResetTokenRow {
  reset_id: string; // TEXT primary key
  user_id: string; // UUID references public.users(id)
  token_salt: string;
  token_hash: string;
  attempts: number;
  max_attempts: number;
  used: boolean;
  used_at: string | null;
  status: 'active' | 'used' | 'expired' | 'invalidated' | 'superseded';
  created_at: string;
  expires_at: string;
}

export interface UserSessionRow {
  jti: string; // TEXT primary key
  family_id: string;
  user_id: string; // UUID references public.users(id)
  auth_time: string;
  last_active_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  status: 'active' | 'rotated' | 'revoked' | 'expired' | 'compromised';
  replaced_by_jti: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
  created_at: string;
}

export interface AuditLogRow {
  id?: string;
  actor_id: string | null;
  action: string;
  target: string;
  meta?: Record<string, unknown>;
  created_at?: string;
}

// In-process write-through memory cache to accelerate synchronous reads
// Correctness is ALWAYS authoritative from Supabase PostgreSQL
interface InMemorySyncCache {
  usersById: Map<string, UserRow>;
  usersByPhone: Map<string, string>;
  usersByEmail: Map<string, string>;
  identitiesByUserId: Map<string, AuthIdentityRow>;
  sessionsByJti: Map<string, UserSessionRow>;
  otpChallengesByPhone: Map<string, OtpChallengeRow>;
  passwordResetTokensByResetId: Map<string, PasswordResetTokenRow>;
  lastSyncedAt: number;
}

const syncCache: InMemorySyncCache = {
  usersById: new Map(),
  usersByPhone: new Map(),
  usersByEmail: new Map(),
  identitiesByUserId: new Map(),
  sessionsByJti: new Map(),
  otpChallengesByPhone: new Map(),
  passwordResetTokensByResetId: new Map(),
  lastSyncedAt: 0,
};

let cachedAdminClient: SupabaseClient | null = null;

/**
 * Checks whether Supabase environment variables are properly configured.
 */
export function isSupabaseConfigured(): boolean {
  const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SERVICE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !key) return false;
  if (
    url.includes('your-project.supabase.co') ||
    key.includes('your-supabase-service-role-key') ||
    key.includes('your-supabase-anon-key')
  ) {
    return false;
  }
  return true;
}

/**
 * Returns a privileged, server-only Supabase client for database persistence.
 * Bypasses RLS using the server service-role key or authenticates via admin privileges.
 */
export function getSupabaseAdminClient(): SupabaseClient | null {
  if (cachedAdminClient) return cachedAdminClient;

  const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SERVICE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !key) return null;
  if (
    url.includes('your-project.supabase.co') ||
    key.includes('your-supabase-service-role-key') ||
    key.includes('your-supabase-anon-key')
  ) {
    return null;
  }

  cachedAdminClient = createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  return cachedAdminClient;
}

/**
 * Maps a database UserRow to the application UserProfile format.
 */
export function mapUserRowToProfile(row: UserRow): UserProfile {
  const shortName =
    row.name
      .split(/\s+/)[0]
      ?.toLowerCase()
      .replace(/[^a-z0-9]/g, '') || 'student';

  return {
    id: row.id,
    name: row.name,
    teacherShortName: shortName,
    email: row.email || '',
    phone: row.phone,
    classNum: row.class,
    school: row.school,
    city: row.city || 'Jaipur',
    role: row.role as UserRole,
    avatar: row.avatar || undefined,
    idCardUrl: row.id_card_url || undefined,
    idVerificationStatus: row.id_verification_status,
    idVerified: row.phone_verified || row.id_verification_status === 'verified',
    streakReminders: true,
    createdAt: row.created_at,
  };
}

// ============================================================================
// DATABASE REPOSITORY OPERATIONS (AUTHORITATIVE PERSISTENCE IN SUPABASE)
// ============================================================================

/**
 * Queries a user and their identity from Supabase by phone or email.
 */
export async function dbFindUserByIdentifier(
  identifier: string
): Promise<{ user: UserRow; identity: AuthIdentityRow } | null> {
  const clean = identifier.trim().toLowerCase();
  const digits = clean.replace(/\D/g, '').slice(-10);
  const isPhone = /^[6-9][0-9]{9}$/.test(digits);

  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    // If Supabase is not configured, check cache
    if (isPhone && syncCache.usersByPhone.has(digits)) {
      const uid = syncCache.usersByPhone.get(digits)!;
      const user = syncCache.usersById.get(uid);
      const identity = syncCache.identitiesByUserId.get(uid);
      if (user && identity) return { user, identity };
    }
    if (!isPhone && syncCache.usersByEmail.has(clean)) {
      const uid = syncCache.usersByEmail.get(clean)!;
      const user = syncCache.usersById.get(uid);
      const identity = syncCache.identitiesByUserId.get(uid);
      if (user && identity) return { user, identity };
    }
    return null;
  }

  try {
    let userQuery = supabase.from('users').select('*');
    if (isPhone) {
      userQuery = userQuery.eq('phone', digits);
    } else {
      userQuery = userQuery.ilike('email', clean);
    }

    const { data: users, error: userError } = await userQuery.limit(1);
    if (userError || !users || users.length === 0) {
      return null;
    }

    const userRow = users[0] as UserRow;
    const { data: identities, error: identError } = await supabase
      .from('auth_identities')
      .select('*')
      .eq('user_id', userRow.id)
      .limit(1);

    if (identError || !identities || identities.length === 0) {
      // If auth_identities table does not have a row yet, construct synthetic fallback
      const syntheticIdentity: AuthIdentityRow = {
        user_id: userRow.id,
        normalized_email: userRow.email,
        normalized_phone: userRow.phone,
        password_salt: null,
        password_hash: null,
        password_changed_at: null,
        sessions_revoked_before: null,
        google_uid: null,
        email_verified: Boolean(userRow.email),
        phone_verified: userRow.phone_verified,
        failed_login_attempts: 0,
        locked_until: null,
        created_at: userRow.created_at,
        updated_at: userRow.created_at,
      };
      cacheUser(userRow, syntheticIdentity);
      return { user: userRow, identity: syntheticIdentity };
    }

    const identityRow = identities[0] as AuthIdentityRow;
    cacheUser(userRow, identityRow);
    return { user: userRow, identity: identityRow };
  } catch {
    return null;
  }
}

/**
 * Queries a user and their identity by user ID.
 */
export async function dbFindUserById(
  userId: string
): Promise<{ user: UserRow; identity: AuthIdentityRow } | null> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    const user = syncCache.usersById.get(userId);
    const identity = syncCache.identitiesByUserId.get(userId);
    if (user && identity) return { user, identity };
    return null;
  }

  try {
    const { data: users, error: userErr } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .limit(1);

    if (userErr || !users || users.length === 0) return null;
    const userRow = users[0] as UserRow;

    const { data: identities } = await supabase
      .from('auth_identities')
      .select('*')
      .eq('user_id', userId)
      .limit(1);

    const identityRow = (identities?.[0] as AuthIdentityRow) || {
      user_id: userRow.id,
      normalized_email: userRow.email,
      normalized_phone: userRow.phone,
      password_salt: null,
      password_hash: null,
      password_changed_at: null,
      sessions_revoked_before: null,
      google_uid: null,
      email_verified: Boolean(userRow.email),
      phone_verified: userRow.phone_verified,
      failed_login_attempts: 0,
      locked_until: null,
      created_at: userRow.created_at,
      updated_at: userRow.created_at,
    };

    cacheUser(userRow, identityRow);
    return { user: userRow, identity: identityRow };
  } catch {
    return null;
  }
}

/**
 * Creates a new user profile and authoritative auth identity in Supabase PostgreSQL.
 * Uses PostgreSQL unique constraints to reject duplicates atomically.
 */
export async function dbCreateUserWithIdentity(params: {
  user: UserRow;
  identity: AuthIdentityRow;
}): Promise<{ ok: true; user: UserProfile } | { ok: false; status: number; error: string }> {
  const supabase = getSupabaseAdminClient();

  // If Supabase is not configured, we fail safely instead of silently writing to /tmp
  if (!supabase) {
    return {
      ok: false,
      status: 503,
      error:
        'Authentication database is not configured. Please set SUPABASE_SERVICE_ROLE_KEY and NEXT_PUBLIC_SUPABASE_URL.',
    };
  }

  try {
    // 1. Insert into public.users table (fails with 23505 if phone/email exists)
    const { error: insertUserError } = await supabase
      .from('users')
      .insert([params.user]);

    if (insertUserError) {
      if (
        insertUserError.code === '23505' ||
        insertUserError.message?.toLowerCase().includes('unique') ||
        insertUserError.message?.toLowerCase().includes('duplicate')
      ) {
        return {
          ok: false,
          status: 409,
          error:
            'An account with this mobile number or email already exists. Please login instead.',
        };
      }
      return {
        ok: false,
        status: 500,
        error: `Database registration error: ${insertUserError.message}`,
      };
    }

    // 2. Insert into public.auth_identities table
    const { error: insertIdentError } = await supabase
      .from('auth_identities')
      .insert([params.identity]);

    if (insertIdentError) {
      // Compensating deletion of user row if identity insert fails
      await supabase.from('users').delete().eq('id', params.user.id);
      return {
        ok: false,
        status: 500,
        error: `Failed to persist authentication identity: ${insertIdentError.message}`,
      };
    }

    cacheUser(params.user, params.identity);
    return { ok: true, user: mapUserRowToProfile(params.user) };
  } catch (err) {
    return {
      ok: false,
      status: 500,
      error: 'Unexpected database failure during user registration.',
    };
  }
}

/**
 * Updates user profile fields in Supabase.
 */
export async function dbUpdateUser(
  userId: string,
  updates: Partial<UserRow>
): Promise<boolean> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) return false;

  try {
    const { error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', userId);

    if (error) return false;

    const cached = syncCache.usersById.get(userId);
    if (cached) {
      Object.assign(cached, updates);
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Updates auth identity fields (password, lock, failed attempts, etc.) in Supabase.
 */
export async function dbUpdateIdentity(
  userId: string,
  updates: Partial<AuthIdentityRow>
): Promise<boolean> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) return false;

  try {
    const payload = {
      ...updates,
      updated_at: new Date().toISOString(),
    };

    const { error } = await supabase
      .from('auth_identities')
      .update(payload)
      .eq('user_id', userId);

    if (error) return false;

    const cached = syncCache.identitiesByUserId.get(userId);
    if (cached) {
      Object.assign(cached, payload);
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Saves a new session into public.user_sessions table.
 */
export async function dbSaveSession(session: UserSessionRow): Promise<boolean> {
  const supabase = getSupabaseAdminClient();
  syncCache.sessionsByJti.set(session.jti, session);

  if (!supabase) return true;

  try {
    const { error } = await supabase.from('user_sessions').insert([session]);
    return !error;
  } catch {
    return false;
  }
}

/**
 * Fetches an authoritative session record from Supabase by JTI.
 */
export async function dbGetSession(
  jti: string
): Promise<UserSessionRow | null> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    return syncCache.sessionsByJti.get(jti) || null;
  }

  try {
    const { data, error } = await supabase
      .from('user_sessions')
      .select('*')
      .eq('jti', jti)
      .limit(1);

    if (error || !data || data.length === 0) {
      return syncCache.sessionsByJti.get(jti) || null;
    }

    const row = data[0] as UserSessionRow;
    syncCache.sessionsByJti.set(jti, row);
    return row;
  } catch {
    return syncCache.sessionsByJti.get(jti) || null;
  }
}

/**
 * Updates a session in public.user_sessions.
 */
export async function dbUpdateSession(
  jti: string,
  updates: Partial<UserSessionRow>
): Promise<boolean> {
  const cached = syncCache.sessionsByJti.get(jti);
  if (cached) Object.assign(cached, updates);

  const supabase = getSupabaseAdminClient();
  if (!supabase) return true;

  try {
    const { error } = await supabase
      .from('user_sessions')
      .update(updates)
      .eq('jti', jti);

    return !error;
  } catch {
    return false;
  }
}

/**
 * Revokes all sessions belonging to a specific session family (e.g. On reuse detection).
 */
export async function dbRevokeSessionFamily(
  familyId: string,
  reason = 'token_reuse_detected'
): Promise<void> {
  const nowIso = new Date().toISOString();

  for (const sess of syncCache.sessionsByJti.values()) {
    if (sess.family_id === familyId) {
      sess.status = 'compromised';
      sess.revoked_at = nowIso;
      sess.revoke_reason = reason;
    }
  }

  const supabase = getSupabaseAdminClient();
  if (!supabase) return;

  try {
    await supabase
      .from('user_sessions')
      .update({
        status: 'compromised',
        revoked_at: nowIso,
        revoke_reason: reason,
      })
      .eq('family_id', familyId);
  } catch {
    // Non-blocking background error
  }
}

/**
 * Revokes all sessions for a specific user ID.
 */
export async function dbRevokeAllUserSessions(
  userId: string,
  exceptJti?: string,
  reason = 'sign_out_all_sessions'
): Promise<void> {
  const nowIso = new Date().toISOString();

  for (const sess of syncCache.sessionsByJti.values()) {
    if (sess.user_id === userId && sess.jti !== exceptJti) {
      sess.status = 'revoked';
      sess.revoked_at = nowIso;
      sess.revoke_reason = reason;
    }
  }

  const supabase = getSupabaseAdminClient();
  if (!supabase) return;

  try {
    let query = supabase
      .from('user_sessions')
      .update({
        status: 'revoked',
        revoked_at: nowIso,
        revoke_reason: reason,
      })
      .eq('user_id', userId)
      .in('status', ['active', 'rotated']);

    if (exceptJti) {
      query = query.neq('jti', exceptJti);
    }

    await query;

    // Record session invalidation timestamp in auth_identities
    await supabase
      .from('auth_identities')
      .update({ sessions_revoked_before: nowIso })
      .eq('user_id', userId);
  } catch {
    // Non-blocking
  }
}

/**
 * Saves a new OTP challenge in public.otp_challenges table.
 */
export async function dbSaveOtpChallenge(
  challenge: OtpChallengeRow
): Promise<boolean> {
  syncCache.otpChallengesByPhone.set(challenge.phone, challenge);

  const supabase = getSupabaseAdminClient();
  if (!supabase) return true;

  try {
    const { error } = await supabase
      .from('otp_challenges')
      .insert([challenge]);

    return !error;
  } catch {
    return false;
  }
}

/**
 * Fetches the latest active OTP challenge for a phone number.
 */
export async function dbGetOtpChallenge(
  phone: string
): Promise<OtpChallengeRow | null> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    return syncCache.otpChallengesByPhone.get(phone) || null;
  }

  try {
    const { data, error } = await supabase
      .from('otp_challenges')
      .select('*')
      .eq('phone', phone)
      .order('created_at', { ascending: false })
      .limit(1);

    if (error || !data || data.length === 0) {
      return syncCache.otpChallengesByPhone.get(phone) || null;
    }

    const row = data[0] as OtpChallengeRow;
    syncCache.otpChallengesByPhone.set(phone, row);
    return row;
  } catch {
    return syncCache.otpChallengesByPhone.get(phone) || null;
  }
}

/**
 * Updates an OTP challenge in public.otp_challenges.
 */
export async function dbUpdateOtpChallenge(
  challengeId: string,
  updates: Partial<OtpChallengeRow>
): Promise<boolean> {
  for (const row of syncCache.otpChallengesByPhone.values()) {
    if (row.challenge_id === challengeId) {
      Object.assign(row, updates);
    }
  }

  const supabase = getSupabaseAdminClient();
  if (!supabase) return true;

  try {
    const { error } = await supabase
      .from('otp_challenges')
      .update(updates)
      .eq('challenge_id', challengeId);

    return !error;
  } catch {
    return false;
  }
}

/**
 * Invalidates any existing active OTP challenges for a phone number or user.
 */
export async function dbInvalidateActiveOtpChallenges(
  phone: string,
  userId: string
): Promise<void> {
  for (const row of syncCache.otpChallengesByPhone.values()) {
    if (
      (row.phone === phone || row.user_id === userId) &&
      row.status === 'active'
    ) {
      row.status = 'superseded';
    }
  }

  const supabase = getSupabaseAdminClient();
  if (!supabase) return;

  try {
    await supabase
      .from('otp_challenges')
      .update({ status: 'superseded' })
      .or(`phone.eq.${phone},user_id.eq.${userId}`)
      .eq('status', 'active');
  } catch {
    // Non-blocking
  }
}

/**
 * Saves a password reset token in public.password_reset_tokens table.
 */
export async function dbSavePasswordResetToken(
  tokenRow: PasswordResetTokenRow
): Promise<boolean> {
  syncCache.passwordResetTokensByResetId.set(tokenRow.reset_id, tokenRow);

  const supabase = getSupabaseAdminClient();
  if (!supabase) return true;

  try {
    const { error } = await supabase
      .from('password_reset_tokens')
      .insert([tokenRow]);

    return !error;
  } catch {
    return false;
  }
}

/**
 * Fetches a password reset token from Supabase by resetId.
 */
export async function dbGetPasswordResetToken(
  resetId: string
): Promise<PasswordResetTokenRow | null> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) {
    return syncCache.passwordResetTokensByResetId.get(resetId) || null;
  }

  try {
    const { data, error } = await supabase
      .from('password_reset_tokens')
      .select('*')
      .eq('reset_id', resetId)
      .limit(1);

    if (error || !data || data.length === 0) {
      return syncCache.passwordResetTokensByResetId.get(resetId) || null;
    }

    const row = data[0] as PasswordResetTokenRow;
    syncCache.passwordResetTokensByResetId.set(resetId, row);
    return row;
  } catch {
    return syncCache.passwordResetTokensByResetId.get(resetId) || null;
  }
}

/**
 * Updates a password reset token in public.password_reset_tokens.
 */
export async function dbUpdatePasswordResetToken(
  resetId: string,
  updates: Partial<PasswordResetTokenRow>
): Promise<boolean> {
  const cached = syncCache.passwordResetTokensByResetId.get(resetId);
  if (cached) Object.assign(cached, updates);

  const supabase = getSupabaseAdminClient();
  if (!supabase) return true;

  try {
    const { error } = await supabase
      .from('password_reset_tokens')
      .update(updates)
      .eq('reset_id', resetId);

    return !error;
  } catch {
    return false;
  }
}

/**
 * Inserts an immutable audit log entry in public.audit_logs.
 */
export async function dbRecordAuditLog(log: AuditLogRow): Promise<void> {
  const supabase = getSupabaseAdminClient();
  if (!supabase) return;

  try {
    await supabase.from('audit_logs').insert([log]);
  } catch {
    // Non-blocking
  }
}

/**
 * Synchronous read helpers for fast lookup
 */
export function getCachedUserById(userId: string): UserProfile | null {
  const row = syncCache.usersById.get(userId);
  return row ? mapUserRowToProfile(row) : null;
}

export function getCachedUserCount(): number {
  return syncCache.usersById.size;
}

export function getCachedSessionCount(): number {
  return syncCache.sessionsByJti.size;
}

function cacheUser(user: UserRow, identity: AuthIdentityRow): void {
  syncCache.usersById.set(user.id, user);
  syncCache.usersByPhone.set(user.phone, user.id);
  if (user.email) {
    syncCache.usersByEmail.set(user.email.toLowerCase(), user.id);
  }
  syncCache.identitiesByUserId.set(user.id, identity);
}
