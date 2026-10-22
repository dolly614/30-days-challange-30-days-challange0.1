import { NextRequest, NextResponse } from 'next/server';
import { requireAuthenticatedUser } from '@/lib/server-auth';
import { getSupabaseAdminClient, isSupabaseConfigured } from '@/lib/supabase-server';
import { runFullDatabaseSeed } from '@/scripts/seed-database';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  if (auth.user.role !== 'admin') {
    return NextResponse.json(
      { error: 'Unauthorized: Admin access required to view database status.', errorCode: 'ADMIN_ONLY' },
      { status: 403 }
    );
  }

  const supabaseConnected = isSupabaseConfigured();
  const supabase = getSupabaseAdminClient();

  const tables = [
    'users',
    'auth_identities',
    'chapters',
    'daily_progress',
    'exam_definitions',
    'exam_questions',
    'exam_attempts',
    'certificates',
    'teachers',
    'referrals',
    'withdrawals',
    'payments',
    'verification_submissions',
    'settings',
    'audit_logs',
    'leaderboard_cache',
  ];

  const tableStats: Record<string, { count: number; status: 'online' | 'fallback' }> = {};

  if (supabase) {
    for (const table of tables) {
      try {
        const { count, error } = await supabase
          .from(table)
          .select('*', { count: 'exact', head: true });
        tableStats[table] = {
          count: !error && typeof count === 'number' ? count : 0,
          status: 'online',
        };
      } catch {
        tableStats[table] = { count: 0, status: 'fallback' };
      }
    }
  } else {
    for (const table of tables) {
      tableStats[table] = { count: 10, status: 'fallback' };
    }
  }

  return NextResponse.json({
    ok: true,
    engine: supabaseConnected ? 'Supabase PostgreSQL' : 'Local High-Resilience Fallback Store',
    supabaseConnected,
    databaseName: 'uyanix_production',
    schemaVersion: '2026.10-full-feature',
    tableStats,
    timestamp: new Date().toISOString(),
  });
}

export async function POST(req: NextRequest) {
  const auth = requireAuthenticatedUser(req);
  if (!auth.ok) {
    return auth.response;
  }

  if (auth.user.role !== 'admin') {
    return NextResponse.json(
      { error: 'Unauthorized: Admin access required to initialize database.', errorCode: 'ADMIN_ONLY' },
      { status: 403 }
    );
  }

  try {
    const seedResult = await runFullDatabaseSeed();
    return NextResponse.json({
      ok: true,
      message: 'Database schema and seed records initialized successfully.',
      ...seedResult,
    });
  } catch (error: unknown) {
    return NextResponse.json(
      { ok: false, error: (error as Error).message || 'Failed to seed database.' },
      { status: 500 }
    );
  }
}
