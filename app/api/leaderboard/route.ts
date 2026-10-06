import { NextRequest, NextResponse } from 'next/server';
import {
  getClientIp,
  getSessionUserFromRequest,
} from '@/lib/server-auth';
import {
  queryAuthoritativeLeaderboard,
  getAuthenticatedStudentSelfRank,
} from '@/lib/leaderboard-integrity-governance';
import { getSupabaseAdminClient } from '@/lib/supabase-server';

export async function GET(req: NextRequest) {
  const ip = getClientIp(req);
  const searchParams = req.nextUrl.searchParams;

  const classFilter = searchParams.get('class');
  const searchQuery = searchParams.get('search');
  const cursor = searchParams.get('cursor');
  const pageSize = searchParams.get('pageSize') || '25';

  const user = getSessionUserFromRequest(req);

  // 1. First, check if database has active exam/progress rankings
  const result = queryAuthoritativeLeaderboard({
    classFilter: classFilter || 'all',
    searchQuery: searchQuery || undefined,
    cursor: cursor || undefined,
    pageSize: Math.min(50, Number(pageSize) || 25),
    clientIp: ip,
  });

  if (!result.ok) {
    return NextResponse.json(
      { ok: false, error: result.reason, errorCode: result.errorCode },
      { status: result.httpStatus }
    );
  }

  // 2. If student is authenticated, get their self-rank
  let selfRank = null;
  if (user) {
    selfRank = getAuthenticatedStudentSelfRank({
      studentId: user.id,
      nowMs: Date.now(),
    });
  }

  return NextResponse.json(
    {
      ok: true,
      entries: result.entries,
      totalMatching: result.totalMatching,
      nextCursor: result.nextCursor,
      selfRank: selfRank?.selfRank || null,
      rankingPolicyVersion: result.rankingPolicyVersion,
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'public, max-age=15, stale-while-revalidate=30',
      },
    }
  );
}
