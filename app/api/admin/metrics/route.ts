import { NextRequest, NextResponse } from 'next/server';
import { requireAuthoritativeAdmin } from '@/lib/server-auth';
import {
  getAuthoritativeAdminMetrics,
  getAuthoritativeAdminAnalytics,
} from '@/lib/admin-authoritative-service';

export async function GET(req: NextRequest) {
  const auth = await requireAuthoritativeAdmin(req);
  if (!auth.ok) {
    return auth.response;
  }

  try {
    const [metrics, analytics] = await Promise.all([
      getAuthoritativeAdminMetrics(),
      getAuthoritativeAdminAnalytics(7),
    ]);

    return NextResponse.json(
      {
        ok: true,
        metrics,
        analytics,
      },
      {
        status: 200,
        headers: { 'Cache-Control': 'private, no-cache, no-store' },
      }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to query admin metrics';
    return NextResponse.json(
      { ok: false, error: message, errorCode: 'METRICS_QUERY_FAILED' },
      { status: 500 }
    );
  }
}
