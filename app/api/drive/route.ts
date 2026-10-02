import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  getClientIp,
  requireAdmin,
  requireTeacherOrAdmin,
} from '@/lib/server-auth';
import { appendImmutableAdminAuditEvent } from '@/lib/admin-control-plane-governance';
import {
  authorizeGoogleResourceOperation,
  validateGoogleUpstreamUrlAgainstSsrf,
  validateNoGoogleSecretOrTokenExposure,
} from '@/lib/google-workspace-security-governance';

export async function GET(req: NextRequest) {
  const guard = requireTeacherOrAdmin(req);
  if (!guard.ok) {
    return guard.response;
  }

  const querySafety = validateNoGoogleSecretOrTokenExposure({
    urlQuery: req.nextUrl.search,
  });
  if (!querySafety.safe) {
    return NextResponse.json(
      { error: querySafety.reason, errorCode: querySafety.errorCode },
      { status: querySafety.httpStatus }
    );
  }

  const ip = getClientIp(req);
  const rate = enforceRateLimit(`drive_get:${ip}:${guard.user.id}`, 30, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Google Drive API rate limit exceeded.' },
      { status: 429 }
    );
  }

  const token = req.headers.get('Authorization');
  if (!token || !token.startsWith('Bearer ')) {
    return NextResponse.json({ error: 'Unauthorized: Missing Bearer token' }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(req.url);
    const search = searchParams.get('q') || '';
    const pageSize = searchParams.get('pageSize') || '25';

    let driveQuery = "mimeType='application/vnd.google-apps.spreadsheet' and trashed=false";
    if (search.trim()) {
      const escaped = search.trim().replace(/'/g, "\\'");
      driveQuery += ` and name contains '${escaped}'`;
    }

    const url = new URL('https://www.googleapis.com/drive/v3/files');
    url.searchParams.set('q', driveQuery);
    url.searchParams.set('pageSize', pageSize);
    url.searchParams.set('orderBy', 'modifiedTime desc');
    url.searchParams.set('fields', 'files(id,name,modifiedTime,webViewLink,owners(displayName,emailAddress))');

    const ssrfCheck = validateGoogleUpstreamUrlAgainstSsrf(url.toString());
    if (!ssrfCheck.ok) {
      return NextResponse.json(
        { error: ssrfCheck.reason, errorCode: ssrfCheck.errorCode },
        { status: ssrfCheck.httpStatus }
      );
    }

    const res = await fetch(ssrfCheck.safeUrl, {
      headers: { Authorization: token },
    });

    const data = await res.json();
    if (!res.ok) {
      return NextResponse.json(
        { error: data.error?.message || 'Failed to list Google Drive spreadsheets' },
        { status: res.status }
      );
    }

    return NextResponse.json(data);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  const guard = requireAdmin(req);
  if (!guard.ok) {
    return guard.response;
  }

  const querySafety = validateNoGoogleSecretOrTokenExposure({
    urlQuery: req.nextUrl.search,
  });
  if (!querySafety.safe) {
    return NextResponse.json(
      { error: querySafety.reason, errorCode: querySafety.errorCode },
      { status: querySafety.httpStatus }
    );
  }

  const ip = getClientIp(req);
  const rate = enforceRateLimit(`drive_del:${ip}:${guard.user.id}`, 10, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Google Drive delete rate limit exceeded.' },
      { status: 429 }
    );
  }

  const token = req.headers.get('Authorization');
  if (!token || !token.startsWith('Bearer ')) {
    return NextResponse.json({ error: 'Unauthorized: Missing Bearer token' }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(req.url);
    const fileId = searchParams.get('fileId');
    if (!fileId) {
      return NextResponse.json({ error: 'Missing fileId parameter' }, { status: 400 });
    }

    const authz = authorizeGoogleResourceOperation({
      actorId: guard.user.id,
      actorRole: guard.user.role,
      accessToken: token,
      resourceId: fileId,
      resourceType: 'DRIVE_FILE',
      operation: 'DELETE',
    });
    if (!authz.authorized) {
      return NextResponse.json(
        { error: authz.reason, errorCode: authz.errorCode },
        { status: authz.httpStatus }
      );
    }

    const deleteUrl = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}`;
    const ssrfDelCheck = validateGoogleUpstreamUrlAgainstSsrf(deleteUrl);
    if (!ssrfDelCheck.ok) {
      return NextResponse.json(
        { error: ssrfDelCheck.reason, errorCode: ssrfDelCheck.errorCode },
        { status: ssrfDelCheck.httpStatus }
      );
    }

    const res = await fetch(ssrfDelCheck.safeUrl, {
      method: 'DELETE',
      headers: { Authorization: token },
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return NextResponse.json(
        { error: errData.error?.message || 'Failed to delete file from Google Drive' },
        { status: res.status }
      );
    }

    appendImmutableAdminAuditEvent({
      actorId: guard.user.id,
      actorRole: guard.user.role,
      action: 'GOOGLE_DRIVE_FILE_DELETED',
      resourceType: 'GOOGLE_DRIVE_FILE',
      resourceId: fileId,
      reason: `Deleted Google Drive spreadsheet ${fileId}`,
      result: 'ALLOW',
    });

    return NextResponse.json({ success: true, deletedFileId: fileId });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
