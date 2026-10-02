import { NextRequest, NextResponse } from 'next/server';
import {
  enforceRateLimit,
  getClientIp,
  requireTeacherOrAdmin,
} from '@/lib/server-auth';
import { appendImmutableAdminAuditEvent } from '@/lib/admin-control-plane-governance';
import {
  authorizeGoogleResourceOperation,
  disconnectAndRevokeGoogleIntegration,
  executeAuthoritativeGoogleSyncJob,
  registerAuthorizedGoogleResource,
  validateAndExecuteGoogleSheetImport,
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
  const rate = enforceRateLimit(`sheets_get:${ip}:${guard.user.id}`, 30, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Google Sheets API rate limit exceeded.' },
      { status: 429 }
    );
  }

  const token = req.headers.get('Authorization');
  if (!token || !token.startsWith('Bearer ')) {
    return NextResponse.json({ error: 'Unauthorized: Missing Bearer token' }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(req.url);
    const spreadsheetId = searchParams.get('spreadsheetId');
    const range = searchParams.get('range');

    if (!spreadsheetId) {
      return NextResponse.json({ error: 'Missing spreadsheetId parameter' }, { status: 400 });
    }

    const authz = authorizeGoogleResourceOperation({
      actorId: guard.user.id,
      actorRole: guard.user.role,
      accessToken: token,
      resourceId: spreadsheetId,
      resourceType: 'SPREADSHEET',
      operation: 'READ',
      sheetTabName: range || undefined,
    });
    if (!authz.authorized) {
      return NextResponse.json(
        { error: authz.reason, errorCode: authz.errorCode },
        { status: authz.httpStatus }
      );
    }

    if (!range) {
      const upstreamUrl = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}`;
      const ssrfCheck = validateGoogleUpstreamUrlAgainstSsrf(upstreamUrl);
      if (!ssrfCheck.ok) {
        return NextResponse.json(
          { error: ssrfCheck.reason, errorCode: ssrfCheck.errorCode },
          { status: ssrfCheck.httpStatus }
        );
      }

      const metaRes = await fetch(ssrfCheck.safeUrl, {
        headers: { Authorization: token },
      });
      const metaData = await metaRes.json();
      if (!metaRes.ok) {
        return NextResponse.json(
          { error: metaData.error?.message || 'Failed to fetch spreadsheet metadata' },
          { status: metaRes.status }
        );
      }
      return NextResponse.json(metaData);
    }

    const valuesUrl = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(
      spreadsheetId
    )}/values/${encodeURIComponent(range)}`;
    const ssrfValuesCheck = validateGoogleUpstreamUrlAgainstSsrf(valuesUrl);
    if (!ssrfValuesCheck.ok) {
      return NextResponse.json(
        { error: ssrfValuesCheck.reason, errorCode: ssrfValuesCheck.errorCode },
        { status: ssrfValuesCheck.httpStatus }
      );
    }

    const valuesRes = await fetch(ssrfValuesCheck.safeUrl, {
      headers: { Authorization: token },
    });
    const valuesData = await valuesRes.json();
    if (!valuesRes.ok) {
      return NextResponse.json(
        { error: valuesData.error?.message || 'Failed to read spreadsheet range' },
        { status: valuesRes.status }
      );
    }

    return NextResponse.json(valuesData);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
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
  const rate = enforceRateLimit(`sheets_post:${ip}:${guard.user.id}`, 20, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: 'Google Sheets mutation rate limit exceeded.' },
      { status: 429 }
    );
  }

  const token = req.headers.get('Authorization');
  if (!token || !token.startsWith('Bearer ')) {
    return NextResponse.json({ error: 'Unauthorized: Missing Bearer token' }, { status: 401 });
  }

  try {
    const body = await req.json();
    const { action, spreadsheetId, range, values, title, sheets } = body;

    if (action === 'disconnect') {
      const revoked = disconnectAndRevokeGoogleIntegration({
        userId: guard.user.id,
        actorRole: guard.user.role,
        accessTokenToRevoke: token.replace(/^Bearer\s+/i, '').trim(),
        reason: body.reason || 'User requested Google integration disconnect',
      });
      return NextResponse.json(revoked, { status: 200 });
    }

    if (action === 'import_validate') {
      const result = validateAndExecuteGoogleSheetImport({
        actorId: guard.user.id,
        actorRole: guard.user.role,
        spreadsheetId: String(spreadsheetId || ''),
        sheetTab: body.sheetTab || 'Chapters',
        headers: Array.isArray(body.headers) ? body.headers : [],
        rows: Array.isArray(body.rows) ? body.rows : [],
        allowAdminResultImportWithApprovalId: body.approvalId,
      });
      return NextResponse.json(result, { status: result.httpStatus });
    }

    if (action === 'sync_job') {
      const syncRes = executeAuthoritativeGoogleSyncJob({
        actorId: guard.user.id,
        actorRole: guard.user.role,
        spreadsheetId: String(spreadsheetId || ''),
        domain: body.domain || 'CHAPTERS',
        externalRevision: Number(body.externalRevision ?? 1),
        currentApprovedRevision:
          body.currentApprovedRevision !== undefined
            ? Number(body.currentApprovedRevision)
            : undefined,
        attemptOverwriteAuthoritativeUyanixDomainFromGoogle: Boolean(
          body.attemptOverwriteAuthoritativeUyanixDomainFromGoogle
        ),
        totalRecords: Number(body.totalRecords ?? 0),
        failedRecordCount: Number(body.failedRecordCount ?? 0),
        idempotencyKey: body.idempotencyKey,
      });
      return NextResponse.json(syncRes, { status: syncRes.httpStatus });
    }

    appendImmutableAdminAuditEvent({
      actorId: guard.user.id,
      actorRole: guard.user.role,
      action: `GOOGLE_SHEETS_${String(action || 'SYNC').toUpperCase()}`,
      resourceType: 'GOOGLE_SPREADSHEET',
      resourceId: String(spreadsheetId || title || 'NEW_SPREADSHEET'),
      reason: `Google Sheets operation '${action}' executed`,
      result: 'ALLOW',
    });

    if (action === 'create') {
      const sheetTabs = Array.isArray(sheets) && sheets.length > 0
        ? sheets.map((tabTitle: string) => ({ properties: { title: tabTitle } }))
        : [
            { properties: { title: 'Leaderboard' } },
            { properties: { title: 'ExamQuestions' } },
            { properties: { title: 'Chapters' } },
            { properties: { title: 'Teachers' } },
          ];

      const createUrl = 'https://sheets.googleapis.com/v4/spreadsheets';
      const ssrfCreate = validateGoogleUpstreamUrlAgainstSsrf(createUrl);
      if (!ssrfCreate.ok) {
        return NextResponse.json(
          { error: ssrfCreate.reason, errorCode: ssrfCreate.errorCode },
          { status: ssrfCreate.httpStatus }
        );
      }

      const createRes = await fetch(ssrfCreate.safeUrl, {
        method: 'POST',
        headers: {
          Authorization: token,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          properties: {
            title: title || `Uyanix 30 Days Challenge — Master Sheet (${new Date().toISOString().slice(0, 10)})`,
          },
          sheets: sheetTabs,
        }),
      });

      const created = await createRes.json();
      if (!createRes.ok) {
        return NextResponse.json(
          { error: created.error?.message || 'Failed to create Google Spreadsheet' },
          { status: createRes.status }
        );
      }

      if (created.spreadsheetId) {
        registerAuthorizedGoogleResource({
          resourceId: String(created.spreadsheetId),
          resourceType: 'SPREADSHEET',
          ownerUserId: guard.user.id,
          ownerRole: guard.user.role,
          purpose: 'MASTER_SHEET',
        });
      }

      if (created.spreadsheetId && range && Array.isArray(values) && values.length > 0) {
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(
            created.spreadsheetId
          )}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`,
          {
            method: 'PUT',
            headers: {
              Authorization: token,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ values }),
          }
        );
      }

      return NextResponse.json(created);
    }

    if (!spreadsheetId || !range) {
      return NextResponse.json(
        { error: 'spreadsheetId and range are required' },
        { status: 400 }
      );
    }

    const authzWrite = authorizeGoogleResourceOperation({
      actorId: guard.user.id,
      actorRole: guard.user.role,
      accessToken: token,
      resourceId: String(spreadsheetId),
      resourceType: 'SPREADSHEET',
      operation: 'WRITE',
      sheetTabName: String(range),
    });
    if (!authzWrite.authorized) {
      return NextResponse.json(
        { error: authzWrite.reason, errorCode: authzWrite.errorCode },
        { status: authzWrite.httpStatus }
      );
    }

    if (action === 'update') {
      await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(
          spreadsheetId
        )}/values/${encodeURIComponent(range)}:clear`,
        {
          method: 'POST',
          headers: {
            Authorization: token,
            'Content-Type': 'application/json',
          },
        }
      );

      const updateRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(
          spreadsheetId
        )}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`,
        {
          method: 'PUT',
          headers: {
            Authorization: token,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ values: values || [] }),
        }
      );

      const updateData = await updateRes.json();
      if (!updateRes.ok) {
        return NextResponse.json(
          { error: updateData.error?.message || 'Failed to update Google Sheet values' },
          { status: updateRes.status }
        );
      }
      return NextResponse.json(updateData);
    }

    if (action === 'append') {
      const appendRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(
          spreadsheetId
        )}/values/${encodeURIComponent(range)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`,
        {
          method: 'POST',
          headers: {
            Authorization: token,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ values: values || [] }),
        }
      );

      const appendData = await appendRes.json();
      if (!appendRes.ok) {
        return NextResponse.json(
          { error: appendData.error?.message || 'Failed to append rows to Google Sheet' },
          { status: appendRes.status }
        );
      }
      return NextResponse.json(appendData);
    }

    if (action === 'clear') {
      const clearRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(
          spreadsheetId
        )}/values/${encodeURIComponent(range)}:clear`,
        {
          method: 'POST',
          headers: {
            Authorization: token,
            'Content-Type': 'application/json',
          },
        }
      );

      const clearData = await clearRes.json();
      if (!clearRes.ok) {
        return NextResponse.json(
          { error: clearData.error?.message || 'Failed to clear Google Sheet range' },
          { status: clearRes.status }
        );
      }
      return NextResponse.json(clearData);
    }

    return NextResponse.json({ error: 'Invalid action specified' }, { status: 400 });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
