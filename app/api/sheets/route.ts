import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const token = req.headers.get('Authorization');
  if (!token) {
    return NextResponse.json({ error: 'Unauthorized: Missing Bearer token' }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(req.url);
    const spreadsheetId = searchParams.get('spreadsheetId');
    const range = searchParams.get('range');

    if (!spreadsheetId) {
      return NextResponse.json({ error: 'Missing spreadsheetId parameter' }, { status: 400 });
    }

    // If range is omitted, fetch spreadsheet metadata (including sheet/tab titles)
    if (!range) {
      const metaRes = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}`,
        {
          headers: { Authorization: token },
        }
      );
      const metaData = await metaRes.json();
      if (!metaRes.ok) {
        return NextResponse.json(
          { error: metaData.error?.message || 'Failed to fetch spreadsheet metadata' },
          { status: metaRes.status }
        );
      }
      return NextResponse.json(metaData);
    }

    // Fetch values for the specific sheet tab / range
    const valuesRes = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(
        spreadsheetId
      )}/values/${encodeURIComponent(range)}`,
      {
        headers: { Authorization: token },
      }
    );
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
  const token = req.headers.get('Authorization');
  if (!token) {
    return NextResponse.json({ error: 'Unauthorized: Missing Bearer token' }, { status: 401 });
  }

  try {
    const body = await req.json();
    const { action, spreadsheetId, range, values, title, sheets } = body;

    // 1. Create a brand new Google Spreadsheet
    if (action === 'create') {
      const sheetTabs = Array.isArray(sheets) && sheets.length > 0
        ? sheets.map((tabTitle: string) => ({ properties: { title: tabTitle } }))
        : [
            { properties: { title: 'Leaderboard' } },
            { properties: { title: 'ExamQuestions' } },
            { properties: { title: 'Chapters' } },
            { properties: { title: 'Teachers' } },
          ];

      const createRes = await fetch('https://sheets.googleapis.com/v4/spreadsheets', {
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

      // If initial values were provided for a specific range, populate them
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

    // 2. Overwrite / Update values in a range
    if (action === 'update') {
      // Clear first so leftover trailing rows are removed cleanly, then write
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

    // 3. Append rows to a sheet tab
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

    // 4. Clear a sheet tab / range
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
