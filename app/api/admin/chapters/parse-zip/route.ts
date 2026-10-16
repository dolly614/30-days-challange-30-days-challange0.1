import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/server-auth';
import {
  processZipArchive,
  bulkSaveAuthoritativeChapters,
} from '@/lib/admin-authoritative-service';

export async function POST(req: NextRequest) {
  const auth = requireAdmin(req);
  if (!auth.ok) {
    return auth.response;
  }

  try {
    const formData = await req.formData();
    const file = formData.get('file');
    const classStr = formData.get('classNum');
    const commit = formData.get('commit') === 'true';
    const overwrite = formData.get('overwrite') !== 'false';

    const classNum = Number(classStr || 1);
    if (isNaN(classNum) || classNum < 1 || classNum > 12) {
      return NextResponse.json(
        { ok: false, error: 'Invalid classNum: must be between 1 and 12', errorCode: 'INVALID_CLASS' },
        { status: 400 }
      );
    }

    if (!file || !(file instanceof Blob)) {
      return NextResponse.json(
        { ok: false, error: 'Missing or invalid ZIP file in request payload.', errorCode: 'FILE_REQUIRED' },
        { status: 400 }
      );
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Call real ZIP processor
    const result = await processZipArchive(buffer, classNum);

    if (result.entries.length === 0) {
      return NextResponse.json(
        {
          ok: false,
          error: 'No valid PDF chapter files could be extracted from this ZIP archive.',
          details: result.errors,
          errorCode: 'NO_CHAPTERS_FOUND',
        },
        { status: 422 }
      );
    }

    // If commit is requested, save directly to database
    if (commit) {
      const itemsToSave = result.entries.map((e) => ({
        day: e.day,
        title: e.title,
        content: e.content,
      }));
      const saveResult = await bulkSaveAuthoritativeChapters({
        classNum,
        items: itemsToSave,
        overwrite,
        actorEmail: auth.user.email,
      });

      return NextResponse.json({
        ok: true,
        committed: true,
        classNum,
        totalEntries: result.entries.length,
        ...saveResult,
        duplicates: result.duplicates,
        warnings: result.errors,
      });
    }

    // Otherwise return preview for Admin confirmation
    return NextResponse.json({
      ok: true,
      committed: false,
      classNum,
      entriesCount: result.entries.length,
      duplicates: result.duplicates,
      warnings: result.errors,
      preview: result.entries.map((e) => ({
        day: e.day,
        filename: e.filename,
        title: e.title,
        size: e.size,
        contentPreview: e.content.slice(0, 300) + (e.content.length > 300 ? '...' : ''),
      })),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'ZIP extraction failed';
    return NextResponse.json(
      { ok: false, error: msg, errorCode: 'ZIP_EXTRACTION_FAILED' },
      { status: 422 }
    );
  }
}
