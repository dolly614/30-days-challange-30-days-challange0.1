import { NextRequest, NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/server-auth';
import { parsePdfBuffer } from '@/lib/admin-authoritative-service';

export async function POST(req: NextRequest) {
  const auth = requireAdmin(req);
  if (!auth.ok) {
    return auth.response;
  }

  try {
    const formData = await req.formData();
    const file = formData.get('file');

    if (!file || !(file instanceof Blob)) {
      return NextResponse.json(
        { ok: false, error: 'Missing or invalid PDF file in request payload.', errorCode: 'FILE_REQUIRED' },
        { status: 400 }
      );
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Call real PDF parser with magic bytes inspection and sanitization
    const parsed = await parsePdfBuffer(buffer);

    return NextResponse.json({
      ok: true,
      text: parsed.text,
      pageCount: parsed.pageCount,
      fileName: (file as File).name || 'document.pdf',
      fileSize: buffer.length,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'PDF parsing failed';
    return NextResponse.json(
      { ok: false, error: msg, errorCode: 'PDF_PARSE_FAILED' },
      { status: 422 }
    );
  }
}
