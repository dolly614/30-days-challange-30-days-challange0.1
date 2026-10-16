import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireAdmin } from '@/lib/server-auth';
import {
  getAuthoritativeChapters,
  saveAuthoritativeChapter,
  bulkSaveAuthoritativeChapters,
  deleteClassAuthoritativeChapters,
  resetAllAuthoritativeChapters,
} from '@/lib/admin-authoritative-service';

const saveChapterSchema = z.object({
  action: z.literal('SAVE_CHAPTER'),
  classNum: z.number().int().min(1).max(12),
  day: z.number().int().min(1).max(30),
  title: z.string().trim().min(1).max(120),
  content: z.string().max(100000),
});

const bulkSaveSchema = z.object({
  action: z.literal('BULK_SAVE_CHAPTERS'),
  classNum: z.number().int().min(1).max(12),
  items: z.array(
    z.object({
      day: z.number().int().min(1).max(30),
      title: z.string().trim().min(1).max(120),
      content: z.string().max(100000),
    })
  ).min(1).max(50),
  overwrite: z.boolean().default(true),
});

const deleteClassSchema = z.object({
  action: z.literal('DELETE_CLASS_CHAPTERS'),
  classNum: z.number().int().min(1).max(12),
});

const resetAllSchema = z.object({
  action: z.literal('RESET_ALL_CHAPTERS'),
});

const chapterActionSchema = z.discriminatedUnion('action', [
  saveChapterSchema,
  bulkSaveSchema,
  deleteClassSchema,
  resetAllSchema,
]);

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const classParam = searchParams.get('class');
  const classNum = classParam ? Number(classParam) : undefined;

  try {
    const chapters = await getAuthoritativeChapters(classNum);
    return NextResponse.json({ ok: true, chapters });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to query chapters';
    return NextResponse.json({ ok: false, error: msg }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const auth = requireAdmin(req);
  if (!auth.ok) {
    return auth.response;
  }

  try {
    const raw = await req.json();
    const parsed = chapterActionSchema.safeParse(raw);
    if (!parsed.success) {
      return NextResponse.json(
        {
          ok: false,
          error: 'Validation failed: ' + parsed.error.issues.map((i) => i.message).join(', '),
          errorCode: 'INVALID_INPUT',
        },
        { status: 400 }
      );
    }

    const data = parsed.data;

    if (data.action === 'SAVE_CHAPTER') {
      const chapter = await saveAuthoritativeChapter({
        classNum: data.classNum,
        day: data.day,
        title: data.title,
        content: data.content,
        actorEmail: auth.user.email,
      });
      return NextResponse.json({ ok: true, chapter });
    }

    if (data.action === 'BULK_SAVE_CHAPTERS') {
      const result = await bulkSaveAuthoritativeChapters({
        classNum: data.classNum,
        items: data.items,
        overwrite: data.overwrite,
        actorEmail: auth.user.email,
      });
      return NextResponse.json({ ok: true, ...result });
    }

    if (data.action === 'DELETE_CLASS_CHAPTERS') {
      const result = await deleteClassAuthoritativeChapters(data.classNum, auth.user.email);
      return NextResponse.json({ ok: true, ...result });
    }

    if (data.action === 'RESET_ALL_CHAPTERS') {
      const result = await resetAllAuthoritativeChapters(auth.user.email);
      return NextResponse.json({ ok: true, ...result });
    }

    return NextResponse.json({ ok: false, error: 'Unknown action' }, { status: 400 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Chapter operation failed';
    return NextResponse.json({ ok: false, error: msg, errorCode: 'CHAPTER_OPERATION_FAILED' }, { status: 500 });
  }
}
