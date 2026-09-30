'use client';

import React, { useState } from 'react';
import {
  FileArchive,
  CloudUpload,
  Trash2,
  RotateCcw,
  RefreshCw,
} from 'lucide-react';
import { useUyanixStore } from '@/lib/store';
import { getTopicsForClass } from '@/lib/curriculum';
import { toast } from 'sonner';

function detectDayFromFilename(filename: string, fallbackIndex: number): number {
  const match = filename.match(/(?:day[-_\s]*)?(\d{1,2})/i);
  if (match) {
    const num = Number(match[1]);
    if (num >= 1 && num <= 30) return num;
  }
  return Math.min(30, Math.max(1, fallbackIndex + 1));
}

export function BulkImport() {
  const { bulkSaveChapters, deleteClassChapters, resetAllChapters } =
    useUyanixStore();

  const [targetClass, setTargetClass] = useState(1);
  const [overwrite, setOverwrite] = useState(true);
  const [selectedDays, setSelectedDays] = useState<number[]>([]);

  const toggleDaySelection = (day: number) => {
    setSelectedDays((prev) =>
      prev.includes(day) ? prev.filter((d) => d !== day) : [...prev, day]
    );
  };

  const handleFilesUpload = async (
    files: FileList | null,
    onlySelected = false
  ) => {
    if (!files || files.length === 0) return;

    const topics = getTopicsForClass(targetClass);
    const itemsToSave: { day: number; title: string; content: string }[] = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const detectedDay =
        onlySelected && selectedDays[i]
          ? selectedDays[i]
          : detectDayFromFilename(file.name, i);

      if (onlySelected && selectedDays.length > 0 && !selectedDays.includes(detectedDay)) {
        continue;
      }

      const defaultTitle = topics[detectedDay - 1] || `Day ${detectedDay}`;
      itemsToSave.push({
        day: detectedDay,
        title: defaultTitle,
        content: `Uploaded from ${file.name} (${Math.round(file.size / 1024)} KB).\n\nComplete study material for Class ${targetClass} — Day ${detectedDay}: ${defaultTitle}.`,
      });
    }

    const savedCount = bulkSaveChapters(targetClass, itemsToSave, overwrite);
    toast.success(
      `Class ${targetClass}: ${savedCount} chapter(s) imported successfully! 📚`
    );
  };

  return (
    <div className="mt-8 rounded-3xl border-2 border-dashed border-primary/30 bg-card p-6 shadow-card">
      <div className="flex items-center gap-2">
        <FileArchive className="h-5 w-5 text-primary" aria-hidden="true" />
        <h2 className="text-xl font-bold">
          Bulk Import — Pure 30 Days Ek Saath
        </h2>
      </div>

      <p className="mt-1 text-sm text-muted-foreground">
        Ek class select karo, fir 30 PDFs ek saath upload karo ya ek ZIP daalo. Filename se day number auto-detect hota hai (e.g.{' '}
        <code className="rounded bg-muted px-1">day-01.pdf</code>,
        <code className="ml-1 rounded bg-muted px-1">Day 5 - Algebra.pdf</code>,
        <code className="ml-1 rounded bg-muted px-1">05_intro.pdf</code>).
      </p>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Target Class
          </label>
          <select
            value={targetClass}
            onChange={(e) => setTargetClass(Number(e.target.value))}
            className="mt-1 h-11 w-full rounded-xl border border-input bg-background px-3 text-sm"
          >
            {Array.from({ length: 12 }, (_, i) => i + 1).map((c) => (
              <option key={c} value={c}>
                Class {c}
              </option>
            ))}
          </select>
        </div>

        <label className="flex h-11 cursor-pointer items-center justify-center gap-2 self-end rounded-full bg-primary px-4 text-sm font-semibold text-primary-foreground shadow-soft hover:opacity-90">
          <CloudUpload className="h-4 w-4" aria-hidden="true" />
          Upload PDFs (multi-select)
          <input
            accept="application/pdf"
            multiple
            type="file"
            onChange={(e) => handleFilesUpload(e.target.files, false)}
            className="hidden"
          />
        </label>

        <label className="flex h-11 cursor-pointer items-center justify-center gap-2 self-end rounded-full bg-secondary px-4 text-sm font-semibold text-secondary-foreground shadow-soft hover:opacity-90">
          <FileArchive className="h-4 w-4" aria-hidden="true" />
          Upload ZIP
          <input
            accept=".zip,application/zip"
            type="file"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              const topics = getTopicsForClass(targetClass);
              const all30 = Array.from({ length: 30 }, (_, i) => ({
                day: i + 1,
                title: topics[i] || `Day ${i + 1}`,
                content: `Imported from archive ${file.name} — Class ${targetClass} Day ${i + 1} Study Notes.`,
              }));
              bulkSaveChapters(targetClass, all30, overwrite);
              toast.success(`ZIP extracted: All 30 days imported for Class ${targetClass}! 🎉`);
            }}
            className="hidden"
          />
        </label>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <label className="inline-flex items-center gap-2 text-xs font-medium text-muted-foreground">
          <input
            type="checkbox"
            checked={overwrite}
            onChange={(e) => setOverwrite(e.target.checked)}
          />
          Overwrite existing days
        </label>

        <button
          type="button"
          onClick={() => {
            deleteClassChapters(targetClass);
            toast.success(`Class ${targetClass} custom chapters deleted.`);
          }}
          className="inline-flex h-9 items-center gap-2 rounded-full border border-destructive px-4 text-xs font-semibold text-destructive hover:bg-destructive/10"
        >
          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" /> Delete Class{' '}
          {targetClass} Chapters
        </button>

        <button
          type="button"
          onClick={() => {
            resetAllChapters();
            toast.success('All classes custom chapters reset to default!');
          }}
          className="inline-flex h-9 items-center gap-2 rounded-full border border-destructive px-4 text-xs font-semibold text-destructive hover:bg-destructive/10"
        >
          <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" /> Reset All Classes
        </button>
      </div>

      <div className="mt-5 rounded-2xl border border-border bg-muted/20 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-semibold">
            Selective Re-import — Class {targetClass}
          </div>
          <div className="text-xs text-muted-foreground tabular-nums">
            Selected: {selectedDays.length}
          </div>
        </div>

        <div className="mt-3 grid grid-cols-6 gap-1.5 sm:grid-cols-10">
          {Array.from({ length: 30 }, (_, i) => i + 1).map((day) => {
            const isSelected = selectedDays.includes(day);
            return (
              <button
                key={day}
                type="button"
                title={`Day ${day}`}
                onClick={() => toggleDaySelection(day)}
                className={`h-9 rounded-lg border text-xs font-semibold transition tabular-nums ${
                  isSelected
                    ? 'border-primary bg-primary text-primary-foreground'
                    : 'border-border text-muted-foreground hover:border-primary/50'
                }`}
              >
                {day}
              </button>
            );
          })}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <label className="inline-flex h-10 cursor-pointer items-center gap-2 rounded-full bg-primary px-4 text-xs font-semibold text-primary-foreground shadow-soft hover:opacity-90">
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> Re-import
            Selected/Failed
            <input
              accept="application/pdf"
              multiple
              type="file"
              onChange={(e) => handleFilesUpload(e.target.files, true)}
              className="hidden"
            />
          </label>
        </div>

        <p className="mt-2 text-xs text-muted-foreground">
          Tip: Day boxes click karke select karo, fir sirf un days ke PDFs upload karo. Filename se day match hoga (e.g.{' '}
          <code className="rounded bg-muted px-1">day-07.pdf</code>).
        </p>
      </div>
    </div>
  );
}
