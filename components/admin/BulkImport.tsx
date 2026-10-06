'use client';

import React, { useState } from 'react';
import {
  FileArchive,
  CloudUpload,
  Trash2,
  RotateCcw,
  RefreshCw,
  Loader2,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

interface ZipPreviewItem {
  day: number;
  filename: string;
  title: string;
  size: number;
  contentPreview: string;
}

export function BulkImport() {
  const { bulkSaveChapters, deleteClassChapters, resetAllChapters, refreshChapters } =
    useUyanixStore();

  const [targetClass, setTargetClass] = useState(1);
  const [overwrite, setOverwrite] = useState(true);
  const [selectedDays, setSelectedDays] = useState<number[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isCommitting, setIsCommitting] = useState(false);

  // ZIP Preview State
  const [pendingZipFile, setPendingZipFile] = useState<File | null>(null);
  const [zipPreview, setZipPreview] = useState<ZipPreviewItem[] | null>(null);
  const [zipDuplicates, setZipDuplicates] = useState<number[]>([]);
  const [zipWarnings, setZipWarnings] = useState<string[]>([]);

  const toggleDaySelection = (day: number) => {
    setSelectedDays((prev) =>
      prev.includes(day) ? prev.filter((d) => d !== day) : [...prev, day]
    );
  };

  const handleZipFileSelect = async (file: File | undefined) => {
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.zip') && file.type !== 'application/zip') {
      toast.error('Please select a valid ZIP archive (.zip)');
      return;
    }

    if (file.size > 35 * 1024 * 1024) {
      toast.error('ZIP archive exceeds the maximum 35MB size limit.');
      return;
    }

    setIsProcessing(true);
    setPendingZipFile(file);
    setZipPreview(null);
    setZipDuplicates([]);
    setZipWarnings([]);

    const toastId = toast.loading(`Inspecting & extracting "${file.name}"...`);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('classNum', String(targetClass));
      formData.append('commit', 'false'); // Preview only first

      const res = await fetch('/api/admin/chapters/parse-zip', {
        method: 'POST',
        credentials: 'include',
        body: formData,
      });

      const data = await res.json();
      if (!res.ok || !data.ok) {
        toast.error(data.error || 'Failed to extract ZIP archive', { id: toastId });
        setPendingZipFile(null);
        return;
      }

      setZipPreview(data.preview || []);
      setZipDuplicates(data.duplicates || []);
      setZipWarnings(data.warnings || []);

      toast.success(
        `ZIP extracted: Found ${data.entriesCount} valid PDF chapter(s). Please review and commit to database!`,
        { id: toastId }
      );
    } catch {
      toast.error('Network failure during ZIP extraction', { id: toastId });
      setPendingZipFile(null);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCommitZip = async () => {
    if (!pendingZipFile || isCommitting) return;

    setIsCommitting(true);
    const toastId = toast.loading(`Committing ${zipPreview?.length || 0} chapters to database...`);

    try {
      const formData = new FormData();
      formData.append('file', pendingZipFile);
      formData.append('classNum', String(targetClass));
      formData.append('commit', 'true');
      formData.append('overwrite', String(overwrite));

      const res = await fetch('/api/admin/chapters/parse-zip', {
        method: 'POST',
        credentials: 'include',
        body: formData,
      });

      const data = await res.json();
      if (!res.ok || !data.ok) {
        toast.error(data.error || 'Failed to save chapters to database', { id: toastId });
        return;
      }

      toast.success(
        `Class ${targetClass}: ${data.inserted} inserted, ${data.updated} updated in database! 🎉`,
        { id: toastId }
      );

      // Revalidate
      await refreshChapters(targetClass);
      setPendingZipFile(null);
      setZipPreview(null);
    } catch {
      toast.error('Failed to commit ZIP chapters to server database', { id: toastId });
    } finally {
      setIsCommitting(false);
    }
  };

  const handleFilesUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    setIsProcessing(true);
    const toastId = toast.loading(`Processing ${files.length} PDFs...`);

    const itemsToSave: { day: number; title: string; content: string }[] = [];

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) {
          continue;
        }

        const formData = new FormData();
        formData.append('file', file);

        const res = await fetch('/api/admin/chapters/parse-pdf', {
          method: 'POST',
          credentials: 'include',
          body: formData,
        });

        if (res.ok) {
          const data = await res.json();
          if (data.ok) {
            const detectedDay = i + 1;
            itemsToSave.push({
              day: detectedDay,
              title: file.name.replace(/\.pdf$/i, '').replace(/[_-]+/g, ' '),
              content: data.text,
            });
          }
        }
      }

      if (itemsToSave.length > 0) {
        const savedCount = await bulkSaveChapters(targetClass, itemsToSave, overwrite);
        toast.success(
          `Class ${targetClass}: ${savedCount} chapter(s) saved to authoritative database! 📚`,
          { id: toastId }
        );
        await refreshChapters(targetClass);
      } else {
        toast.error('No valid PDFs could be parsed.', { id: toastId });
      }
    } catch {
      toast.error('Failed to upload and parse PDFs.', { id: toastId });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDeleteClass = async () => {
    if (!confirm(`Kya aap sach mein Class ${targetClass} ke saare custom chapters delete karna chahte hain?`)) {
      return;
    }
    const success = await deleteClassChapters(targetClass);
    if (success) {
      toast.success(`Class ${targetClass} custom chapters deleted from database.`);
      await refreshChapters(targetClass);
    } else {
      toast.error(`Failed to delete Class ${targetClass} chapters.`);
    }
  };

  const handleResetAll = async () => {
    if (!confirm('Warning: Kya aap saari classes ke custom chapters ko database se reset karna chahte hain?')) {
      return;
    }
    const success = await resetAllChapters();
    if (success) {
      toast.success('All classes custom chapters reset to default in database!');
      await refreshChapters();
    } else {
      toast.error('Failed to reset chapters in database.');
    }
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
        Ek class select karo, fir 30 PDFs ek saath upload karo ya ek ZIP daalo. Server archive ko safely inspect karega, PDF text extract karega, aur database transaction ke saath commit karega.
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

        <label
          className={`flex h-11 cursor-pointer items-center justify-center gap-2 self-end rounded-full bg-primary px-4 text-sm font-semibold text-primary-foreground shadow-soft hover:opacity-90 ${
            isProcessing ? 'opacity-50 pointer-events-none' : ''
          }`}
        >
          {isProcessing ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          ) : (
            <CloudUpload className="h-4 w-4" aria-hidden="true" />
          )}
          Upload PDFs (multi-select)
          <input
            accept="application/pdf"
            multiple
            type="file"
            disabled={isProcessing}
            onChange={(e) => handleFilesUpload(e.target.files)}
            className="hidden"
          />
        </label>

        <label
          className={`flex h-11 cursor-pointer items-center justify-center gap-2 self-end rounded-full bg-secondary px-4 text-sm font-semibold text-secondary-foreground shadow-soft hover:opacity-90 ${
            isProcessing ? 'opacity-50 pointer-events-none' : ''
          }`}
        >
          {isProcessing ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          ) : (
            <FileArchive className="h-4 w-4" aria-hidden="true" />
          )}
          {isProcessing ? 'Inspecting ZIP...' : 'Upload Real ZIP'}
          <input
            accept=".zip,application/zip"
            type="file"
            disabled={isProcessing}
            onChange={(e) => handleZipFileSelect(e.target.files?.[0])}
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
          onClick={handleDeleteClass}
          className="inline-flex h-9 items-center gap-2 rounded-full border border-destructive px-4 text-xs font-semibold text-destructive hover:bg-destructive/10"
        >
          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" /> Delete Class{' '}
          {targetClass} Chapters
        </button>

        <button
          type="button"
          onClick={handleResetAll}
          className="inline-flex h-9 items-center gap-2 rounded-full border border-destructive px-4 text-xs font-semibold text-destructive hover:bg-destructive/10"
        >
          <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" /> Reset All Classes
        </button>
      </div>

      {/* ZIP Archive Inspection & Confirmation Preview */}
      {zipPreview && (
        <div className="mt-6 rounded-2xl border-2 border-primary/40 bg-card p-5 shadow-card">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-secondary" />
              <h3 className="text-base font-bold">
                ZIP Inspection Preview — {zipPreview.length} Chapters Extracted
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setZipPreview(null);
                  setPendingZipFile(null);
                }}
                className="h-9 rounded-full border border-border px-3 text-xs font-semibold hover:bg-muted"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={isCommitting}
                onClick={handleCommitZip}
                className="inline-flex h-9 items-center gap-2 rounded-full bg-primary px-4 text-xs font-semibold text-primary-foreground shadow-soft hover:opacity-90 disabled:opacity-50"
              >
                {isCommitting ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-3.5 w-3.5" />
                )}
                {isCommitting ? 'Committing...' : `Commit to Database (Class ${targetClass})`}
              </button>
            </div>
          </div>

          {zipDuplicates.length > 0 && (
            <div className="mt-3 flex items-center gap-2 rounded-xl bg-amber-500/10 p-3 text-xs text-amber-600">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Duplicate day entries detected for Days: {zipDuplicates.join(', ')}. Overwrite rule will apply.</span>
            </div>
          )}

          <div className="mt-4 max-h-56 overflow-y-auto space-y-2 pr-1">
            {zipPreview.map((item) => (
              <div
                key={`${item.day}-${item.filename}`}
                className="flex items-start justify-between rounded-xl border border-border/80 bg-muted/20 p-2.5 text-xs"
              >
                <div>
                  <span className="font-bold text-primary mr-2">Day {item.day}:</span>
                  <span className="font-semibold">{item.title}</span>
                  <span className="text-muted-foreground ml-2 font-mono text-[11px]">
                    ({item.filename} • {Math.round(item.size / 1024)} KB)
                  </span>
                  <p className="mt-1 text-muted-foreground line-clamp-1 italic">
                    {item.contentPreview}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Selective Re-import Grid */}
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
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> Re-import Selected
            <input
              accept="application/pdf"
              multiple
              type="file"
              onChange={(e) => handleFilesUpload(e.target.files)}
              className="hidden"
            />
          </label>
        </div>
      </div>
    </div>
  );
}
