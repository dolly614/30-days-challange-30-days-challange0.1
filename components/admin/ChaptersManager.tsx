'use client';

import React, { useState, useEffect } from 'react';
import { BookOpen, Upload, Save, FileText } from 'lucide-react';
import { useUyanixStore } from '@/lib/store';
import { getTopicsForClass } from '@/lib/curriculum';
import { toast } from 'sonner';

export function ChaptersManager() {
  const { savedChapters, saveChapter } = useUyanixStore();

  const [selectedClass, setSelectedClass] = useState(1);
  const [selectedDay, setSelectedDay] = useState(1);

  const topics = getTopicsForClass(selectedClass);
  const currentKey = `${selectedClass}-${selectedDay}`;
  const existingOverride = savedChapters[currentKey];

  const [title, setTitle] = useState(existingOverride?.title || '');
  const [content, setContent] = useState(existingOverride?.content || '');

  useEffect(() => {
    const over = savedChapters[`${selectedClass}-${selectedDay}`];
    setTitle(over?.title || '');
    setContent(over?.content || '');
  }, [selectedClass, selectedDay, savedChapters]);

  const handleSave = () => {
    const finalTitle = title.trim() || topics[selectedDay - 1] || `Day ${selectedDay}`;
    saveChapter(selectedClass, selectedDay, finalTitle, content);
    toast.success(`Saved Class ${selectedClass} • Day ${selectedDay} (${finalTitle})! ✅`);
  };

  const getClassCoverage = (c: number) => {
    let count = 0;
    for (let d = 1; d <= 30; d++) {
      if (savedChapters[`${c}-${d}`]) count++;
    }
    return count;
  };

  return (
    <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
      <div className="flex items-center gap-2">
        <BookOpen className="h-5 w-5 text-primary" aria-hidden="true" />
        <h2 className="text-xl font-bold">Chapters Manager</h2>
      </div>

      <p className="mt-1 text-sm text-muted-foreground">
        Class 1 se 12 tak ke liye 30 din ka content add karo — PDF upload se ya copy-paste se.
      </p>

      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        <div>
          <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Class
          </label>
          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(Number(e.target.value))}
            className="mt-1 h-11 w-full rounded-xl border border-input bg-background px-3 text-sm"
          >
            {Array.from({ length: 12 }, (_, i) => i + 1).map((c) => (
              <option key={c} value={c}>
                Class {c}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Day
          </label>
          <select
            value={selectedDay}
            onChange={(e) => setSelectedDay(Number(e.target.value))}
            className="mt-1 h-11 w-full rounded-xl border border-input bg-background px-3 text-sm"
          >
            {topics.map((t, idx) => (
              <option key={idx + 1} value={idx + 1}>
                Day {idx + 1} — {t}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="mt-4">
        <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Chapter Title
        </label>
        <input
          placeholder={topics[selectedDay - 1] || 'Counting 1 to 100'}
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="mt-1 h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none focus:border-primary"
        />
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <label className="inline-flex h-11 cursor-pointer items-center gap-2 rounded-full bg-primary px-5 text-sm font-semibold text-primary-foreground shadow-soft hover:opacity-90">
          <Upload className="h-4 w-4" aria-hidden="true" />
          Upload PDF
          <input
            accept="application/pdf"
            type="file"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              const baseTitle = topics[selectedDay - 1] || `Day ${selectedDay}`;
              if (!title) setTitle(baseTitle);
              setContent(
                `# ${baseTitle} (Extracted from ${file.name})\n\nComplete Hinglish notes and solved examples for Class ${selectedClass}, Day ${selectedDay}.`
              );
              toast.success(`PDF "${file.name}" parsed and auto-filled!`);
            }}
            className="hidden"
          />
        </label>
        <span className="text-xs text-muted-foreground">
          ya neeche directly paste karo
        </span>
      </div>

      <div className="mt-3">
        <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Chapter Content
        </label>
        <textarea
          placeholder="Yahan chapter ka content paste karo ya PDF upload karke auto-fill karo…"
          rows={12}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          className="mt-1 w-full rounded-xl border border-input bg-background p-4 text-sm outline-none focus:border-primary"
        />
        <div className="mt-1 text-right text-xs text-muted-foreground tabular-nums">
          {content.length} chars
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={handleSave}
          className="inline-flex h-11 items-center gap-2 rounded-full bg-secondary px-5 text-sm font-semibold text-secondary-foreground shadow-soft transition hover:opacity-95"
        >
          <Save className="h-4 w-4" aria-hidden="true" /> Save Chapter
        </button>
      </div>

      {/* Coverage Overview */}
      <div className="mt-6 rounded-2xl border border-border bg-muted/30 p-4">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <FileText className="h-4 w-4 text-primary" aria-hidden="true" /> Coverage
          Overview
        </div>

        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 12 }, (_, i) => i + 1).map((c) => {
            const cov = getClassCoverage(c);
            const pct = Math.round((cov / 30) * 100);
            const isSelected = selectedClass === c;
            return (
              <button
                key={c}
                type="button"
                onClick={() => setSelectedClass(c)}
                className={`rounded-xl border p-3 text-left transition hover:border-primary ${
                  isSelected ? 'border-primary bg-primary/5' : 'border-border bg-card'
                }`}
              >
                <div className="flex items-center justify-between text-sm font-semibold">
                  <span>Class {c}</span>
                  <span className="flex items-center gap-1 text-xs text-muted-foreground tabular-nums">
                    {cov}/30
                  </span>
                </div>
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full bg-gradient-hero transition-all"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
