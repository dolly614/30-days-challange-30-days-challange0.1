'use client';

import React from 'react';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export function StudentVerifications() {
  const { verifications, handleVerification } = useUyanixStore();
  const pendingList = verifications.filter((v) => v.status === 'pending');

  return (
    <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold">Student ID Verifications</h2>
        <span className="rounded-full bg-primary/10 px-3 py-1 text-xs font-semibold text-primary tabular-nums">
          {pendingList.length} pending
        </span>
      </div>

      {pendingList.length === 0 ? (
        <p className="mt-4 text-sm text-muted-foreground">
          Abhi koi pending verification nahi hai.
        </p>
      ) : (
        <div className="mt-4 space-y-3">
          {pendingList.map((v) => (
            <div
              key={v.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-border p-4 text-sm"
            >
              <div>
                <div className="font-semibold">
                  {v.studentName} • Class {v.classNum}
                </div>
                <div className="text-xs text-muted-foreground">
                  {v.school} • Document: <span className="font-mono">{v.documentName}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    handleVerification(v.id, 'approved');
                    toast.success(`Approved ${v.studentName}'s Student ID`);
                  }}
                  className="rounded-full bg-secondary px-4 py-1.5 text-xs font-semibold text-secondary-foreground"
                >
                  Approve
                </button>
                <button
                  type="button"
                  onClick={() => {
                    handleVerification(v.id, 'rejected');
                    toast.error(`Rejected ${v.studentName}'s ID`);
                  }}
                  className="rounded-full border border-destructive px-4 py-1.5 text-xs font-semibold text-destructive"
                >
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
