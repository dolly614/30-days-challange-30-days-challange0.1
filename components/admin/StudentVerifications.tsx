'use client';

import React, { useState } from 'react';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export function StudentVerifications() {
  const { verifications, handleVerification, syncAdminVerifications } = useUyanixStore();
  const [processingId, setProcessingId] = useState<string | null>(null);

  React.useEffect(() => {
    syncAdminVerifications();
  }, [syncAdminVerifications]);

  const pendingList = verifications.filter((v) => v.status === 'pending');

  const onVerificationAction = async (id: string, status: 'approved' | 'rejected', studentName: string) => {
    if (processingId) return;
    setProcessingId(id);
    try {
      const success = await handleVerification(id, status);
      if (success) {
        if (status === 'approved') {
          toast.success(`Approved ${studentName}'s Student ID ✅`);
        } else {
          toast.info(`Rejected ${studentName}'s Student ID`);
        }
      } else {
        toast.error(`Failed to update verification for ${studentName}`);
      }
    } catch {
      toast.error('Network error updating verification');
    } finally {
      setProcessingId(null);
    }
  };

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
                  disabled={processingId === v.id}
                  onClick={() => onVerificationAction(v.id, 'approved', v.studentName)}
                  className="rounded-full bg-secondary px-4 py-1.5 text-xs font-semibold text-secondary-foreground disabled:opacity-50"
                >
                  {processingId === v.id ? 'Updating...' : 'Approve'}
                </button>
                <button
                  type="button"
                  disabled={processingId === v.id}
                  onClick={() => onVerificationAction(v.id, 'rejected', v.studentName)}
                  className="rounded-full border border-destructive px-4 py-1.5 text-xs font-semibold text-destructive disabled:opacity-50"
                >
                  {processingId === v.id ? 'Updating...' : 'Reject'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
