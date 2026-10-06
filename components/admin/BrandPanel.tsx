'use client';

import React, { useState } from 'react';
import { Image as ImageIcon, Upload, RotateCcw, Loader2 } from 'lucide-react';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export function BrandPanel() {
  const { brandLogo, setBrandLogo, resetBrandLogo } = useUyanixStore();
  const [isUpdating, setIsUpdating] = useState(false);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml'];
    if (!allowedTypes.includes(file.type)) {
      toast.error('Only PNG, JPG, WEBP, or SVG images are allowed.');
      return;
    }

    if (file.size > 2 * 1024 * 1024) {
      toast.error('Max 2MB image allowed!');
      return;
    }

    setIsUpdating(true);
    const toastId = toast.loading('Uploading and setting brand logo on server...');

    const reader = new FileReader();
    reader.onload = async () => {
      if (typeof reader.result === 'string') {
        try {
          const success = await setBrandLogo(reader.result);
          if (success) {
            toast.success('Brand logo updated and persisted on server! 🎨', { id: toastId });
          } else {
            toast.error('Failed to update brand logo on server.', { id: toastId });
          }
        } catch {
          toast.error('Network error updating brand logo', { id: toastId });
        } finally {
          setIsUpdating(false);
        }
      }
    };
    reader.readAsDataURL(file);
    e.target.value = '';
  };

  const handleReset = async () => {
    if (isUpdating) return;
    setIsUpdating(true);
    const toastId = toast.loading('Resetting brand logo on server...');
    try {
      const success = await resetBrandLogo();
      if (success) {
        toast.success('Brand logo reset to default on server! 🔄', { id: toastId });
      } else {
        toast.error('Failed to reset brand logo on server.', { id: toastId });
      }
    } catch {
      toast.error('Network error resetting brand logo.', { id: toastId });
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
      <div className="flex items-center gap-2">
        <ImageIcon className="h-5 w-5 text-primary" aria-hidden="true" />
        <h2 className="text-xl font-bold">Brand Logo</h2>
      </div>

      <p className="mt-1 text-sm text-muted-foreground">
        Header, footer aur register pages me apply hoga. Server authoritative storage.
      </p>

      <div className="mt-5 flex flex-wrap items-center gap-5">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          alt="Current logo"
          referrerPolicy="no-referrer"
          className="h-20 w-20 rounded-2xl border border-border object-cover shadow-soft"
          src={brandLogo || '/uyanix-logo.jpg'}
        />

        <div className="flex flex-wrap gap-3">
          <label
            className={`inline-flex h-10 cursor-pointer items-center gap-2 rounded-full bg-gradient-hero px-4 text-sm font-semibold text-primary-foreground shadow-soft ${
              isUpdating ? 'opacity-50 pointer-events-none' : ''
            }`}
          >
            {isUpdating ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Upload className="h-4 w-4" aria-hidden="true" />
            )}
            Upload new logo
            <input
              accept="image/png,image/jpeg,image/webp,image/svg+xml"
              type="file"
              disabled={isUpdating}
              onChange={handleUpload}
              className="hidden"
            />
          </label>

          <button
            type="button"
            disabled={isUpdating}
            onClick={handleReset}
            className="inline-flex h-10 items-center gap-2 rounded-full border border-border px-4 text-sm font-semibold hover:bg-accent disabled:opacity-50"
          >
            <RotateCcw className="h-4 w-4" aria-hidden="true" /> Reset to default
          </button>
        </div>
      </div>

      <p className="mt-3 text-[11px] text-muted-foreground">
        PNG/JPG/WEBP/SVG, max 2MB. Square images dikhte best hain.
      </p>
    </div>
  );
}
