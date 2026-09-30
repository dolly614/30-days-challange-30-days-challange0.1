'use client';

import React from 'react';
import { Image as ImageIcon, Upload, RotateCcw } from 'lucide-react';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

export function BrandPanel() {
  const { brandLogo, setBrandLogo, resetBrandLogo } = useUyanixStore();

  const handleUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      toast.error('Max 2MB image allowed!');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setBrandLogo(reader.result);
        toast.success('Brand logo updated across Header, Footer & Register pages! 🎨');
      }
    };
    reader.readAsDataURL(file);
  };

  return (
    <div className="mt-8 rounded-3xl border border-border bg-card p-6 shadow-card">
      <div className="flex items-center gap-2">
        <ImageIcon className="h-5 w-5 text-primary" aria-hidden="true" />
        <h2 className="text-xl font-bold">Brand Logo</h2>
      </div>

      <p className="mt-1 text-sm text-muted-foreground">
        Header, footer aur register pages me apply hoga.
      </p>

      <div className="mt-5 flex flex-wrap items-center gap-5">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          alt="Current logo"
          referrerPolicy="no-referrer"
          className="h-20 w-20 rounded-2xl border border-border object-cover shadow-soft"
          src={brandLogo}
        />

        <div className="flex flex-wrap gap-3">
          <label className="inline-flex h-10 cursor-pointer items-center gap-2 rounded-full bg-gradient-hero px-4 text-sm font-semibold text-primary-foreground shadow-soft">
            <Upload className="h-4 w-4" aria-hidden="true" /> Upload new logo
            <input
              accept="image/png,image/jpeg,image/webp,image/svg+xml"
              type="file"
              onChange={handleUpload}
              className="hidden"
            />
          </label>

          <button
            type="button"
            onClick={() => {
              resetBrandLogo();
              toast.success('Brand logo reset to default!');
            }}
            className="inline-flex h-10 items-center gap-2 rounded-full border border-border px-4 text-sm font-semibold hover:bg-accent"
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
