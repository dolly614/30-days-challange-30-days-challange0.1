'use client';

import React, { useState } from 'react';
import { useUyanixStore } from '@/lib/store';
import { Flame } from 'lucide-react';

interface BrandMarkProps {
  size?: number;
  className?: string;
}

export function BrandMark({ size = 36, className = '' }: BrandMarkProps) {
  const brandLogo = useUyanixStore((s) => s.brandLogo);
  const [imgError, setImgError] = useState(false);

  if (imgError || !brandLogo) {
    return (
      <div
        style={{ width: size, height: size }}
        className={`inline-flex items-center justify-center rounded-xl bg-gradient-hero text-primary-foreground shadow-soft ring-1 ring-border ${className}`}
      >
        <Flame className="h-5 w-5" />
      </div>
    );
  }

  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      alt="Uyanix logo"
      width={size}
      height={size}
      referrerPolicy="no-referrer"
      onError={() => setImgError(true)}
      className={`rounded-xl object-cover shadow-soft ring-1 ring-border ${className}`}
      src={brandLogo}
      style={{ width: `${size}px`, height: `${size}px` }}
    />
  );
}
