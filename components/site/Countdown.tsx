'use client';

import React, { useEffect, useState } from 'react';

interface TimeLeft {
  days: string;
  hours: string;
  mins: string;
  secs: string;
}

export function Countdown() {
  const [timeLeft, setTimeLeft] = useState<TimeLeft>({
    days: '03',
    hours: '14',
    mins: '42',
    secs: '19',
  });

  useEffect(() => {
    const target = Date.now() + (3 * 86400 + 14 * 3600 + 42 * 60 + 19) * 1000;

    const tick = () => {
      const diff = Math.max(0, Math.floor((target - Date.now()) / 1000));
      const d = Math.floor(diff / 86400);
      const h = Math.floor((diff % 86400) / 3600);
      const m = Math.floor((diff % 3600) / 60);
      const s = diff % 60;

      setTimeLeft({
        days: String(d).padStart(2, '0'),
        hours: String(h).padStart(2, '0'),
        mins: String(m).padStart(2, '0'),
        secs: String(s).padStart(2, '0'),
      });
    };

    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  const units = [
    { label: 'Days', value: timeLeft.days },
    { label: 'Hours', value: timeLeft.hours },
    { label: 'Mins', value: timeLeft.mins },
    { label: 'Secs', value: timeLeft.secs },
  ];

  return (
    <div className="flex gap-2 sm:gap-3">
      {units.map((u) => (
        <div
          key={u.label}
          className="card-interactive flex w-16 flex-col items-center rounded-2xl bg-card px-2 py-3 shadow-card sm:w-20"
        >
          <span
            key={`${u.label}-${u.value}`}
            className="animate-pop-in inline-block text-2xl font-bold tabular-nums text-primary sm:text-3xl"
          >
            {u.value}
          </span>
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground sm:text-xs">
            {u.label}
          </span>
        </div>
      ))}
    </div>
  );
}
