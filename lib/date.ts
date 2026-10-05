const IST_TIMEZONE = 'Asia/Kolkata';

export function getISTDate(date: Date = new Date()): Date {
  const istString = date.toLocaleString('en-US', { timeZone: IST_TIMEZONE });
  return new Date(istString);
}

export function getISTDayStart(date: Date = new Date()): Date {
  const ist = getISTDate(date);
  ist.setHours(0, 0, 0, 0);
  return ist;
}

export function isSameISTDay(a: Date, b: Date): boolean {
  const aIST = getISTDate(a);
  const bIST = getISTDate(b);
  return (
    aIST.getFullYear() === bIST.getFullYear() &&
    aIST.getMonth() === bIST.getMonth() &&
    aIST.getDate() === bIST.getDate()
  );
}

export function getStreakDayIndex(startDate: Date, currentDate: Date = new Date()): number {
  const start = getISTDayStart(startDate).getTime();
  const current = getISTDayStart(currentDate).getTime();
  const diffDays = Math.floor((current - start) / (1000 * 60 * 60 * 24));
  return diffDays + 1;
}

export function formatISTDate(date: Date, options?: Intl.DateTimeFormatOptions): string {
  return new Intl.DateTimeFormat('en-IN', {
    timeZone: IST_TIMEZONE,
    ...options,
  }).format(date);
}
