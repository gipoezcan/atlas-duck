import type { Lang } from './index';

const LOCALE: Record<Lang, string> = { en: 'en-US', de: 'de-DE' };

const DE_DATE_TIME = new Intl.DateTimeFormat('de-DE', {
  timeZone: 'UTC',
  day: '2-digit',
  month: '2-digit',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
});

/**
 * A Unix time in seconds as UTC date and time with the suffix " UTC" (PD-298):
 * `1970-01-01 00:00 UTC` in English, `01.01.1970, 00:00 UTC` in German.
 */
export function formatDateTime(lang: Lang, secs: number): string {
  const date = new Date(secs * 1000);
  if (lang === 'de') return `${DE_DATE_TIME.format(date)} UTC`;
  return `${date.toISOString().replace('T', ' ').slice(0, 16)} UTC`;
}

export function formatNumber(lang: Lang, n: number): string {
  return new Intl.NumberFormat(LOCALE[lang]).format(n);
}

/** A byte count with a 1024-based B/KB/MB/GB unit and at most one decimal. */
export function formatBytes(lang: Lang, n: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const text = new Intl.NumberFormat(LOCALE[lang], { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(value);
  return `${text} ${units[unit]}`;
}