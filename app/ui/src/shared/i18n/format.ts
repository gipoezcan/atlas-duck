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

/** An RFC 3339 timestamp as UTC date and time (see ormatDateTime); text that is not one is returned as it is. */
export function formatTimestamp(lang: Lang, rfc3339: string): string {
  const ms = Date.parse(rfc3339);
  return Number.isNaN(ms) ? rfc3339 : formatDateTime(lang, ms / 1000);
}

export function formatNumber(lang: Lang, n: number): string {
  return new Intl.NumberFormat(LOCALE[lang]).format(n);
}

/**
 * A byte count with a 1024-based unit (B, KiB, MiB, GiB, TiB) and at most one
 * decimal. The unit is chosen after rounding: 1048575 B is "1 MiB", never
 * "1,024 KiB".
 */
export function formatBytes(lang: Lang, n: number): string {
  const format = new Intl.NumberFormat(LOCALE[lang], { maximumFractionDigits: 1 });
  if (n < 1024) return `${format.format(n)} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = n / 1024;
  let unit = 0;
  while (Math.round(value * 10) >= 10240 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${format.format(value)} ${units[unit]}`;
}
