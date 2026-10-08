//! The injectable clock (C.3), the real `SystemClock`, and the `ClockState` machine that
//! derives `ts_utc`, `epoch` and the clock flags of each record (§8.2, §8.8, L36, L47).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Days, NaiveDate, NaiveDateTime, Utc};

use crate::types::EventFlags;

/// Milliseconds since 1970-01-01T00:00:00Z (F.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcInstant(pub i64);

const RFC3339_MS: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

/// 0000-01-01T00:00:00.000Z and 9999-12-31T23:59:59.999Z: the range whose RFC 3339 text
/// is exactly 24 bytes.
const MIN_TEXT_MS: i64 = -62_167_219_200_000;
const MAX_TEXT_MS: i64 = 253_402_300_799_999;

impl UtcInstant {
    /// `YYYY-MM-DDTHH:MM:SS.mmmZ`, always 24 ASCII bytes (the `ts_utc` column text).
    /// Values outside years 0000..=9999 saturate to the nearest bound (never to 1970); use
    /// [`UtcInstant::try_to_rfc3339_ms`] where an unrepresentable instant must be an error.
    pub fn to_rfc3339_ms(self) -> String {
        self.saturated().format_ms()
    }

    /// As [`UtcInstant::to_rfc3339_ms`], but `None` outside years 0000..=9999.
    pub fn try_to_rfc3339_ms(self) -> Option<String> {
        (MIN_TEXT_MS..=MAX_TEXT_MS)
            .contains(&self.0)
            .then(|| self.format_ms())
    }

    fn saturated(self) -> UtcInstant {
        UtcInstant(self.0.clamp(MIN_TEXT_MS, MAX_TEXT_MS))
    }

    /// Only called with a value inside the text range, which chrono always represents.
    fn format_ms(self) -> String {
        let dt = DateTime::<Utc>::from_timestamp_millis(self.0).unwrap_or(if self.0 < 0 {
            DateTime::<Utc>::MIN_UTC
        } else {
            DateTime::<Utc>::MAX_UTC
        });
        dt.format(RFC3339_MS).to_string()
    }

    /// Strict inverse of [`UtcInstant::to_rfc3339_ms`]: exactly milliseconds and a `Z`.
    pub fn parse_rfc3339_ms(s: &str) -> Option<UtcInstant> {
        if s.len() != 24 || !s.is_ascii() {
            return None;
        }
        let naive = NaiveDateTime::parse_from_str(s, RFC3339_MS).ok()?;
        let t = UtcInstant(naive.and_utc().timestamp_millis());
        (t.to_rfc3339_ms() == s).then_some(t)
    }

    /// The UTC calendar day (the `epoch` column and DEK months derive from it). Saturates
    /// outside years 0000..=9999, like [`UtcInstant::to_rfc3339_ms`].
    pub fn date(self) -> NaiveDate {
        DateTime::<Utc>::from_timestamp_millis(self.saturated().0)
            .map_or(NaiveDate::MIN, |d| d.date_naive())
    }
}

pub trait Clock: Send + Sync {
    /// Wall clock.
    fn now_utc(&self) -> UtcInstant;
    /// CLOCK_BOOTTIME / CLOCK_MONOTONIC on Darwin / Windows interrupt time (V27).
    fn suspend_aware_elapsed(&self) -> Duration;
}

/// The real clocks. `suspend_aware_elapsed` counts time spent asleep (V27) and is measured
/// from construction.
pub struct SystemClock {
    base: Duration,
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock {
            base: raw_suspend_aware(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_utc(&self) -> UtcInstant {
        let ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            Err(e) => i64::try_from(e.duration().as_millis()).map_or(i64::MIN, |m| -m),
        };
        UtcInstant(ms)
    }

    fn suspend_aware_elapsed(&self) -> Duration {
        raw_suspend_aware().saturating_sub(self.base)
    }
}

#[cfg(target_os = "linux")]
fn raw_suspend_aware() -> Duration {
    clock_gettime(libc::CLOCK_BOOTTIME)
}

/// On Darwin `CLOCK_MONOTONIC` keeps counting during sleep (unlike `CLOCK_UPTIME_RAW`).
#[cfg(target_os = "macos")]
fn raw_suspend_aware() -> Duration {
    clock_gettime(libc::CLOCK_MONOTONIC)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn clock_gettime(id: libc::clockid_t) -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the call.
    let rc = unsafe { libc::clock_gettime(id, &mut ts) };
    if rc != 0 {
        return fallback_elapsed();
    }
    Duration::new(
        ts.tv_sec.max(0) as u64,
        ts.tv_nsec.clamp(0, 999_999_999) as u32,
    )
}

/// `QueryInterruptTime` counts 100 ns units and includes time asleep (not the unbiased variant).
#[cfg(windows)]
fn raw_suspend_aware() -> Duration {
    let mut t: u64 = 0;
    // SAFETY: `t` is a valid, writable u64 for the duration of the call.
    unsafe { windows_sys::Win32::System::WindowsProgramming::QueryInterruptTime(&mut t) };
    Duration::from_nanos(t.saturating_mul(100))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn raw_suspend_aware() -> Duration {
    fallback_elapsed()
}

/// Process-relative monotonic time, used only if the OS call fails or the OS is unsupported.
#[cfg(not(windows))]
fn fallback_elapsed() -> Duration {
    use std::sync::OnceLock;
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

/// `date - 1 day`, `None` on underflow (the predicate using it is then false).
fn minus_day(d: NaiveDate) -> Option<NaiveDate> {
    d.checked_sub_days(Days::new(1))
}

pub fn date_of(t: UtcInstant) -> NaiveDate {
    t.date()
}

/// `YYYY-MM-DD`, the `epoch` column text.
pub fn epoch_text(d: NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

/// `YYYY-MM`, the DEK month label.
pub fn month_text(d: NaiveDate) -> String {
    d.format("%Y-%m").to_string()
}

/// Strict inverse of [`epoch_text`].
pub fn parse_epoch(s: &str) -> Option<NaiveDate> {
    if s.len() != 10 || !s.is_ascii() {
        return None;
    }
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    (epoch_text(d) == s).then_some(d)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnomalyKind {
    LocalAhead,
    LocalBehind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockAnomaly {
    pub kind: AnomalyKind,
    pub local: UtcInstant,
    pub server: UtcInstant,
}

/// What `ClockState::stamp` decided for one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub ts_utc: UtcInstant,
    pub epoch: Option<NaiveDate>,
    pub clock_flags: EventFlags,
}

#[derive(Clone, Copy, Debug)]
pub struct Corroboration {
    pub server: UtcInstant,
    pub mono_at: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct ClockState {
    pub(crate) prev_epoch: Option<NaiveDate>, // head record's epoch (NULL possible)
    pub(crate) prev_ts: Option<UtcInstant>,   // head record's ts_utc
    pub(crate) prev_flags: EventFlags,        // head record's flags
    corr: Option<Corroboration>,              // this process only
    ahead_episode: bool,
    behind_episode: bool,
}

impl ClockState {
    /// State at open: the head record's view, no corroboration, no episodes.
    pub fn from_head(epoch: Option<NaiveDate>, ts: UtcInstant, flags: EventFlags) -> Self {
        ClockState {
            prev_epoch: epoch,
            prev_ts: Some(ts),
            prev_flags: flags,
            ..ClockState::default()
        }
    }

    pub fn corroborated_at(&self, mono_now: Duration) -> Option<UtcInstant> {
        self.corr.map(|c| {
            let extra =
                i64::try_from(mono_now.saturating_sub(c.mono_at).as_millis()).unwrap_or(i64::MAX);
            UtcInstant(c.server.0.saturating_add(extra))
        })
    }

    pub fn corroborated_date(&self, mono_now: Duration) -> Option<NaiveDate> {
        self.corroborated_at(mono_now).map(date_of)
    }

    pub fn is_corroborated(&self) -> bool {
        self.corr.is_some()
    }

    /// Source (a): a server Date header (successful, parsed, TLS-verified response; the
    /// caller guarantees it).
    pub fn observe(
        &mut self,
        server: UtcInstant,
        now: UtcInstant,
        mono_now: Duration,
    ) -> Option<ClockAnomaly> {
        let newest = match self.corroborated_at(mono_now) {
            Some(cur) if cur.0 > server.0 => cur,
            _ => server,
        };
        self.corr = Some(Corroboration {
            server: newest,
            mono_at: mono_now,
        });
        let ahead = matches!(
            date_of(server).checked_add_days(Days::new(1)),
            Some(limit) if date_of(now) > limit
        );
        let started = ahead && !self.ahead_episode;
        self.ahead_episode = ahead;
        started.then_some(ClockAnomaly {
            kind: AnomalyKind::LocalAhead,
            local: now,
            server,
        })
    }

    /// Called by the writer before each append batch. Starts/ends the local-behind episode.
    pub fn behind_transition(
        &mut self,
        now: UtcInstant,
        mono_now: Duration,
    ) -> Option<ClockAnomaly> {
        let cd_at = self.corroborated_at(mono_now)?;
        let behind = matches!(minus_day(date_of(cd_at)), Some(l) if date_of(now) < l);
        let started = behind && !self.behind_episode;
        self.behind_episode = behind;
        started.then_some(ClockAnomaly {
            kind: AnomalyKind::LocalBehind,
            local: now,
            server: cd_at,
        })
    }

    /// Stamps one record, in seq order. Mutates the "previous record" view.
    pub fn stamp(&mut self, now: UtcInstant, mono_now: Duration) -> Stamp {
        let today = date_of(now);
        let cd = self.corroborated_date(mono_now);
        let epoch = match cd {
            Some(cd) => {
                let cand = today.min(cd);
                Some(match self.prev_epoch {
                    Some(p) if p > cand => p,
                    _ => cand,
                })
            }
            None => self.prev_epoch,
        };
        let mut flags = EventFlags::default();
        if let Some(p) = self.prev_ts
            && now.0 < p.0.saturating_sub(5_000)
        {
            flags |= EventFlags::BACKWARDS;
        }
        if self.ahead_episode {
            flags |= EventFlags::FORWARD;
        }
        match cd {
            // (a)
            Some(cd) => {
                if matches!(minus_day(cd), Some(l) if today < l) {
                    flags |= EventFlags::BEHIND;
                }
            }
            // (b) (L47: no GENESIS clause)
            None => {
                let cmos = matches!(self.prev_epoch, Some(pe) if today < pe);
                if self.prev_flags.contains(EventFlags::BEHIND) || cmos {
                    flags |= EventFlags::BEHIND;
                }
            }
        }
        self.prev_epoch = epoch;
        self.prev_ts = Some(now);
        self.prev_flags = flags;
        Stamp {
            ts_utc: now,
            epoch,
            clock_flags: flags,
        }
    }
}
