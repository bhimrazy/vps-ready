//! Transaction IDs: the UTC start time, `20261023T114246Z`, with `-2`, `-3`
//! appended when that directory already exists.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch now, or 0 if the clock is before it.
#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The base ID for `at` (Unix seconds): `YYYYMMDDTHHMMSSZ` in UTC.
#[must_use]
pub fn base_id(at: u64) -> String {
    let (days, secs) = (at / 86_400, at % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// The `n`-th ID for `base`: `base` itself for 1, `base-n` after that.
#[must_use]
pub fn nth_id(base: &str, n: u32) -> String {
    if n <= 1 {
        base.to_owned()
    } else {
        format!("{base}-{n}")
    }
}

/// The sort key of an ID: its base and its number (1 without a suffix), or
/// `None` if `id` is not one. Sorting by this key is sorting by start time,
/// where plain string order would put `-10` before `-2`.
#[must_use]
pub fn sort_key(id: &str) -> Option<(&str, u32)> {
    let (base, n) = match id.split_once('-') {
        Some((base, n)) if !n.starts_with('0') => (base, n.parse().ok().filter(|n| *n >= 2)?),
        Some(_) => return None,
        None => (id, 1),
    };
    let well_formed = base.len() == 16
        && base.bytes().enumerate().all(|(i, b)| match i {
            8 => b == b'T',
            15 => b == b'Z',
            _ => b.is_ascii_digit(),
        });
    well_formed.then_some((base, n))
}

/// The proleptic Gregorian date of `days` since 1970-01-01, after Howard
/// Hinnant's `civil_from_days`.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // Shift the epoch to 0000-03-01 so a leap day is the last day of its year.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, from March 1
    let mp = (5 * doy + 2) / 153; // month from March, [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = era * 400 + yoe + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Days since the epoch, counted day by day, for checking the closed form.
    fn days_from_civil_slow(year: u64, month: u64, day: u64) -> u64 {
        let leap =
            |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
        let month_len = |y, m| match m {
            2 if leap(y) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        let years: u64 = (1970..year).map(|y| if leap(y) { 366 } else { 365 }).sum();
        let months: u64 = (1..month).map(|m| month_len(year, m)).sum();
        years + months + day - 1
    }

    #[test]
    fn known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(
            civil_from_days(days_from_civil_slow(2026, 10, 23)),
            (2026, 10, 23)
        );
        // Leap years: divisible by 4, except centuries not divisible by 400.
        for (y, m, d) in [
            (2000, 2, 29),
            (2000, 3, 1),
            (2024, 2, 29),
            (2024, 12, 31),
            (2100, 2, 28),
            (2100, 3, 1),
            (2400, 2, 29),
        ] {
            assert_eq!(civil_from_days(days_from_civil_slow(y, m, d)), (y, m, d));
        }
    }

    #[test]
    fn every_day_follows_the_previous() {
        let mut prev = civil_from_days(0);
        for days in 1..200_000 {
            let date = civil_from_days(days);
            let (y, m, d) = prev;
            let next_day = (y, m, d + 1);
            let next_month = (y, m + 1, 1);
            let next_year = (y + 1, 1, 1);
            assert!(
                date == next_day
                    || (date == next_month && m < 12)
                    || (date == next_year && m == 12),
                "{prev:?} -> {date:?}"
            );
            prev = date;
        }
    }

    #[test]
    fn formats_utc_ids() {
        assert_eq!(base_id(0), "19700101T000000Z");
        assert_eq!(base_id(1_792_755_766), "20261023T114246Z");
        // The last second of a year and the first of the next.
        assert_eq!(base_id(1_798_761_599), "20261231T235959Z");
        assert_eq!(base_id(1_798_761_600), "20270101T000000Z");
        assert_eq!(base_id(951_782_400), "20000229T000000Z");
    }

    #[test]
    fn sort_keys() {
        let base = "20261023T114246Z";
        assert_eq!(nth_id(base, 1), base);
        assert_eq!(nth_id(base, 3), "20261023T114246Z-3");
        assert_eq!(sort_key(base), Some((base, 1)));
        assert_eq!(sort_key("20261023T114246Z-10"), Some((base, 10)));
        for bad in [
            "20261023T114246Z-1",
            "20261023T114246Z-02",
            "20261023T114246Z-",
            "20261023T114246Z-x",
            "20261023T11424Z",
            "20261023X114246Z",
            "lock",
        ] {
            assert_eq!(sort_key(bad), None, "{bad}");
        }
    }
}
