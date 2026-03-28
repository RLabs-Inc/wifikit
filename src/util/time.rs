// Time utilities — local clock formatting without heavy dependencies.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format the current local time as HH:MM:SS.
/// Uses libc localtime_r for timezone-aware formatting on Unix systems.
///
/// # Safety rationale
/// Uses `unsafe` for libc::localtime_r FFI — not USB register access,
/// but required for timezone conversion without adding chrono dependency.
/// Safety is guaranteed because:
/// - `epoch_secs` is a valid time_t from SystemTime
/// - `tm` is properly zeroed before use
/// - localtime_r is thread-safe (unlike localtime)
pub fn local_clock_hms() -> String {
    let epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;

    // SAFETY: tm is zeroed, epoch_secs is valid, localtime_r is thread-safe.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&epoch_secs, &mut tm); }

    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// Format the current local time as YYYYMMDD-HHMMSS for use in filenames.
///
/// # Safety rationale
/// Same as `local_clock_hms` — uses libc::localtime_r for timezone conversion.
pub fn local_datetime_file_stamp() -> String {
    let epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&epoch_secs, &mut tm); }

    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_clock_hms_format() {
        let clock = local_clock_hms();
        // Should be HH:MM:SS format
        assert_eq!(clock.len(), 8);
        assert_eq!(&clock[2..3], ":");
        assert_eq!(&clock[5..6], ":");
        // Hours, minutes, seconds should be valid
        let h: u32 = clock[0..2].parse().unwrap();
        let m: u32 = clock[3..5].parse().unwrap();
        let s: u32 = clock[6..8].parse().unwrap();
        assert!(h < 24);
        assert!(m < 60);
        assert!(s < 60);
    }

    #[test]
    fn test_local_datetime_file_stamp_format() {
        let stamp = local_datetime_file_stamp();
        // Should be YYYYMMDD-HHMMSS format (15 chars)
        assert_eq!(stamp.len(), 15);
        assert_eq!(&stamp[8..9], "-");
        // Year should be >= 2024
        let year: u32 = stamp[0..4].parse().unwrap();
        assert!(year >= 2024);
    }
}
