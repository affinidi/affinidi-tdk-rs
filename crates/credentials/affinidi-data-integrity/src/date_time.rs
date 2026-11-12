//! Strict `xsd:dateTimeStamp` parsing for proof timestamps such as `expires`.
//!
//! VC Data Integrity 1.0 §2.1 types `expires` as an
//! [XMLSCHEMA11-2] `dateTimeStamp`: a date-time that always carries a time
//! zone, either `Z` or a `+hh:mm` / `-hh:mm` offset. `chrono`'s general
//! parsers are deliberately lenient (lowercase `t`/`z`, a space separator,
//! leap seconds, offsets past ±14:00), and a value only some implementations
//! accept is a value two verifiers can disagree about. This parser accepts
//! exactly:
//!
//! ```text
//! YYYY-MM-DDThh:mm:ss[.f+](Z|(+|-)hh:mm)
//! ```
//!
//! with month 01-12, a day that exists in that month (leap years included),
//! hour 00-23, minute and second 00-59, and an offset of at most 14:00.
//!
//! [XMLSCHEMA11-2]: https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveTime, Utc};

const MAX_OFFSET_HOURS: u32 = 14;

/// Parses `value` as an `xsd:dateTimeStamp`, returning it in UTC, or a short
/// description of what is wrong with it.
pub(crate) fn parse_date_time_stamp(value: &str) -> Result<DateTime<Utc>, String> {
    let bytes = value.as_bytes();
    let mut cursor = Cursor { bytes, position: 0 };

    let year = cursor.number(4, "year")?;
    cursor.expect(b'-')?;
    let month = cursor.number(2, "month")?;
    cursor.expect(b'-')?;
    let day = cursor.number(2, "day")?;
    cursor.expect(b'T')?;
    let hour = cursor.number(2, "hour")?;
    cursor.expect(b':')?;
    let minute = cursor.number(2, "minute")?;
    cursor.expect(b':')?;
    let second = cursor.number(2, "second")?;
    let nanosecond = cursor.fraction()?;
    let offset_seconds = cursor.offset()?;
    if cursor.position != bytes.len() {
        return Err("unexpected characters after the time zone".to_string());
    }

    if !(1..=12).contains(&month) {
        return Err(format!("month {month:02} is out of range"));
    }
    let date = NaiveDate::from_ymd_opt(year as i32, month, day)
        .ok_or_else(|| format!("day {day:02} does not exist in {year:04}-{month:02}"))?;
    if hour > 23 {
        return Err(format!("hour {hour:02} is out of range"));
    }
    if minute > 59 {
        return Err(format!("minute {minute:02} is out of range"));
    }
    if second > 59 {
        return Err(format!("second {second:02} is out of range"));
    }
    let time = NaiveTime::from_hms_nano_opt(hour, minute, second, nanosecond)
        .ok_or_else(|| "time of day is out of range".to_string())?;
    let offset = FixedOffset::east_opt(offset_seconds)
        .ok_or_else(|| "time zone offset is out of range".to_string())?;

    date.and_time(time)
        .and_local_timezone(offset)
        .single()
        .map(|local| local.with_timezone(&Utc))
        .ok_or_else(|| "date-time is out of range".to_string())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn expect(&mut self, wanted: u8) -> Result<(), String> {
        match self.peek() {
            Some(found) if found == wanted => {
                self.position += 1;
                Ok(())
            }
            Some(found) => Err(format!(
                "expected '{}' at position {}, found '{}'",
                wanted as char,
                self.position,
                found.escape_ascii()
            )),
            None => Err(format!(
                "expected '{}' at position {}, found the end of the value",
                wanted as char, self.position
            )),
        }
    }

    fn number(&mut self, width: usize, field: &str) -> Result<u32, String> {
        let end = self.position + width;
        let digits = self
            .bytes
            .get(self.position..end)
            .filter(|digits| digits.iter().all(u8::is_ascii_digit))
            .ok_or_else(|| format!("{field} must be {width} digits"))?;
        self.position = end;
        Ok(digits
            .iter()
            .fold(0, |total, digit| total * 10 + u32::from(digit - b'0')))
    }

    /// Optional `.f+`; digits past nanosecond precision are accepted and
    /// truncated.
    fn fraction(&mut self) -> Result<u32, String> {
        if self.peek() != Some(b'.') {
            return Ok(0);
        }
        self.position += 1;
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        let digits = &self.bytes[start..self.position];
        if digits.is_empty() {
            return Err("fractional seconds must have at least one digit".to_string());
        }
        let mut nanosecond = 0;
        for place in 0..9 {
            let digit = digits.get(place).map_or(0, |digit| u32::from(digit - b'0'));
            nanosecond = nanosecond * 10 + digit;
        }
        Ok(nanosecond)
    }

    /// `Z` or `(+|-)hh:mm`, as seconds east of UTC. The time zone is
    /// required: a `dateTimeStamp` without one is malformed.
    fn offset(&mut self) -> Result<i32, String> {
        let sign = match self.peek() {
            Some(b'Z') => {
                self.position += 1;
                return Ok(0);
            }
            Some(b'+') => 1,
            Some(b'-') => -1,
            _ => return Err("a time zone ('Z' or '+hh:mm' / '-hh:mm') is required".to_string()),
        };
        self.position += 1;
        let hours = self.number(2, "offset hour")?;
        self.expect(b':')?;
        let minutes = self.number(2, "offset minute")?;
        if minutes > 59 {
            return Err(format!("offset minute {minutes:02} is out of range"));
        }
        if hours > MAX_OFFSET_HOURS || (hours == MAX_OFFSET_HOURS && minutes != 0) {
            return Err(format!(
                "offset {hours:02}:{minutes:02} is beyond the maximum of 14:00"
            ));
        }
        Ok(sign * (hours * 3600 + minutes * 60) as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_date_time_stamp;
    use chrono::{TimeZone, Utc};

    #[test]
    fn accepts_utc_and_offsets() {
        let expected = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        assert_eq!(
            parse_date_time_stamp("2026-03-01T12:00:00Z").unwrap(),
            expected
        );
        assert_eq!(
            parse_date_time_stamp("2026-03-01T14:00:00+02:00").unwrap(),
            expected
        );
        assert_eq!(
            parse_date_time_stamp("2026-03-01T07:30:00-04:30").unwrap(),
            expected
        );
        assert_eq!(
            parse_date_time_stamp("2026-03-02T02:00:00+14:00").unwrap(),
            expected
        );
        assert_eq!(
            parse_date_time_stamp("2026-02-28T22:00:00-14:00").unwrap(),
            expected
        );
        assert_eq!(
            parse_date_time_stamp("2026-03-01T12:00:00-00:00").unwrap(),
            expected
        );
    }

    #[test]
    fn accepts_fractional_seconds() {
        let parsed = parse_date_time_stamp("2026-03-01T12:00:00.123456789123Z").unwrap();
        assert_eq!(
            parsed,
            Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap()
                + chrono::TimeDelta::nanoseconds(123_456_789)
        );
        let parsed = parse_date_time_stamp("2026-03-01T12:00:00.5Z").unwrap();
        assert_eq!(parsed.timestamp_subsec_millis(), 500);
    }

    #[test]
    fn accepts_february_29_in_leap_years_only() {
        assert!(parse_date_time_stamp("2024-02-29T00:00:00Z").is_ok());
        assert!(parse_date_time_stamp("2000-02-29T00:00:00Z").is_ok());
        assert!(parse_date_time_stamp("2026-02-29T00:00:00Z").is_err());
        assert!(parse_date_time_stamp("1900-02-29T00:00:00Z").is_err());
    }

    #[test]
    fn rejects_out_of_range_fields() {
        for value in [
            "2026-00-10T00:00:00Z",
            "2026-13-10T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-06-31T00:00:00Z",
            "2026-01-10T24:00:00Z",
            "2026-01-10T23:60:00Z",
            "2026-01-10T23:59:60Z",
            "2026-01-10T23:59:59+14:01",
            "2026-01-10T23:59:59-15:00",
            "2026-01-10T23:59:59+02:60",
        ] {
            assert!(
                parse_date_time_stamp(value).is_err(),
                "{value} must be refused"
            );
        }
    }

    #[test]
    fn rejects_malformed_shapes() {
        for value in [
            "",
            "2026-01-10",
            "2026-01-10T00:00:00",
            "2026-01-10t00:00:00Z",
            "2026-01-10T00:00:00z",
            "2026-01-10 00:00:00Z",
            "2026-1-10T00:00:00Z",
            "26-01-10T00:00:00Z",
            "+2026-01-10T00:00:00Z",
            "2026-01-10T00:00Z",
            "2026-01-10T00:00:00.Z",
            "2026-01-10T00:00:00+0200",
            "2026-01-10T00:00:00+02",
            "2026-01-10T00:00:00Z ",
            "2026-01-10T00:00:00ZZ",
            "２０２６-01-10T00:00:00Z",
            "not a date",
        ] {
            assert!(
                parse_date_time_stamp(value).is_err(),
                "{value:?} must be refused"
            );
        }
    }
}
