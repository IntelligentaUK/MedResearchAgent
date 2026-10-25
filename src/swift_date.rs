//! Dates in `library.json` use Swift's default `JSONEncoder` strategy: a number of seconds
//! since 2001-01-01T00:00:00Z. The file is shared with the Swift `DementiaResearch` app, so
//! dates are always written in that form. Reading also accepts RFC 3339 strings, which
//! earlier builds of this port wrote.
//!
//! Use with `#[serde(with = "crate::swift_date")]`, or `crate::swift_date::option` together
//! with `default` for `Option<DateTime<Utc>>` fields.

use chrono::{DateTime, TimeZone, Utc};
use serde::{de, Deserialize, Deserializer, Serializer};

/// 2001-01-01T00:00:00Z as a Unix timestamp.
const REFERENCE_UNIX_SECONDS: i64 = 978_307_200;
const NANOS_PER_SECOND: i64 = 1_000_000_000;
/// Keeps nanosecond arithmetic within `i64` (roughly ±285 years around 2001).
const MAXIMUM_OFFSET_SECONDS: f64 = 9.0e9;

pub fn to_seconds(date: &DateTime<Utc>) -> f64 {
    let seconds = date.timestamp() - REFERENCE_UNIX_SECONDS;
    seconds as f64 + f64::from(date.timestamp_subsec_nanos()) / NANOS_PER_SECOND as f64
}

pub fn from_seconds(seconds: f64) -> Option<DateTime<Utc>> {
    if !seconds.is_finite() || seconds.abs() > MAXIMUM_OFFSET_SECONDS {
        return None;
    }
    // Split before scaling: `seconds * 1e9` alone would round to the nearest 128 ns for
    // present-day dates, so values would not survive a round trip unchanged.
    let whole = seconds.floor();
    let nanos = ((seconds - whole) * NANOS_PER_SECOND as f64).round() as i64;
    let total = (REFERENCE_UNIX_SECONDS + whole as i64) * NANOS_PER_SECOND + nanos;
    Some(Utc.timestamp_nanos(total))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawDate {
    Seconds(f64),
    Text(String),
}

fn parse<E: de::Error>(raw: RawDate) -> Result<DateTime<Utc>, E> {
    match raw {
        RawDate::Seconds(seconds) => from_seconds(seconds)
            .ok_or_else(|| E::custom(format!("date {seconds} is out of range"))),
        RawDate::Text(text) => DateTime::parse_from_rfc3339(&text)
            .map(|date| date.with_timezone(&Utc))
            .map_err(|e| E::custom(format!("invalid date {text:?}: {e}"))),
    }
}

pub fn serialize<S: Serializer>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_f64(to_seconds(date))
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<DateTime<Utc>, D::Error> {
    parse(RawDate::deserialize(deserializer)?)
}

pub mod option {
    use super::{parse, to_seconds, RawDate};
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        date: &Option<DateTime<Utc>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match date {
            Some(date) => serializer.serialize_some(&to_seconds(date)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<DateTime<Utc>>, D::Error> {
        Option::<RawDate>::deserialize(deserializer)?
            .map(parse)
            .transpose()
    }
}
