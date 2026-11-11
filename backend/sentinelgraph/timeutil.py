"""Time normalization.

The whole tool hinges on honest timestamps. We never invent a timestamp:
if parsing fails or the field is absent, ts_utc stays NULL and ts_status says
why. That distinction is surfaced in the timeline UI.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

# Formats seen in the log exports we actually support.
_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
    "%b %d %Y %H:%M:%S",
]

# Windows EVTX CSV export uses US locale strings like:
#   "11/3/2026 9:14:22 AM"
_WIN_FORMATS = [
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M %p",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
]

# Syslog style without year: "Nov  3 09:14:22"
_SYSLOG_FORMAT = "%b %d %H:%M:%S"

ASSUMED_TZ = timezone(timedelta(hours=7))  # WIB: labelled as 'assumed', never 'ok'


def normalize_ts(raw: str | None, source_tz: str | None = None) -> tuple[str | None, str]:
    """Return (iso_utc_or_None, status).

    status is one of:
      ok       - parsed with explicit timezone information
      assumed  - parsed as naive time, interpreted using a declared timezone
      invalid  - present but unparseable
      missing  - absent / empty
    """
    if raw is None:
        return None, "missing"
    text = str(raw).strip()
    if not text:
        return None, "missing"

    # Numeric epoch seconds or milliseconds
    if text.isdigit():
        try:
            num = int(text)
            if num > 10**12:  # milliseconds
                num = num / 1000.0
            elif num < 10**8:
                raise ValueError
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            return _iso(dt), "ok"
        except (ValueError, OSError, OverflowError):
            pass

    candidates = list(_FORMATS) + list(_WIN_FORMATS)
    for fmt in candidates:
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            tz = _tz_from_name(source_tz) or ASSUMED_TZ
            dt = dt.replace(tzinfo=tz)
            return _iso(dt), "assumed"
        return _iso(dt.astimezone(timezone.utc)), "ok"

    # Syslog without year -> assume current year, mark assumed
    for fmt in (_SYSLOG_FORMAT,):
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        now = datetime.now(tz=ASSUMED_TZ)
        dt = dt.replace(year=now.year, tzinfo=ASSUMED_TZ)
        if dt > now + timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        return _iso(dt.astimezone(timezone.utc)), "assumed"

    # ISO with offset like +0700 handled above; try fromisoformat as last resort
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_tz_from_name(source_tz) or ASSUMED_TZ)
            return _iso(dt.astimezone(timezone.utc)), "assumed"
        return _iso(dt.astimezone(timezone.utc)), "ok"
    except ValueError:
        return None, "invalid"


def _tz_from_name(name: str | None) -> timezone | None:
    if not name:
        return None
    mapping = {
        "utc": timezone.utc,
        "wib": ASSUMED_TZ,
        "asia/jakarta": ASSUMED_TZ,
        "ict": timezone(timedelta(hours=7)),
        "gmt": timezone.utc,
    }
    return mapping.get(name.strip().lower())


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def now_iso() -> str:
    return _iso(datetime.now(tz=timezone.utc))


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def seconds_between(a: str | None, b: str | None) -> float | None:
    da, dbb = parse_iso(a), parse_iso(b)
    if da is None or dbb is None:
        return None
    return abs((dbb - da).total_seconds())
