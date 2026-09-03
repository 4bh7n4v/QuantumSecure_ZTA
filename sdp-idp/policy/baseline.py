"""Baseline Policy Engine + Policy Administrator for the IDP.

This is deliberately a small subset of the SDP Controller's full Policy
Engine (which does posture scoring, resource ACLs and micro-segmentation).
The IDP's baseline PE/PA only makes the anomaly calls it can make at
token-issue and token-refresh time:

  1. Impossible travel / geo-velocity — if this request's location is
     physically unreachable from the user's previous successful request in
     the elapsed time, deny and revoke.
  2. Time-window access — a user may only authenticate inside their
     assigned schedule (users.access_window).

Milestone 1 wires the CALL SITES and logging only; both checks currently
`allow` and log. The impossible-travel maths and schedule parsing land in
Milestone 4, at which point only this file changes.
"""

from __future__ import annotations

from dataclasses import dataclass

from store import events
from store.users import User
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Policy")

# Fastest plausible point-to-point travel, used by the M4 impossible-travel
# check. ~900 km/h cruising + slack.
MAX_TRAVEL_KMH = 1000.0


@dataclass
class PolicyResult:
    allowed: bool
    reason: str


def check_login(user: User, source_ip: str | None, source_geo: str | None) -> PolicyResult:
    """Called after the first factor passes, before the FIDO2 ceremony."""
    status(log, "Baseline PE: evaluating login", username=user.username,
           source_ip=source_ip, source_geo=source_geo,
           access_window=user.access_window or "(none)")

    window = _check_time_window(user)
    if not window.allowed:
        status(log, "Baseline PE: login DENIED", username=user.username, reason=window.reason)
        return window

    status(log, "Baseline PE: login allowed", username=user.username)
    return PolicyResult(allowed=True, reason="ok")


def check_refresh(user_id: str, username: str, device_id: str,
                  source_ip: str | None, source_geo: str | None,
                  prev_ip: str | None, prev_geo: str | None,
                  seconds_since_prev: float | None) -> PolicyResult:
    """Called on POST /token/refresh, before a new access token is minted."""
    status(log, "Baseline PE: evaluating refresh", username=username, device_id=device_id,
           source_ip=source_ip, source_geo=source_geo,
           prev_ip=prev_ip, prev_geo=prev_geo,
           seconds_since_prev=None if seconds_since_prev is None else round(seconds_since_prev))

    travel = _check_impossible_travel(source_geo, prev_geo, seconds_since_prev)
    if not travel.allowed:
        status(log, "Baseline PE: refresh DENIED", username=username, reason=travel.reason)
        events.record("token_refresh", "denied", user_id=user_id, username=username,
                      device_id=device_id, source_ip=source_ip, source_geo=source_geo,
                      detail=travel.reason)
        return travel

    status(log, "Baseline PE: refresh allowed", username=username)
    return PolicyResult(allowed=True, reason="ok")


# --------------------------------------------------------------------------- #
# Individual checks — M1 stubs, real logic in M4                              #
# --------------------------------------------------------------------------- #

def _check_time_window(user: User) -> PolicyResult:
    if not user.access_window:
        return PolicyResult(allowed=True, reason="no window configured")
    # M4: parse `user.access_window` (e.g. "mon-fri 09:00-18:00 Asia/Kolkata")
    # and compare against now.
    status(log, "Baseline PA: time-window check is a no-op until Milestone 4",
           window=user.access_window)
    return PolicyResult(allowed=True, reason="time-window enforcement pending (M4)")


def _check_impossible_travel(cur_geo: str | None, prev_geo: str | None,
                             seconds_since_prev: float | None) -> PolicyResult:
    if not cur_geo or not prev_geo or seconds_since_prev is None:
        status(log, "Baseline PE: impossible-travel check skipped (no geo data yet)")
        return PolicyResult(allowed=True, reason="insufficient geo data")
    # M4: parse "lat,lon" from cur_geo/prev_geo, haversine distance, compare
    # implied speed against MAX_TRAVEL_KMH.
    status(log, "Baseline PE: impossible-travel maths lands in Milestone 4")
    return PolicyResult(allowed=True, reason="impossible-travel enforcement pending (M4)")
