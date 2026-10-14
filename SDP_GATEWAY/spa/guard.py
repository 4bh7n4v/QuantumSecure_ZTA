"""Cheap checks the Gateway runs on a knock before any real work.

Ported from the PULGABLE_ZTNA_V2 Gateway's "PEP shielding": a flood of
knocks, or a captured knock sent again, must be dropped before it costs an
ML-KEM decapsulation, a JWKS lookup, or a round trip to the Controller.

  - RateLimiter   per-source-IP token bucket
  - ReplayCache   remembers a hash of every raw knock for a short window
  - is_fresh      the knock's own timestamp must be close to now
  - SpentTickets  knock-ticket ids already used; a ticket opens a port once

The replay cache outlives the freshness window on purpose:
a knock older than the window is refused as stale, so the cache only needs
to remember a knock for as long as it could still pass that check.

ReplayCache alone cannot stop a ticket being used twice: every ML-KEM
encapsulation yields new ciphertext, so the same ticket re-wrapped in a
fresh knock hashes differently. SpentTickets keys on the ticket's own
one-time id instead, which no re-wrapping changes.
"""

from __future__ import annotations

import collections
import hashlib
import threading
import time

# How far a knock's timestamp may be from the Gateway's clock, either way.
MAX_SKEW_SECONDS = 60


class RateLimiter:
    """Token bucket per source IP. Oldest IPs are evicted past max_entries so
    a spoofed-source flood cannot grow the table without bound."""

    def __init__(self, capacity: float = 10.0, fill_rate: float = 2.0,
                 max_entries: int = 10_000) -> None:
        self._capacity = capacity
        self._fill_rate = fill_rate
        self._max_entries = max_entries
        self._buckets: collections.OrderedDict[str, tuple[float, float]] = collections.OrderedDict()
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.pop(ip, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - last) * self._fill_rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[ip] = (tokens, now)
            if len(self._buckets) > self._max_entries:
                self._buckets.popitem(last=False)
            return allowed


class ReplayCache:
    """Remembers SHA-256 fingerprints of raw knocks for `ttl` seconds.

    The default ttl is twice the skew: a knock stamped up to MAX_SKEW_SECONDS
    in the future stays acceptable for that long after it first arrives, and
    must stay remembered for all of it.

    In memory only (PULGABLE kept it in SQLite). A knock captured in the last
    couple of minutes before a Gateway restart could be replayed once after
    it; accepted for now to keep the Gateway stateless on disk.
    """

    def __init__(self, ttl: float = MAX_SKEW_SECONDS * 2) -> None:
        self._ttl = ttl
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_replay(self, raw_packet: bytes) -> bool:
        fingerprint = hashlib.sha256(raw_packet).hexdigest()
        now = time.monotonic()
        with self._lock:
            self._seen = {fp: exp for fp, exp in self._seen.items() if exp > now}
            if fingerprint in self._seen:
                return True
            self._seen[fingerprint] = now + self._ttl
            return False


class SpentTickets:
    """One-time ids of knock tickets that have already opened a port.

    Called only after the ticket's IDP signature and expiry have verified,
    so an unauthenticated sender cannot fill it. In memory only, like
    ReplayCache: a Gateway restart forgets spent ids, but a ticket lives 60 s.
    """

    def __init__(self) -> None:
        self._spent: dict[str, int] = {}   # ticket_id -> ticket expires_at (unix s)
        self._lock = threading.Lock()

    def spend(self, ticket_id: str, expires_at: int, now: float | None = None) -> bool:
        """Mark `ticket_id` used. True the first time, False on any reuse."""
        now = time.time() if now is None else now
        with self._lock:
            # A ticket past its expiry fails verify() before it gets here, so
            # its id can never come back: forget it. `>=` keeps a ticket on
            # its last valid second, which verify() still accepts.
            self._spent = {tid: exp for tid, exp in self._spent.items() if exp >= now}
            if ticket_id in self._spent:
                return False
            self._spent[ticket_id] = expires_at
            return True


def is_fresh(timestamp, now: float | None = None) -> bool:
    if not isinstance(timestamp, (int, float)):
        return False
    now = time.time() if now is None else now
    return abs(now - timestamp) <= MAX_SKEW_SECONDS
