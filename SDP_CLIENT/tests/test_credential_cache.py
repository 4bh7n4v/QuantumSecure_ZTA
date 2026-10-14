"""A cached credential must never be handed to an authenticator that cannot
use it.

This is a regression suite for a real failure seen on Windows: the client had
enrolled through CNG, the Windows backend later became Windows Hello, and the
cached credential id was replayed to Hello, which had never held that key. The
ceremony died inside Windows with "There was a problem signing in with your
passkey" — an accurate message that says nothing about the actual cause.

The rule these tests hold in place: a credential is only offered back to the
backend that created it, and anything else reads as "nothing cached", which
sends the client to registration instead of into a dead end.
"""

from __future__ import annotations

import json

import pytest

from fido2_agent import credential_cache

USERNAME = "alice"
CREDENTIAL_ID = bytes.fromhex("e4cb3286eefd0a9f" + "00" * 24)


@pytest.fixture(autouse=True)
def cache_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(credential_cache, "CREDENTIAL_DIR", tmp_path / "credentials")


def test_credential_is_returned_to_the_backend_that_enrolled_it():
    credential_cache.save(USERNAME, "windows-webauthn", CREDENTIAL_ID)

    assert credential_cache.load(USERNAME, "windows-webauthn") == CREDENTIAL_ID


def test_credential_from_another_backend_reads_as_absent():
    """The exact Windows failure: enrolled through CNG, later asked for by
    Windows Hello. Hello cannot sign for it, so the client must re-register
    rather than hand it over.
    """
    credential_cache.save(USERNAME, "windows-cng", CREDENTIAL_ID)

    assert credential_cache.load(USERNAME, "windows-webauthn") is None


def test_the_same_machine_can_hold_credentials_for_different_users():
    credential_cache.save(USERNAME, "tpm2-tools", CREDENTIAL_ID)
    other = bytes.fromhex("ab" * 32)
    credential_cache.save("bob", "tpm2-tools", other)

    assert credential_cache.load(USERNAME, "tpm2-tools") == CREDENTIAL_ID
    assert credential_cache.load("bob", "tpm2-tools") == other


def test_nothing_cached_yet_reads_as_absent():
    assert credential_cache.load(USERNAME, "tpm2-tools") is None


def test_a_corrupted_cache_re_enrols_instead_of_raising():
    """A half-written file must not take the client down; re-enrolling is
    always a safe recovery because the IDP re-verifies attestation anyway.
    """
    credential_cache.save(USERNAME, "tpm2-tools", CREDENTIAL_ID)
    credential_cache._path(USERNAME).write_text("{ this is not json")

    assert credential_cache.load(USERNAME, "tpm2-tools") is None


def test_a_cache_missing_the_backend_field_re_enrols():
    path = credential_cache._path(USERNAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"credential_id": CREDENTIAL_ID.hex()}))

    assert credential_cache.load(USERNAME, "tpm2-tools") is None


def test_a_legacy_bin_cache_re_enrols_and_is_reported(caplog):
    """Older clients wrote a bare credential id with no backend recorded, so
    there is nothing to attribute it to and it cannot be migrated.
    """
    legacy = credential_cache.CREDENTIAL_DIR / (
        credential_cache._path(USERNAME).stem + ".bin")
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_bytes(CREDENTIAL_ID)

    with caplog.at_level("INFO"):
        result = credential_cache.load(USERNAME, "windows-webauthn")

    assert result is None
    assert "older client version" in caplog.text
