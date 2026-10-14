"""A software TPM must never be mistaken for the onboard chip.

The project rule is that device identity is hardware-rooted, with `swtpm`
tolerated under WSL only — there being no chip to reach inside a WSL kernel.
That rule lives or dies on the probe order, and the probe order had a hole:
asking tpm2-tools for "the default TPM" does not mean the chip. With no target
given, it walks /dev/tpmrm0, then /dev/tpm0, then a SIMULATOR on the default
port. A machine with no chip but a stray swtpm running would probe
"successfully" and be recorded as real hardware.

These tests pin the probe order so a simulator is only ever reached where it
was explicitly asked for.
"""

from __future__ import annotations

import sys

import pytest

from tpm import anchored_trust


@pytest.fixture
def native_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(anchored_trust, "is_wsl", lambda: False)


@pytest.fixture
def wsl(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(anchored_trust, "is_wsl", lambda: True)


def _no_explicit_tcti(monkeypatch):
    import dataclasses

    from shared.config.settings import settings
    monkeypatch.setattr(anchored_trust, "settings",
                        dataclasses.replace(settings, tpm_tcti=""))


def test_native_linux_names_the_device_files_explicitly(monkeypatch, native_linux):
    """Never an unset target: that is what silently reaches a simulator."""
    _no_explicit_tcti(monkeypatch)

    order = anchored_trust._internal_backends()

    assert [tcti for _, tcti in order] == list(anchored_trust.DEVICE_TCTIS)
    assert None not in [tcti for _, tcti in order]


def test_native_linux_never_falls_back_to_a_software_tpm(monkeypatch, native_linux):
    """No chip on a real Linux host means no hardware root, and the caller
    must abort rather than quietly accept a simulator.
    """
    _no_explicit_tcti(monkeypatch)

    backends = [backend for backend, _ in anchored_trust._internal_backends()]

    assert anchored_trust.BACKEND_SWTPM not in backends


def test_wsl_may_use_a_software_tpm_but_only_after_the_real_probe(monkeypatch, wsl):
    """A WSL kernel is not given the host's chip, so the simulator is the only
    option there — but it stays last, so a passed-through TPM would still win.
    """
    _no_explicit_tcti(monkeypatch)

    order = anchored_trust._internal_backends()

    assert order[-1][0] == anchored_trust.BACKEND_SWTPM
    assert all(backend == anchored_trust.BACKEND_TPM2_TOOLS for backend, _ in order[:-1])


def test_an_explicit_tcti_is_tried_first(monkeypatch, native_linux):
    """TPM_TCTI is how an operator points at a non-default chip, a resource
    manager, or a deliberately chosen simulator.
    """
    import dataclasses

    from shared.config.settings import settings
    monkeypatch.setattr(anchored_trust, "settings",
                        dataclasses.replace(settings, tpm_tcti="tabrmd:"))

    order = anchored_trust._internal_backends()

    assert order[0] == (anchored_trust.BACKEND_TPM2_TOOLS, "tabrmd:")


def test_a_simulated_anchor_is_labelled_as_simulated(monkeypatch, wsl):
    """`simulated` is what tells a real chip from a stand-in after the fact,
    so it must follow the backend that actually served the request.
    """
    monkeypatch.setattr(anchored_trust.tpm_handler, "probe",
                        lambda tcti: tcti == "swtpm:host=127.0.0.1,port=2321")
    monkeypatch.setattr(anchored_trust.tpm_handler, "load_signing_key", lambda *a, **k: object())
    monkeypatch.setattr(anchored_trust.tpm_handler, "load_public_key", lambda key: None)
    monkeypatch.setattr(anchored_trust, "_pem", lambda key: b"")
    monkeypatch.setattr(anchored_trust.attestation, "available", lambda: False)

    anchor = anchored_trust.select_trust_anchor("alice")

    assert anchor.backend == anchored_trust.BACKEND_SWTPM
    assert anchor.simulated is True
