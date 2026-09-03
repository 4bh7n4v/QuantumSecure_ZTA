"""Low-level iptables primitives for opening a single (src_ip, dst_port) hole.

Requires root + NET_ADMIN — the Gateway container should run with
`cap_add: [NET_ADMIN]`, not full --privileged. When iptables is unusable
(missing binary, insufficient permission — e.g. running this outside its
container during development on this host) calls degrade to a logged
dry-run instead of raising, so the rest of the SPA flow can still be
exercised and tested.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from shared.utils.logger import get_logger, status

log = get_logger("Firewall")

_IPTABLES = shutil.which("iptables")
CHAIN = "SDP_SPA"


def _usable() -> bool:
    # iptables genuinely requires root or CAP_NET_ADMIN; without that every
    # call below fails with "Permission denied" but still exits nonzero in a
    # way earlier code here didn't check, so it silently claimed success.
    return _IPTABLES is not None and os.geteuid() == 0


def ensure_chain(chain: str = CHAIN) -> None:
    """Idempotently create `chain`, hook it into INPUT, and default it to DROP.

    ACCEPT rules inserted by allow() go at position 1, ahead of the trailing
    DROP — this is the actual mechanism behind "ports stay closed until a
    valid SPA knock precedes any connection attempt".
    """
    if not _usable():
        status(log, "[DRY-RUN] iptables unavailable or not running as root/NET_ADMIN - would ensure chain",
               chain=chain)
        return

    create = subprocess.run([_IPTABLES, "-N", chain], capture_output=True, text=True)
    if create.returncode != 0 and "already exists" not in create.stderr:
        status(log, "Firewall chain creation failed", chain=chain, error=create.stderr.strip())
        return

    linked = subprocess.run([_IPTABLES, "-C", "INPUT", "-j", chain], capture_output=True)
    if linked.returncode != 0:
        subprocess.run([_IPTABLES, "-A", "INPUT", "-j", chain], check=True, capture_output=True)
        subprocess.run([_IPTABLES, "-A", chain, "-j", "DROP"], check=True, capture_output=True)
    status(log, "Firewall chain ready", chain=chain)


def allow(src_ip: str, dst_port: int, protocol: str = "tcp") -> bool:
    if not _usable():
        status(log, "[DRY-RUN] would ALLOW", src_ip=src_ip, port=dst_port, protocol=protocol)
        return False
    cmd = [_IPTABLES, "-I", CHAIN, "1", "-s", src_ip, "-p", protocol, "--dport", str(dst_port), "-j", "ACCEPT"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        status(log, "Firewall rule inserted", src_ip=src_ip, port=dst_port, protocol=protocol)
        return True
    except subprocess.CalledProcessError as exc:
        status(log, "Firewall insert failed", error=exc.stderr.strip())
        return False


def revoke(src_ip: str, dst_port: int, protocol: str = "tcp") -> None:
    if not _usable():
        status(log, "[DRY-RUN] would REVOKE", src_ip=src_ip, port=dst_port, protocol=protocol)
        return
    cmd = [_IPTABLES, "-D", CHAIN, "-s", src_ip, "-p", protocol, "--dport", str(dst_port), "-j", "ACCEPT"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        status(log, "Firewall rule revoked", src_ip=src_ip, port=dst_port)
    except subprocess.CalledProcessError as exc:
        status(log, "Firewall revoke failed", error=exc.stderr.strip())
