"""Structured console logger shared across all four components.

Every component prints live "what is happening right now" status lines
(registration begin, trust score computed, SPA knock sent, etc.) through
this single helper so log format stays consistent end to end.
"""

from __future__ import annotations

import logging
import sys


def get_logger(component: str) -> logging.Logger:
    logger = logging.getLogger(component)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            fmt=f"%(asctime)s | {component:<12} | %(levelname)-8s | %(message)s",
            datefmt="%H:%M:%S",
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def status(logger: logging.Logger, step: str, **fields) -> None:
    """Print one live-status line, e.g. status(log, "Registration begin", user="alice")."""
    if fields:
        detail = " | ".join(f"{k}={v}" for k, v in fields.items())
        logger.info("%s | %s", step, detail)
    else:
        logger.info(step)


# --------------------------------------------------------------------------- #
# Ceremony-narration helpers                                                  #
#                                                                             #
# Used by the FIDO2 registration/authentication flows on both the client and  #
# the IDP so the terminal reads as a clear, numbered walk-through of the      #
# protocol: a title banner, then "Step n/N: ...", then a summary block.       #
# --------------------------------------------------------------------------- #

_BANNER_WIDTH = 64


def banner(logger: logging.Logger, title: str, char: str = "=") -> None:
    """A titled separator, e.g.

        ================================================================
        FIDO2 REGISTRATION INITIATED
        ================================================================
    """
    rule = char * _BANNER_WIDTH
    logger.info(rule)
    logger.info(title)
    logger.info(rule)


def step(logger: logging.Logger, n: int, total: int, description: str, **fields) -> None:
    """One numbered ceremony step: ``Step 3/6: Building clientDataJSON | origin=...``."""
    msg = f"Step {n}/{total}: {description}"
    if fields:
        msg += " | " + " | ".join(f"{k}={v}" for k, v in fields.items())
    logger.info(msg)


def field(logger: logging.Logger, label: str, value) -> None:
    """An indented ``label: value`` line for the summary blocks."""
    logger.info("    %s: %s", label, value)
