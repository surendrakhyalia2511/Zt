#!/usr/bin/env python3
"""
env_loader.py
ZeroShield Gateway — Environment Variable Loader

Loads .env file from /home/sk/.env
No external dependencies — pure Python.

Usage:
    from env_loader import env
    token = env("TELEGRAM_TOKEN")
    port  = env("DASHBOARD_PORT", "8443")
"""

import os

ENV_FILE = "/home/sk/.env"
_cache = {}


def _load():
    """Parse .env file into _cache dict."""
    if _cache:
        return
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key   = key.strip()
                value = value.strip().strip('"').strip("'")
                _cache[key] = value
    except FileNotFoundError:
        pass   # Fall back to os.environ only


def env(key: str, default: str = None) -> str:
    """
    Get env variable — checks .env file first, then os.environ.

    Args:
        key     : variable name
        default : fallback if not found

    Returns:
        value string or default
    """
    _load()
    return _cache.get(key) or os.environ.get(key) or default


def require(key: str) -> str:
    """Get env variable — raises if missing."""
    val = env(key)
    if val is None:
        raise EnvironmentError(
            f"Required env variable '{key}' not set.\n"
            f"Add it to {ENV_FILE}"
        )
    return val


def all_vars() -> dict:
    """Return all loaded env vars (for debugging)."""
    _load()
    merged = {**os.environ, **_cache}
    # Mask sensitive values
    masked = {}
    for k, v in merged.items():
        if any(s in k.upper() for s in ["TOKEN", "SECRET", "PASSWORD", "KEY"]):
            masked[k] = v[:6] + "..." if len(v) > 6 else "***"
        else:
            masked[k] = v
    return masked
