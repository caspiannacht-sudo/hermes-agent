"""Fail-closed website policy for URL-capable tools (not an egress sandbox).

Policy is read on EVERY call, including disabled policies and shared files. The
legacy cache attributes remain for compatibility, but never authorize access.
Bare rules match the host and its subdomains; ``*.host`` matches subdomains only
(at any depth). IP literals match exactly. No other glob syntax is supported.
URLs and bare ``host/path`` rules select an entire host, not a path or port.
``www`` is NOT stripped. Both inputs use the same hostname/IDNA normalization.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from contextvars import ContextVar, Token
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from hermes_constants import get_hermes_home
from tools.url_safety import _normalize_hostname as _normalize_host

logger = logging.getLogger(__name__)
_DEFAULT_WEBSITE_BLOCKLIST = {
    "enabled": False, "strict": False, "mode": "blocklist",
    "domains": [], "shared_files": [], "allowlist_domains": [], "allowlist_files": [],
}
# Retained for callers/tests resetting legacy state; deliberately unused on reads.
_CACHE_TTL_SECONDS = 30.0
_cache_lock = threading.Lock()
_cached_policy: Optional[Dict[str, Any]] = None
_cached_policy_path: Optional[str] = None
_cached_policy_time: float = 0.0
_unattended: ContextVar[bool] = ContextVar("unattended_website_policy", default=False)


class WebsitePolicyError(Exception):
    """Policy cannot be safely interpreted; callers must deny access."""


def begin_unattended_website_policy() -> Token:
    """Activate strict policy in this context; propagate via copy_context to workers."""
    return _unattended.set(True)


def end_unattended_website_policy(token: Token) -> None:
    """Restore the exact previous value (including nested strict scopes)."""
    _unattended.reset(token)


def is_strict_website_policy() -> bool:
    """Unknown policy is strict, never an inferred non-strict preflight result."""
    if _unattended.get():
        return True
    try:
        return load_website_blocklist()["strict"]
    except Exception:
        return True


def _canonical_host(host: str) -> str:
    # Validate BEFORE normalization can erase ambiguous input. A single final DNS
    # dot is valid; empty labels, zone IDs and URL-escaped hosts are not.
    if not host or host.endswith("..") or any(c in host for c in "%\\/*?@#"):
        raise WebsitePolicyError("Invalid hostname")
    host = _normalize_host(host)
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        if ":" in host:
            raise WebsitePolicyError("Invalid IP literal") from None
    try:
        host = host.encode("idna").decode("ascii").lower()
        # Reject malformed ASCII punycode as well as invalid Unicode labels.
        for label in host.split("."):
            if label.startswith("xn--"):
                label.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise WebsitePolicyError("Invalid IDNA hostname") from exc
    if len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise WebsitePolicyError("Invalid DNS hostname")
    return host


def _extract_host_from_urlish(url: str) -> str:
    """HTTP(S), protocol-relative or bare host/path; malformed input is an error.

    Credentials, whitespace/control characters, backslashes, percent-encoded
    hosts, bad ports, unsupported schemes and empty hosts are rejected.
    """
    if not isinstance(url, str) or not url or any(
        c.isspace() or ord(c) < 32 or ord(c) == 127 or c == "\\" for c in url
    ):
        raise WebsitePolicyError("Invalid URL text")
    try:
        value = url if "://" in url or url.startswith("//") else "//" + url
        parsed = urlsplit(value)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            raise WebsitePolicyError("Unsupported URL scheme")
        if parsed.username is not None or parsed.password is not None:
            raise WebsitePolicyError("URL credentials are not supported")
        if not parsed.hostname or parsed.netloc.endswith(":"):
            raise WebsitePolicyError("Missing hostname or port")
        port = parsed.port  # Property evaluation rejects invalid/out-of-range ports.
        if port is not None and port == 0:
            raise WebsitePolicyError("Invalid port")
        # urlsplit tolerates junk following a bracketed IPv6 literal.
        if parsed.netloc.startswith("["):
            suffix = parsed.netloc.partition("]")[2]
            if suffix and not re.fullmatch(r":[0-9]+", suffix):
                raise WebsitePolicyError("Invalid IPv6 authority")
        return _canonical_host(parsed.hostname)
    except (ValueError, UnicodeError) as exc:
        raise WebsitePolicyError("Malformed URL") from exc


def _normalize_rule(rule: Any) -> str:
    if not isinstance(rule, str) or not rule.strip():
        raise WebsitePolicyError("Rules must be nonempty strings")
    value = rule.strip()
    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]
    if "*" in value:
        raise WebsitePolicyError("Only a leading *. wildcard is supported")
    # Wildcards only have a bare hostname operand (no port/path/URL).
    if wildcard and any(c in value for c in "/:?#@"):
        raise WebsitePolicyError("Wildcard requires a bare DNS hostname")
    host = _extract_host_from_urlish(value)
    if wildcard:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return "*." + host
        raise WebsitePolicyError("IP wildcards are not supported")
    return host


def _require_mapping(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise WebsitePolicyError(f"{label} must be a mapping")
    return value


def _load_policy_config(config_path: Path) -> Dict[str, Any]:
    # Missing/unreadable/empty YAML is unknown, NOT a disabled policy. An explicit
    # empty mapping is the supported way to omit policy in attended operation.
    try:
        import yaml
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WebsitePolicyError("Unable to read website policy configuration") from exc
    root = _require_mapping(config, "config root")
    security = _require_mapping(root.get("security", {}), "security")
    policy = _require_mapping(security.get("website_blocklist", {}), "website_blocklist")
    if set(policy) - set(_DEFAULT_WEBSITE_BLOCKLIST):
        raise WebsitePolicyError("Unknown website policy field")
    return {**_DEFAULT_WEBSITE_BLOCKLIST, **policy}


def _require_type(policy: Dict[str, Any], key: str, kind: type, default: Any) -> Any:
    value = policy.get(key, default)
    if type(value) is not kind:
        raise WebsitePolicyError(f"website_blocklist.{key} must be {kind.__name__}")
    return value


def _file_rules(entry: Any, base: Path, *, require_nonempty: bool) -> List[Dict[str, str]]:
    if not isinstance(entry, str) or not entry.strip():
        raise WebsitePolicyError("List file paths must be nonempty strings")
    path = Path(entry.strip()).expanduser()
    if not path.is_absolute():
        path = base / path
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError, ValueError) as exc:
        raise WebsitePolicyError("Unable to read website list file") from exc
    rules = [
        {"pattern": _normalize_rule(line), "source": str(path)}
        for line in lines if line.strip() and not line.lstrip().startswith("#")
    ]
    if require_nonempty and not rules:
        raise WebsitePolicyError("Each allowlist file must contain active rules")
    return rules


def _collect_rules(policy: Dict[str, Any], domain_key: str, file_key: str, base: Path) -> List[Dict[str, str]]:
    rules = [
        {"pattern": _normalize_rule(value), "source": "config"}
        for value in _require_type(policy, domain_key, list, [])
    ]
    for entry in _require_type(policy, file_key, list, []):
        rules.extend(_file_rules(entry, base, require_nonempty=file_key == "allowlist_files"))
    return rules


def load_website_blocklist(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Return validated policy or raise WebsitePolicyError; never use cached state.

    Relative list paths are relative to the selected config's directory. Every
    source is validated, even when disabled or unused by the selected mode.
    ``rules`` retains the historical deny-rule shape; ``allowlist_rules`` is new.
    Context strictness is applied by check_website_access, not persisted here.
    """
    try:
        path = Path(config_path) if config_path is not None else get_hermes_home() / "config.yaml"
        policy = _load_policy_config(path)
        enabled = _require_type(policy, "enabled", bool, False)
        strict = _require_type(policy, "strict", bool, False)
        mode = policy["mode"]
        if type(mode) is not str or mode not in {"blocklist", "allowlist"}:
            raise WebsitePolicyError("mode must be blocklist or allowlist")
        return {
            "enabled": enabled, "strict": strict, "mode": mode,
            "rules": _collect_rules(policy, "domains", "shared_files", path.parent),
            "allowlist_rules": _collect_rules(policy, "allowlist_domains", "allowlist_files", path.parent),
        }
    except WebsitePolicyError:
        raise
    except Exception as exc:
        raise WebsitePolicyError("Unable to load website policy") from exc


def _match_host_against_rule(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith("." + pattern[2:])
    try:
        ipaddress.ip_address(pattern)
    except ValueError:
        return host == pattern or host.endswith("." + pattern)
    return host == pattern


def _denial(url: str, host: str, reason: str, rule: str = "", source: str = "policy") -> Dict[str, str]:
    return {"url": url, "host": host, "rule": rule, "source": source,
            "message": "Blocked by website policy: " + reason}


def check_website_access(url: str, config_path: Optional[Path] = None) -> Optional[Dict[str, str]]:
    """None means allowed; all policy/URL errors return denial, including explicit paths."""
    host = ""
    try:
        host = _extract_host_from_urlish(url)
        policy = load_website_blocklist(config_path)
        strict = _unattended.get() or policy["strict"]
        if not policy["enabled"]:
            return _denial(url, host, "strict policy is disabled") if strict else None
        for rule in policy["rules"]:
            if _match_host_against_rule(host, rule["pattern"]):
                return _denial(url, host, "matched deny rule", rule["pattern"], rule["source"])
        if strict or policy["mode"] == "allowlist":
            for rule in policy["allowlist_rules"]:
                if _match_host_against_rule(host, rule["pattern"]):
                    return None
            return _denial(url, host, "no allowlist rule matched")
        return None
    except Exception:
        # Do not leak config content or assume unreadable policy was non-strict.
        logger.warning("Website policy or URL invalid; denying access")
        return _denial(url, host, "policy or URL could not be validated")


# ---- BEGIN PLUGIN-COMPAT (revert-scheduled; see COMPAT_MANIFEST.md) ----
# Names external plugins imported from this module before the Sep 2026 decomposition.
# Internal code MUST NOT use these (scripts/check_compat_pointers.py fails CI if it does).
# The whole block is removed by reverting the commit that added it.

def invalidate_cache() -> None:
    """Compatibility only: policy reads now always bypass the cache."""
    global _cached_policy
    with _cache_lock:
        _cached_policy = None
# ---- END PLUGIN-COMPAT ----
