"""Shared website dispatch gates. No provider discovery or transport in policy checks."""

STRICT_SEARCH_ERROR = "Blocked by website policy: strict web search is unsupported (remote search is not qualified)"
STRICT_EXTRACT_ERROR = "Blocked by website policy: strict extraction requires the bundled target-direct backend"


def strict_web_policy() -> bool:
    # Failure to import/evaluate strict intent is never permission for remote dispatch.
    try:
        from tools.website_policy import is_strict_website_policy
        return is_strict_website_policy() is not False
    except Exception:
        return True


def website_denial(url):
    try:
        from tools.website_policy import check_website_access
        return check_website_access(url)
    except Exception:
        return {"message": "Blocked by website policy: policy evaluation failed"}


def strict_extract_provider():
    """Resolve ONLY bundled direct, before broad plugin discovery/initialization.

    Read presence-sensitive effective selection (without defaults), including
    managed choices. Do not trust third-party capability metadata.
    """
    from hermes_cli.config_effective import load_user_config_effective
    from utils import is_truthy_value
    cfg = load_user_config_effective(fail_closed=True)
    if not isinstance(cfg, dict):
        raise ValueError(STRICT_EXTRACT_ERROR)
    web = cfg.get("web", {})
    plugins = cfg.get("plugins", {})
    if not isinstance(web, dict) or not isinstance(plugins, dict):
        raise ValueError(STRICT_EXTRACT_ERROR)
    for key in ("extract_backend", "backend", "search_backend"):
        if key in web and web[key] is not None and not isinstance(web[key], str):
            raise ValueError(STRICT_EXTRACT_ERROR)
    selected = web.get("extract_backend") or web.get("backend")
    if not selected and (is_truthy_value(web.get("use_gateway")) or web.get("search_backend")):
        selected = "firecrawl"
    if selected is not None and (not isinstance(selected, str) or selected.strip().lower() != "direct"):
        raise ValueError(STRICT_EXTRACT_ERROR)
    disabled = plugins.get("disabled", [])
    if not isinstance(disabled, list) or any(not isinstance(x, str) for x in disabled):
        raise ValueError(STRICT_EXTRACT_ERROR)
    if {"web/direct", "web-direct", "direct"}.intersection(disabled):
        raise ValueError(STRICT_EXTRACT_ERROR + "; web/direct is disabled")
    from plugins.web.direct.provider import DirectWebProvider
    provider = DirectWebProvider()
    if not provider.is_available():
        raise ValueError(STRICT_EXTRACT_ERROR + "; direct dependencies unavailable")
    return provider


def require_strict_provider(provider):
    if strict_web_policy():
        from plugins.web.direct.provider import DirectWebProvider
        if type(provider) is not DirectWebProvider:
            raise ValueError(STRICT_EXTRACT_ERROR)
