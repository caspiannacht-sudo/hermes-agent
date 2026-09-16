"""Native synthetic tests; PREPARED ONLY. Run with scripts/run_tests.sh after integration.

Real policy/config, real HTTPX parser and SSRF guard. Only DNS and the underlying
httpcore TCP dialer are replaced in transport cases; no actual socket is opened.
"""
import asyncio
import json
import socket
from pathlib import Path

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "false")
    from tools import website_policy as policy, url_safety
    from hermes_cli import config
    monkeypatch.setattr(config, "load_config", config.load_config_readonly)
    monkeypatch.setattr(policy, "_cached_policy", None)
    monkeypatch.setattr(policy, "_cached_policy_path", None)
    monkeypatch.setattr(policy, "_cached_policy_time", 0.0)
    url_safety._reset_allow_private_cache()

    def write(strict=True, backend="direct", **policy_values):
        data = {"security": {"website_blocklist": {
            "enabled": True, "strict": strict, "allowlist_domains": ["allowed.example"],
            **policy_values,
        }}, "web": {"keyless_fallback": True, "keyless_rescue": True}}
        if backend is not None:
            data["web"]["extract_backend"] = backend
        (tmp_path / "config.yaml").write_text(json.dumps(data), encoding="utf-8")
        policy._cached_policy = None
        return data
    write()
    yield write, tmp_path, policy
    url_safety._reset_allow_private_cache()


@pytest.fixture
def wire(env, monkeypatch):
    from httpcore._backends.sync import SyncBackend
    state = {"dns": [], "dials": [], "writes": [], "body": b"hello", "status": 200,
             "headers": {"Content-Type": "text/plain"}, "rebind": False}

    def dns(host, port, *args, **kwargs):
        state["dns"].append((host, port))
        ip = "127.0.0.1" if host == "127.0.0.1" or (state["rebind"] and len(state["dns"]) > 1) else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 80))]

    class Stream:
        def __init__(self):
            headers = {**state["headers"], "Content-Length": str(len(state["body"])), "Connection": "close"}
            self.data = (f"HTTP/1.1 {state['status']} Synthetic\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode() + state["body"]
        def read(self, max_bytes, timeout=None):
            data, self.data = self.data[:max_bytes], self.data[max_bytes:]
            return data
        def write(self, buffer, timeout=None):
            state["writes"].append(bytes(buffer))
        def close(self):
            pass
        def get_extra_info(self, info):
            return None

    def dial(self, host, port, **kwargs):
        state["dials"].append((host, port, kwargs))
        return Stream()
    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr(SyncBackend, "connect_tcp", dial)
    return state


def _direct(url="http://allowed.example/page"):
    from plugins.web.direct.provider import DirectWebProvider
    return DirectWebProvider().extract([url])[0]


@pytest.mark.parametrize("html", [False, True])
def test_native_direct_guard_and_text(env, wire, html):
    if html:
        wire["headers"]["Content-Type"] = "text/html; charset=utf-8"
        wire["body"] = b"<title>Example</title><p>Hello &amp; world</p><script>secret()</script><style>noise</style>"
    result = _direct()
    assert not result["error"]
    assert result["content"] == ("Hello & world" if html else "hello")
    assert wire["dials"][0][0] == "93.184.216.34"
    assert len(wire["dials"]) == 1
    sent = b"".join(wire["writes"])
    assert sent.count(b"GET /page HTTP/1.1") == 1
    assert b"Host: allowed.example" in sent
    assert wire["dials"][0][2]["timeout"] == 10.0


@pytest.mark.parametrize("host,canonical", [("faß.example", "fass.example"), ("bücher.example", "xn--bcher-kva.example")])
def test_builtin_idna_authority_is_the_actual_wire_target(env, wire, host, canonical):
    write, _, _ = env
    write(allowlist_domains=[host])
    result = _direct("http://" + host + "/page")
    assert not result["error"]
    assert len(wire["dials"]) == 1
    assert all(name == canonical for name, _ in wire["dns"])
    sent = b"".join(wire["writes"])
    assert ("Host: " + canonical + "\r\n").encode() in sent
    assert sent.count(b"GET /page HTTP/1.1") == 1


def test_plugin_name_cannot_qualify_strict_dispatch(env, monkeypatch):
    from tools.web_tools_extract import _extract_safe_urls
    from tools import web_result_cache as cache
    class Unqualified:
        name = "direct"
        def extract(self, urls, **kwargs):
            pytest.fail("unqualified provider dispatched")
    monkeypatch.setattr(cache, "extract_cache_get", lambda *a, **k: pytest.fail("unqualified cache read"))
    with pytest.raises(ValueError, match="bundled"):
        asyncio.run(_extract_safe_urls(Unqualified(), ["http://allowed.example"], None))


@pytest.mark.parametrize("case", ["blocked", "malformed", "secret", "userinfo", "private", "rebind"])
def test_native_guards_prevent_underlying_dial(env, wire, case):
    write, home, policy = env
    url = "http://allowed.example/page"
    if case == "blocked":
        url = "http://blocked.example/page"
    elif case == "malformed":
        (home / "config.yaml").write_text("security: [", encoding="utf-8")
    elif case == "secret":
        url += "?token=synthetic-opaque-value"
    elif case == "userinfo":
        url = "http://synthetic:password@allowed.example/page"
    elif case == "private":
        write(strict=False, enabled=False, allowlist_domains=[])
        url = "http://127.0.0.1/page"
    else:
        wire["rebind"] = True
    result = _direct(url)
    assert result["error"]
    assert wire["dials"] == [] and wire["writes"] == []
    if case == "rebind":
        assert len(wire["dns"]) == 2
        assert "connect-time" in result["error"]


@pytest.mark.parametrize("case", ["redirect", "pdf", "binary", "oversize", "compressed"])
def test_unsupported_response_never_follows_or_rescues(env, wire, case):
    from plugins.web.direct.provider import MAX_BODY_BYTES
    if case == "redirect":
        wire.update(status=302, headers={"Location": "http://blocked.example/private"})
    elif case == "pdf":
        wire["headers"]["Content-Type"] = "application/pdf"
    elif case == "binary":
        wire["body"] = b"hello\x00binary"
    elif case == "oversize":
        wire["body"] = b"a" * (MAX_BODY_BYTES + 1)
    else:
        wire["headers"]["Content-Encoding"] = "gzip"
    assert _direct()["error"]
    assert len(wire["dials"]) == 1
    assert all(host == "allowed.example" for host, _ in wire["dns"])


@pytest.mark.parametrize("tier", ["keyed", "keyless"])
def test_richer_available_provider_precedes_direct(env, monkeypatch, tier):
    write, _, _ = env
    write(strict=False, backend=None, allowlist_domains=[])
    from tools import web_tools as web
    from agent import web_search_registry as registry
    web._ensure_web_plugins_loaded()
    richer = registry.get_provider("firecrawl")
    direct = registry.get_provider("direct")
    assert richer is not None and direct is not None
    for provider in registry.list_providers():
        monkeypatch.setattr(provider, "is_available", lambda: False)
        monkeypatch.setattr(provider, "is_keyless_available", lambda: False)
    monkeypatch.setattr(direct, "is_available", lambda: True)
    monkeypatch.setattr(richer, "is_available" if tier == "keyed" else "is_keyless_available", lambda: True)
    assert registry.get_active_extract_provider() is richer


@pytest.mark.parametrize("backend", ["firecrawl", "nous", "missing", False, 0, []])
def test_strict_gate_precedes_discovery_cache_and_remote_search(env, monkeypatch, backend):
    write, _, _ = env
    write(backend=backend)
    from tools import web_tools as web
    from tools import web_result_cache as cache
    def forbidden(*args, **kwargs):
        pytest.fail("strict request reached discovery/cache/provider")
    monkeypatch.setattr(web, "_ensure_web_plugins_loaded", forbidden)
    monkeypatch.setattr(web, "_get_extract_backend", forbidden)
    monkeypatch.setattr(cache, "extract_cache_get", forbidden)
    assert not json.loads(asyncio.run(web.web_extract_tool(["http://allowed.example"]))) ["success"]
    assert "unsupported" in json.loads(web.web_search_tool("synthetic query"))["error"]
    assert not web._web_capability_ready("search")


def test_full_strict_entrypoint_uses_bundled_direct_only(env, wire, monkeypatch):
    from tools import web_tools as web, web_tools_rescue as rescue
    def forbidden(*args, **kwargs):
        pytest.fail("strict request reached discovery or rescue")
    monkeypatch.setattr(web, "_ensure_web_plugins_loaded", forbidden)
    monkeypatch.setattr(rescue, "_rescue_extract", forbidden)
    result = json.loads(asyncio.run(web.web_extract_tool(["http://allowed.example/page"])))
    assert result["results"][0]["content"] == "hello"
    assert len(wire["dials"]) == 1
    assert web._web_capability_ready("extract")


@pytest.mark.parametrize("mode", ["denied", "mixed", "outage", "short", "exception"])
def test_shared_denials_never_become_cache_misses(env, monkeypatch, mode):
    write, _, policy = env
    write(strict=False, backend="synthetic", domains=["blocked.example"], allowlist_domains=[])
    from tools.web_tools_extract import _extract_safe_urls
    from tools import web_result_cache as cache
    from plugins.web import keyless_mcp
    reads, writes, vendor, rescued = [], [], [], []
    allowed, blocked = "http://allowed.example", "http://blocked.example"
    urls = [blocked] if mode in {"denied", "exception"} else [blocked, allowed, blocked]
    if mode == "exception":
        # Deliberately fault the policy boundary only in the dedicated error test.
        def explode(url):
            raise RuntimeError("synthetic policy fault")
        monkeypatch.setattr(policy, "check_website_access", explode)
    def cache_get(url, **kwargs):
        reads.append(url)
        return None
    monkeypatch.setattr(cache, "extract_cache_get", cache_get)
    monkeypatch.setattr(cache, "extract_cache_put", lambda url, *a, **k: writes.append(url))
    def rescue(name, urls):
        rescued.extend(urls)
        return [{"url": u, "content": "rescued", "error": None} for u in urls]
    monkeypatch.setattr(keyless_mcp, "extract_with_failover", rescue)
    class Provider:
        name = "synthetic"
        def extract(self, urls, **kwargs):
            vendor.extend(urls)
            if mode == "outage":
                raise RuntimeError("synthetic provider outage")
            if mode == "short":
                return []
            return [{"url": u, "content": "fresh", "error": None} for u in urls]
    results = asyncio.run(_extract_safe_urls(Provider(), urls, None))
    assert len(results) == len(urls)
    for collection in (reads, writes, vendor, rescued):
        assert blocked not in collection
    assert results[0]["error"]
    if mode in {"denied", "exception"}:
        assert reads == writes == vendor == rescued == []
    else:
        assert reads == vendor == [allowed]
        assert results[2]["error"]
    if mode == "outage":
        assert rescued == [allowed] and writes == []


@pytest.mark.parametrize("result_count", [0, 1, 4])
def test_rescue_rechecks_policy_when_provider_result_count_differs(env, monkeypatch, result_count):
    write, _, _ = env
    write(strict=False, domains=["blocked.example"], allowlist_domains=[])
    from tools.web_tools_rescue import _rescue_extract
    from plugins.web import keyless_mcp
    calls = []
    def rescue(name, urls):
        calls.append(urls)
        return [{"url": u, "content": "rescued", "error": None} for u in urls]
    monkeypatch.setattr(keyless_mcp, "extract_with_failover", rescue)
    urls = ["http://blocked.example", "http://allowed.example"]
    results = [{"url": urls[0], "content": "", "error": "outage"}] * result_count
    merged = _rescue_extract("synthetic", urls, results)
    assert calls == [[urls[1]]]
    assert len(merged) == 2 and merged[0]["blocked_by_policy"]
    assert merged[1]["content"] == "rescued"


@pytest.mark.parametrize("web_config,expected", [
    ({"backend": "nous"}, "firecrawl"),
    ({"extract_backend": "nous"}, "firecrawl"),
    ({"use_gateway": True}, "firecrawl"),
    ({"search_backend": "tavily"}, "firecrawl"),
    ({"extract_backend": "missing"}, "missing"),
    ({"extract_backend": "direct"}, "direct"),
    ({}, "direct"),
])
def test_real_discovery_selection_and_dispatch_identity(env, wire, monkeypatch, web_config, expected):
    write, home, policy = env
    data = write(strict=False, allowlist_domains=[])
    data["web"] = {**web_config, "keyless_fallback": False, "keyless_rescue": False}
    (home / "config.yaml").write_text(json.dumps(data), encoding="utf-8")
    policy._cached_policy = None
    from tools import web_tools as web
    from agent import web_search_registry as registry
    web._ensure_web_plugins_loaded()
    assert registry.get_provider("direct") is not None  # real discovery, not manual registration
    for provider in registry.list_providers():
        if provider.name != "direct":
            monkeypatch.setattr(provider, "is_available", lambda: False)
            monkeypatch.setattr(provider, "is_keyless_available", lambda: False)
    monkeypatch.setattr(web, "_has_env", lambda name: False)
    monkeypatch.setattr(web, "_is_tool_gateway_ready", lambda: False)
    monkeypatch.setattr(web, "_ddgs_package_importable", lambda: False)
    assert web._get_extract_backend() == expected
    selected = registry.get_active_extract_provider()
    assert (selected.name if selected else None) == (None if expected == "missing" else expected)
    calls = []
    if selected is not None:
        def extract(urls, **kwargs):
            calls.append(selected.name)
            return [{"url": u, "content": "synthetic result", "error": None} for u in urls]
        monkeypatch.setattr(selected, "extract", extract)
    result = json.loads(asyncio.run(web.web_extract_tool(["http://allowed.example/page"])))
    if expected == "missing":
        assert not result["success"] and calls == []
    else:
        assert calls == [expected]
        assert web._web_capability_ready("extract") is (expected == "direct")
    assert wire["dials"] == []
