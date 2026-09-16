"""Native public-API regressions; synthetic config/files, no transport calls.

These use only APIs present on the public baseline, so expected baseline failures
are semantic assertion failures, not failures to import a newly invented API.
Run only in an authorized disposable checkout with the canonical test runner.
"""
import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def policy_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    wp = importlib.import_module("tools.website_policy")
    monkeypatch.setattr(wp, "_cached_policy", None)
    monkeypatch.setattr(wp, "_cached_policy_path", None)
    monkeypatch.setattr(wp, "_cached_policy_time", 0.0)
    config = tmp_path / "config.yaml"
    config.write_text("{}", encoding="utf-8")

    def write(**values):
        data = {"enabled": True, "strict": True, **values}
        config.write_text(json.dumps({"security": {"website_blocklist": data}}), encoding="utf-8")
        return config

    return wp, config, write


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("values", [
    {"enabled": False}, {}, {"mode": "blocklist"},
    {"allowlist_domains": ["other.example"]},
    {"allowlist_domains": []}, {"allowlist_files": []},
])
def test_strict_requires_enabled_matching_allowlist(policy_env, explicit, values):
    wp, config, write = policy_env
    write(**values)
    assert wp.check_website_access("https://allowed.example", config if explicit else None) is not None


@pytest.mark.parametrize("strict,mode", [(True, "blocklist"), (True, "allowlist"), (False, "allowlist")])
def test_allow_and_deny_precedence(policy_env, strict, mode):
    wp, config, write = policy_env
    write(strict=strict, mode=mode, allowlist_domains=["allowed.example"], domains=["secret.allowed.example"])
    assert wp.check_website_access("https://allowed.example") is None
    assert wp.check_website_access("https://sub.allowed.example") is None
    denial = wp.check_website_access("https://secret.allowed.example")
    assert denial is not None
    assert denial["rule"] == "secret.allowed.example"
    assert wp.check_website_access("https://elsewhere.example") is not None


@pytest.mark.parametrize("key", ["domains", "shared_files", "allowlist_domains", "allowlist_files"])
@pytest.mark.parametrize("bad", [None, False, 0, "", {}, "allowed.example"])
def test_falsey_and_wrong_list_containers_deny(policy_env, key, bad):
    wp, config, write = policy_env
    values = {"allowlist_domains": ["allowed.example"], key: bad}
    write(**values)
    assert wp.check_website_access("https://allowed.example", config) is not None
    with pytest.raises(wp.WebsitePolicyError):
        wp.load_website_blocklist(config)


@pytest.mark.parametrize("key", ["domains", "shared_files", "allowlist_domains", "allowlist_files"])
@pytest.mark.parametrize("bad", [None, False, 0, 123, "", "  ", {}])
def test_invalid_list_elements_are_not_skipped(policy_env, key, bad):
    wp, config, write = policy_env
    values = {"allowlist_domains": ["allowed.example"], key: [bad]}
    write(**values)
    assert wp.check_website_access("https://allowed.example", config) is not None


@pytest.mark.parametrize("key,bad", [
    ("enabled", 0), ("enabled", 1), ("enabled", "true"), ("enabled", None),
    ("strict", 0), ("strict", 1), ("strict", "false"), ("strict", None),
    ("mode", None), ("mode", False), ("mode", 0), ("mode", []),
    ("mode", "ALLOWLIST"), ("mode", "unknown"), ("allow_domains", []),
])
def test_invalid_scalar_and_unknown_fields_deny(policy_env, key, bad):
    wp, config, write = policy_env
    write(**{"allowlist_domains": ["allowed.example"], key: bad})
    assert wp.check_website_access("https://allowed.example", config) is not None


@pytest.mark.parametrize("raw", [
    "", "null", "false", "0", "[]", "[unclosed", "security: null", "security: false",
    "security: 0", "security: []", "security: {website_blocklist: null}",
    "security: {website_blocklist: false}", "security: {website_blocklist: 0}",
    "security: {website_blocklist: []}",
])
@pytest.mark.parametrize("explicit", [False, True])
def test_unknown_config_never_fails_open(policy_env, raw, explicit):
    wp, config, _ = policy_env
    config.write_text(raw, encoding="utf-8")
    assert wp.check_website_access("https://allowed.example", config if explicit else None) is not None


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("failure", ["missing", "decode", "directory", "permission", "unexpected"])
def test_config_read_errors_deny(policy_env, monkeypatch, explicit, failure):
    wp, config, write = policy_env
    write(allowlist_domains=["allowed.example"])
    if failure == "missing":
        config.unlink()
    elif failure == "decode":
        config.write_bytes(b"\xff")
    elif failure == "directory":
        config.unlink()
        config.mkdir()
    else:
        read = Path.read_text
        def fail(path, *args, **kwargs):
            if path == config:
                raise PermissionError("synthetic") if failure == "permission" else RuntimeError("synthetic")
            return read(path, *args, **kwargs)
        monkeypatch.setattr(Path, "read_text", fail)
    assert wp.check_website_access("https://allowed.example", config if explicit else None) is not None


@pytest.mark.parametrize("bad", ["missing", "empty", "comments", "decode", "directory", "malformed", "permission"])
@pytest.mark.parametrize("reverse", [False, True])
def test_each_allowlist_file_required(policy_env, monkeypatch, bad, reverse):
    wp, config, write = policy_env
    good = config.parent / "good.txt"
    good.write_text("# good\nallowed.example\n", encoding="utf-8")
    broken = config.parent / "bad.txt"
    payloads = {"empty": "", "comments": "# only comment\n\n", "malformed": "allowed.example\nhttps://[bad\n"}
    if bad in payloads:
        broken.write_text(payloads[bad], encoding="utf-8")
    elif bad == "decode":
        broken.write_bytes(b"\xff")
    elif bad == "directory":
        broken.mkdir()
    elif bad == "permission":
        broken.write_text("allowed.example", encoding="utf-8")
        read = Path.read_text
        def fail(path, *args, **kwargs):
            if path == broken:
                raise PermissionError("synthetic unreadable source")
            return read(path, *args, **kwargs)
        monkeypatch.setattr(Path, "read_text", fail)
    files = [good.name, broken.name]
    write(allowlist_domains=["allowed.example"], allowlist_files=files[::-1] if reverse else files)
    assert wp.check_website_access("https://allowed.example", config) is not None


@pytest.mark.parametrize("bad", [None, False, 0, 123, "", "  ", {}])
@pytest.mark.parametrize("reverse", [False, True])
def test_valid_allowlist_file_cannot_mask_invalid_file_entry(policy_env, bad, reverse):
    wp, config, write = policy_env
    good = config.parent / "good.txt"
    good.write_text("allowed.example", encoding="utf-8")
    files = [good.name, bad]
    write(allowlist_files=files[::-1] if reverse else files)
    assert wp.check_website_access("https://allowed.example", config) is not None


def test_files_relative_to_explicit_config_and_deny_first(policy_env):
    wp, config, write = policy_env
    alternate = config.parent / "alternate"
    alternate.mkdir()
    target = alternate / "config.yaml"
    target.write_text(json.dumps({"security": {"website_blocklist": {
        "enabled": True, "strict": True, "allowlist_files": ["allow.txt"], "shared_files": ["deny.txt"],
    }}}), encoding="utf-8")
    (alternate / "allow.txt").write_text("allowed.example\n", encoding="utf-8")
    (alternate / "deny.txt").write_text("secret.allowed.example\n", encoding="utf-8")
    assert wp.check_website_access("https://allowed.example", target) is None
    assert wp.check_website_access("https://secret.allowed.example", target) is not None


@pytest.mark.parametrize("rule,url,allowed", [
    ("example.com", "https://example.com", True),
    ("example.com", "https://a.b.example.com", True),
    ("example.com", "https://notexample.com", False),
    ("*.example.com", "https://example.com", False),
    ("*.example.com", "https://a.b.example.com", True),
    ("www.example.com", "https://example.com", False),
    ("HTTPS://BÜCHER.example./path", "https://xn--bcher-kva.example/other", True),
    ("xn--bcher-kva.example", "https://bücher.example", True),
    ("example.com/path", "https://EXAMPLE.COM.:443/other", True),
    ("https://example.com/path?query=x#part", "https://example.com/other", True),
    ("HTTPS://[2001:db8::1]/path", "https://[2001:db8::1]", True),
    ("[2001:db8::1]", "https://[2001:0db8::1]:443", True),
    ("192.0.2.1", "https://x.192.0.2.1", False),
])
def test_shared_host_normalization_and_matching(policy_env, rule, url, allowed):
    wp, config, write = policy_env
    write(allowlist_domains=[rule])
    assert (wp.check_website_access(url, config) is None) is allowed


@pytest.mark.parametrize("bad", [
    "", "https://", "https://[bad", "https://[::1]junk", "https://example.com:bad",
    "https://example.com:65536", "https://example.com:", "https://example.com:0",
    "file:///tmp/a", "javascript:alert(1)", "ftp://example.com", "/relative/path",
    "https://user:pass@example.com", "https://example.com\\evil", "https://%65xample.com",
    "https://exa mple.com", "https://example.com\n", "https://-bad.example",
    "https://example..com", "https://example.com..", "https://xn--.example",
    "https://[fe80::1%25en0]", None, False, 0,
])
def test_bad_urls_deny_even_when_policy_disabled(policy_env, bad):
    wp, config, write = policy_env
    write(enabled=False, strict=False)
    assert wp.check_website_access(bad, config) is not None


@pytest.mark.parametrize("rule", ["*", "ex*.com", "?.example", "*.https://example.com", "*.192.0.2.1", "# comment", "https://user@example.com", "bad..example"])
def test_bad_rules_cannot_be_masked_by_good_rule(policy_env, rule):
    wp, config, write = policy_env
    write(allowlist_domains=["allowed.example", rule])
    assert wp.check_website_access("https://allowed.example", config) is not None


@pytest.mark.parametrize("transition", ["edit", "profile"])
def test_disabled_cache_cannot_hide_policy_edits_or_profile_switch(policy_env, monkeypatch, transition):
    wp, config, write = policy_env
    write(enabled=False, strict=False)
    assert wp.check_website_access("https://allowed.example") is None
    if transition == "edit":
        write(strict=False, domains=["allowed.example"])
    else:
        other = config.parent / "other-profile"
        other.mkdir()
        (other / "config.yaml").write_text(json.dumps({"security": {"website_blocklist": {
            "enabled": True, "domains": ["allowed.example"],
        }}}), encoding="utf-8")
        monkeypatch.setenv("HERMES_HOME", str(other))
    assert wp.check_website_access("https://allowed.example") is not None


def test_allowlist_file_edits_take_effect_immediately(policy_env):
    wp, config, write = policy_env
    allow = config.parent / "allow.txt"
    allow.write_text("allowed.example", encoding="utf-8")
    write(allowlist_files=[allow.name])
    assert wp.check_website_access("https://allowed.example") is None
    allow.write_text("other.example", encoding="utf-8")
    assert wp.check_website_access("https://allowed.example") is not None
    allow.unlink()
    assert wp.check_website_access("https://other.example") is not None


def test_attended_blocklist_and_omitted_policy_remain_supported(policy_env):
    wp, config, write = policy_env
    assert wp.check_website_access("https://allowed.example") is None
    write(strict=False, domains=["blocked.example"])
    assert wp.check_website_access("https://allowed.example") is None
    assert wp.check_website_access("https://sub.blocked.example") is not None
