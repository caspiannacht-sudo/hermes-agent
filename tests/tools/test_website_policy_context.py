"""New ContextVar API tests; native module imports and synthetic config only.

Unlike test_website_policy_strict.py these require the proposed new public API.
They qualify context mechanics, not scheduler placement or transport enforcement.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import Context, copy_context
import importlib
import json
from pathlib import Path
from threading import Event

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    wp = importlib.import_module("tools.website_policy")
    config = tmp_path / "config.yaml"

    def write(**values):
        policy = {"enabled": True, "strict": False, "allowlist_domains": ["allowed.example"], **values}
        config.write_text(json.dumps({"security": {"website_blocklist": policy}}), encoding="utf-8")

    write()
    return wp, config, write


def test_nested_token_reset_restores_previous_strictness(env):
    wp, _, _ = env
    def exercise():
        assert not wp.is_strict_website_policy()
        outer = wp.begin_unattended_website_policy()
        try:
            assert wp.is_strict_website_policy()
            inner = wp.begin_unattended_website_policy()
            try:
                assert wp.check_website_access("https://other.example") is not None
            finally:
                wp.end_unattended_website_policy(inner)
            assert wp.is_strict_website_policy()
        finally:
            wp.end_unattended_website_policy(outer)
        assert not wp.is_strict_website_policy()
        assert wp.check_website_access("https://other.example") is None
    Context().run(exercise)


@pytest.mark.parametrize("values", [{"enabled": False}, {"allowlist_domains": []}, {"mode": "blocklist", "allowlist_domains": []}])
def test_context_forces_allowlist_per_call(env, values):
    wp, _, write = env
    write(**values)
    def exercise():
        assert wp.check_website_access("https://other.example") is None
        token = wp.begin_unattended_website_policy()
        try:
            assert wp.check_website_access("https://other.example") is not None
        finally:
            wp.end_unattended_website_policy(token)
        assert wp.check_website_access("https://other.example") is None
    Context().run(exercise)


def test_context_allows_valid_target_but_block_rule_wins(env):
    wp, _, write = env
    write(domains=["secret.allowed.example"])
    def exercise():
        token = wp.begin_unattended_website_policy()
        try:
            assert wp.check_website_access("https://allowed.example") is None
            assert wp.check_website_access("https://secret.allowed.example") is not None
        finally:
            wp.end_unattended_website_policy(token)
    Context().run(exercise)


def test_config_strict_survives_context_reset(env):
    wp, _, write = env
    write(strict=True)
    token = wp.begin_unattended_website_policy()
    wp.end_unattended_website_policy(token)
    assert wp.is_strict_website_policy()
    assert wp.check_website_access("https://other.example") is not None


@pytest.mark.parametrize("failure", ["missing", "yaml", "root", "shape", "file", "generic"])
def test_strict_query_is_true_on_unknown_policy(env, monkeypatch, failure):
    wp, config, write = env
    if failure == "missing":
        config.unlink()
    elif failure == "yaml":
        config.write_text("[", encoding="utf-8")
    elif failure == "root":
        config.write_text("false", encoding="utf-8")
    elif failure == "shape":
        write(strict=False, allowlist_domains=False)
    elif failure == "file":
        write(allowlist_files=["missing.txt"])
    else:
        original = Path.read_text
        def fail(path, *args, **kwargs):
            if path == config:
                raise RuntimeError("synthetic generic read failure")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(Path, "read_text", fail)
    assert Context().run(wp.is_strict_website_policy) is True
    assert wp.check_website_access("https://allowed.example") is not None


def test_copied_worker_remains_strict_after_parent_reset(env):
    wp, _, _ = env
    entered, release = Event(), Event()
    def worker():
        entered.set()
        assert release.wait(5), "test release not received"
        return wp.is_strict_website_policy(), wp.check_website_access("https://other.example")

    def exercise():
        token = wp.begin_unattended_website_policy()
        inherited = copy_context()
        wp.end_unattended_website_policy(token)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(inherited.run, worker)
            try:
                assert entered.wait(5), "worker did not start"
                assert not wp.is_strict_website_policy()
                assert wp.check_website_access("https://other.example") is None
            finally:
                release.set()
            strict, denial = future.result(timeout=5)
        assert strict is True and denial is not None
        assert not wp.is_strict_website_policy()
    Context().run(exercise)


def test_async_sibling_contexts_do_not_leak(env):
    wp, _, _ = env
    async def exercise():
        entered, release = asyncio.Event(), asyncio.Event()
        async def strict_task():
            token = wp.begin_unattended_website_policy()
            try:
                entered.set()
                await release.wait()
                return wp.check_website_access("https://other.example")
            finally:
                wp.end_unattended_website_policy(token)
        task = asyncio.create_task(strict_task())
        try:
            await asyncio.wait_for(entered.wait(), 5)
            assert not wp.is_strict_website_policy()
            assert wp.check_website_access("https://other.example") is None
        finally:
            release.set()
        assert await asyncio.wait_for(task, 5) is not None
        assert not wp.is_strict_website_policy()
    Context().run(asyncio.run, exercise())


def test_finally_restores_on_base_exception(env):
    wp, _, _ = env
    def exercise():
        with pytest.raises(KeyboardInterrupt):
            token = wp.begin_unattended_website_policy()
            try:
                raise KeyboardInterrupt
            finally:
                wp.end_unattended_website_policy(token)
        assert not wp.is_strict_website_policy()
    Context().run(exercise)
