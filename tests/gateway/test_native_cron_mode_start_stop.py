"""Hosted-only constructor -> normal no-platform startup -> idle native stop.

No __new__, extracted source, fake runner, replacement start/stop, provider or
adapter. Optional integrations are explicitly seamed; see PLAN.md. This tests
cron-capable runner mode, NOT the outer cron scheduler or complete gateway.
"""
import asyncio
import json
import logging
import os
from pathlib import Path

import pytest


async def _settled(task, label, seconds=15):
    """Observation bound only: do not turn cancellation into a passing outcome."""
    done, pending = await asyncio.wait({task}, timeout=seconds)
    assert not pending, f"INCONCLUSIVE: {label} did not settle; hosted owner must clean up"
    return task.result()


@pytest.mark.asyncio
async def test_real_constructor_normal_cron_mode_start_and_idle_stop(
    tmp_path, monkeypatch, caplog,
):
    # Use the canonical fixture's home, including its DB-isolation marker. HOME
    # itself is not redirected by that fixture, so isolate it explicitly here.
    home = Path(os.environ["HERMES_HOME"])
    assert home.is_relative_to(tmp_path)
    assert Path(os.environ["HERMES_TEST_ISOLATION"]) == home
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    (home / "config.yaml").write_text(
        "agent:\n  gateway_startup_warmup_timeout: 0\n"
        "security:\n  tirith_enabled: false\n"
        "gateway:\n  loop_watchdog: false\n"
        "sessions:\n  auto_archive: false\n  auto_prune: false\n"
        "checkpoints:\n  auto_prune: false\n", encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_STARTUP_WARMUP_TIMEOUT", "0")
    monkeypatch.setenv("TIRITH_ENABLED", "false")
    monkeypatch.setenv("HERMES_DISABLE_LAZY_INSTALLS", "1")

    # Make the native empty-work counter and empty auxiliary cleanup imports
    # mandatory: their production best-effort wrappers can otherwise hide an
    # incomplete dependency closure. Neither call constructs a provider client.
    from cron.scheduler import get_running_job_ids
    from agent.auxiliary_client import shutdown_cached_clients
    assert get_running_job_ids() == []
    assert callable(shutdown_cached_clients)
    from gateway import run, status
    from gateway.config import GatewayConfig
    from gateway.run_startup import GatewayStartupMixin
    from gateway.run_shutdown import GatewayShutdownMixin
    from gateway.shutdown_watchdog import get_loop_heartbeat_path, get_loop_tick_socket_path

    # Fail rather than silently rebind an already-imported production module.
    assert run._hermes_home == home
    assert run.GatewayRunner.start is GatewayStartupMixin.start
    assert run.GatewayRunner.stop is GatewayShutdownMixin.stop
    caplog.set_level(logging.DEBUG)
    calls = []

    def optional_noop(name):
        def invoke(*args, **kwargs):
            calls.append(name)
        return invoke

    # Exactly enumerated optional boundaries. All constructor phases stay real.
    monkeypatch.setattr(run.GatewayRunner, "_start_install_faulthandler",
                        optional_noop("faulthandler"))
    monkeypatch.setattr(run.GatewayRunner, "_start_log_systemd_timing_alignment",
                        optional_noop("systemd_timing"))
    monkeypatch.setattr(run.GatewayRunner, "_start_register_plugins_relay_hooks",
                        staticmethod(optional_noop("plugin_relay_shell_registration")))
    monkeypatch.setattr(run.GatewayRunner, "_start_free_tier_bootstrap",
                        staticmethod(optional_noop("free_tier_bootstrap")))

    async def no_room_start(self):
        calls.append("room_start")

    async def no_room_stop(self, timeout=5.0):
        calls.append("room_stop")
        return True

    monkeypatch.setattr(run.GatewayRunner, "_ensure_hosted_room_worker", no_room_start)
    monkeypatch.setattr(run.GatewayRunner, "_stop_hosted_room_worker", no_room_stop)

    def no_global_tool_sweep(phase):
        calls.append("tool_sweep:" + phase)
        return []

    monkeypatch.setattr(run.GatewayRunner, "_stop_kill_tool_subprocesses",
                        staticmethod(no_global_tool_sweep))

    # Keep actual task creation, retention, on_spawn and cancellation machinery;
    # replace only each enumerated watcher's business body with an inert waiter.
    # Unknown names FAIL, rather than quietly admitting a new integration.
    allowed = {
        "hosted_room_worker", "session_housekeeping_watcher",
        "model_catalog_refresh_watcher", "session_stall_watcher",
        "kanban_notifier_watcher", "kanban_dispatcher_watcher",
        "platform_reconnect_watcher", "handoff_watcher",
        "async_delegation_watcher", "loop_wakeup_watcher",
        "profile_reconcile_watcher", "drain_control_watcher",
    }
    native_spawn = run.GatewayRunner._spawn_supervised
    spawned = {}
    entered = set()
    exited = set()
    all_entered = asyncio.Event()

    def supervised_idle(self, coro_factory, name, **kwargs):
        assert name in allowed, f"unreviewed supervised integration: {name}"
        assert name not in spawned, f"duplicate startup watcher: {name}"

        async def idle():
            entered.add(name)
            if entered == allowed:
                all_entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                exited.add(name)

        task = native_spawn(self, idle, name, **kwargs)
        spawned[name] = task
        return task

    monkeypatch.setattr(run.GatewayRunner, "_spawn_supervised", supervised_idle)
    # Clean-marker recovery is real, not mocked. No pre-existing work is seeded.
    marker = home / ".clean_shutdown"
    marker.touch()
    runner = run.GatewayRunner(GatewayConfig(
        platforms={}, sessions_dir=home / "sessions", loop_watchdog=False,
        multiplex_profiles=False,
    ))
    start_task = stop_task = None
    try:
        assert runner._session_db_init_error is None
        db = runner.session_store._db
        assert db is not None and db._conn is not None
        assert Path(db.db_path) == home / "state.db"
        assert runner._session_db._db is db
        assert not runner._running and not runner._shutdown_event.is_set()
        start_task = asyncio.create_task(runner.start())
        assert await _settled(start_task, "native start") is True
        assert runner._running and not runner.should_exit_cleanly
        assert not runner._startup_restore_in_progress
        assert runner._startup_warmup_task is None
        assert runner.adapters == {} and runner._profile_adapters == {}
        assert runner._failed_platforms == {}
        assert not marker.exists(), "native recovery did not consume clean marker"
        assert status.read_runtime_status()["gateway_state"] == "running"
        assert set(spawned) == allowed
        entered_task = asyncio.create_task(all_entered.wait())
        try:
            assert await _settled(entered_task, "supervised task entry", 5) is True
        finally:
            # Observer-only cleanup, not native resource cleanup.
            if not entered_task.done():
                entered_task.cancel()
                await asyncio.gather(entered_task, return_exceptions=True)
        assert all(not task.done() for task in spawned.values())
        heartbeat = runner._loop_heartbeat_task
        poller = runner._heartbeat_poll_task
        assert heartbeat in runner._background_tasks and not heartbeat.done()
        assert poller in runner._background_tasks and not poller.done()

        # Actual heartbeat's first disk write + Unix listener, not mere spawn.
        heartbeat_path = get_loop_heartbeat_path(home)
        deadline = asyncio.get_running_loop().time() + 10
        while not heartbeat_path.exists():
            assert asyncio.get_running_loop().time() < deadline, "heartbeat readiness timeout"
            await asyncio.sleep(0.01)
        beat = json.loads(heartbeat_path.read_text(encoding="utf-8"))
        assert beat["pid"] == os.getpid() and beat["loop_tick_socket"] is True
        tick_path = get_loop_tick_socket_path(home)
        assert tick_path.exists()
        owned = set(runner._background_tasks)
        assert set(spawned.values()) <= owned
        executor = runner._executor
        assert executor is not None, "native recovery/heartbeat scan did not use runner executor"

        stop_task = asyncio.create_task(runner.stop())
        assert await _settled(stop_task, "native stop") is None
        # Native stop issues cancellations synchronously; allow their native
        # finally blocks to settle, without test cancellation or socket/DB closes.
        done, pending = await asyncio.wait(owned, timeout=5)
        assert not pending, "native stop left background resources unsettled"
        for task in done:
            if not task.cancelled():
                assert task.exception() is None
        assert exited == entered == allowed
        assert not tick_path.exists(), "native heartbeat failed to close its listener"
        assert db._conn is None and db._read_conns_closed
        assert not runner._session_db_handles
        assert all(not thread.is_alive() for thread in executor._threads)
        assert runner._executor_closing
        assert runner._shutdown_event.is_set() and runner._shutdown_watchdog_done.is_set()
        assert runner._stop_task.done() and runner._stop_task.exception() is None
        assert not runner._running and not runner._background_tasks
        assert marker.exists()
        assert status.read_runtime_status()["gateway_state"] == "stopped"
        assert calls == [
            "faulthandler", "systemd_timing", "plugin_relay_shell_registration",
            "free_tier_bootstrap", "room_start", "room_stop", "tool_sweep:final-cleanup",
        ]
        # Don't admit a green result produced by swallowed optional import errors.
        assert not [r for r in caplog.records if r.exc_info or r.levelno >= logging.ERROR]
    finally:
        # Failure cleanup uses the SAME native stop, never manual success-making
        # DB/task cleanup. Unsettled startup is left for the bounded hosted owner.
        if start_task is None or start_task.done():
            if stop_task is None:
                stop_task = asyncio.create_task(runner.stop())
            await _settled(stop_task, "failure-path native stop")
