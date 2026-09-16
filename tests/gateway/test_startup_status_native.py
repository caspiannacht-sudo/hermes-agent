"""Hosted-only actual GatewayRunner.start prefix -> real status I/O qualification.

The native start method and native environment/status helper run unchanged.
Construction, signals, watchdogs, telemetry and post-prefix platform startup are
not qualified. An explicit shutdown-check boundary stops before platform access.
No source extraction and no sys.modules substitution.
"""
from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
async def test_native_start_resets_stale_status_before_early_abort(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import status
    from gateway.run import GatewayRunner
    from gateway.run_startup import GatewayStartupMixin
    from hermes_cli import config, profiles, security_advisories
    from agent.monitoring import gateway_health_export
    import hermes_startup_watchdog

    # No SDK, adapter, provider or owner is constructed. Collaborator substitutions
    # are named below; the status writer and startup callsite are NOT substituted.
    runner = object.__new__(GatewayRunner)
    runner.config = SimpleNamespace(sessions_dir=tmp_path / "sessions")
    monkeypatch.setattr(runner, "_start_install_faulthandler", lambda: None)
    monkeypatch.setattr(runner, "_start_loop_liveness_guards", lambda loop: None)
    monkeypatch.setattr(runner, "_start_log_systemd_timing_alignment", lambda: None)
    monkeypatch.setattr(hermes_startup_watchdog, "disarm_startup_watchdog", lambda: None)
    monkeypatch.setattr(config, "load_config", lambda: {})
    monkeypatch.setattr(profiles, "get_active_profile_name", lambda: "default")
    monkeypatch.setattr(gateway_health_export, "start_gateway_health_export",
                        lambda cfg: SimpleNamespace(enabled=False))
    monkeypatch.setattr(security_advisories, "detect_compromised", lambda: [])
    monkeypatch.setattr(security_advisories, "gateway_log_message", lambda found: None)

    for platform in ("discord", "old:telegram"):
        status.write_runtime_status(platform=platform, platform_state="paused")
    status.write_runtime_status(gateway_state="stopped", exit_reason="synthetic-old-exit")
    observed = []

    async def stop_before_external_startup():
        record = status.read_runtime_status()
        assert record["platforms"] == {}, "native startup retained stale platform diagnostics"
        assert record["gateway_state"] == "starting"
        assert record["exit_reason"] is None
        observed.append(record)
        return True

    monkeypatch.setattr(runner, "_abort_startup_if_shutdown_requested", stop_before_external_startup)
    assert GatewayRunner.start is GatewayStartupMixin.start
    assert await runner.start() is True
    assert len(observed) == 1
    # Prove normal post-reset merge/provenance remains native too.
    for platform in ("telegram", "fresh:discord"):
        status.write_runtime_status(platform=platform, platform_state="connected")
    record = status.read_runtime_status()
    assert set(record["platforms"]) == {"telegram", "fresh:discord"}
    for entry in record["platforms"].values():
        assert entry["writer_pid"] == record["pid"]
        assert entry["writer_start_time"] == record["start_time"]
