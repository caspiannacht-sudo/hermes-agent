"""Local continuity contract: startup reset clears stale diagnostics, not later siblings.

Adapted from the September Aurelian reconciliation. These exercise the real
status-file implementation with synthetic records, not a gateway startup.
"""
from gateway import status


def test_fresh_status_reset_and_normal_merge(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    for platform in ('discord', 'secondary:telegram'):
        status.write_runtime_status(platform=platform, platform_state='paused')
    status.write_runtime_status(gateway_state='starting', exit_reason=None, reset_platforms=True)
    assert status.read_runtime_status()['platforms'] == {}
    for platform in ('telegram', 'secondary:discord'):
        status.write_runtime_status(platform=platform, platform_state='connected')
    record = status.read_runtime_status()
    assert record['gateway_state'] == 'starting'
    assert record['exit_reason'] is None
    assert set(record['platforms']) == {'telegram', 'secondary:discord'}
    for entry in record['platforms'].values():
        assert entry['state'] == 'connected'
        assert entry['writer_pid'] == record['pid']
        assert entry['writer_start_time'] == record['start_time']


def test_reset_first_write_and_selective_profile_removal(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    status.write_runtime_status(platform='stale', platform_state='paused')
    status.write_runtime_status(reset_platforms=True, platform='telegram', platform_state='connecting')
    assert set(status.read_runtime_status()['platforms']) == {'telegram'}
    for platform in ('one:discord', 'two:discord'):
        status.write_runtime_status(platform=platform, platform_state='connected')
    status.write_runtime_status(drop_profile_platforms='one')
    assert set(status.read_runtime_status()['platforms']) == {'telegram', 'two:discord'}
    status.write_runtime_status(clear_profile_platforms=True)
    assert set(status.read_runtime_status()['platforms']) == {'telegram'}


def test_startup_status_reset_wiring():
    """Structural call-site coverage only; not execution of gateway startup."""
    import ast
    from pathlib import Path
    tree = ast.parse((Path(__file__).parents[2] / 'gateway/run_startup.py').read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'GatewayStartupMixin')
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_start_log_startup_environment')
    calls = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == '_write_runtime_status_quiet']
    assert len(calls) == 1
    keywords = {kw.arg: kw.value for kw in calls[0].keywords}
    reset = keywords.get('reset_platforms')
    assert isinstance(reset, ast.Constant) and reset.value is True, 'startup must explicitly reset all platform diagnostics'
