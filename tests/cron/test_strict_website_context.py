"""Native scheduler/policy integration contracts (proposed; not locally executed).

Requires the companion website-policy engine API. No sys.modules substitution,
source extraction, or fake policy. External effects are controlled at boundaries;
run_job, prompt gates and the actual copy_context worker handoff remain real.
"""
import builtins
import contextvars
import threading
from types import SimpleNamespace

import pytest


class StopRun(BaseException):
    pass


@pytest.fixture
def lane(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    home = tmp_path / 'hermes'
    home.mkdir()
    # Unknown/missing configuration is deliberately strict. A valid empty
    # synthetic config is required to test restoration to an attended false state.
    (home / 'config.yaml').write_text('{}', encoding='utf-8')
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.chdir(tmp_path)
    from hermes_cli import env_loader
    monkeypatch.setattr(env_loader, 'load_hermes_dotenv', lambda *a, **k: [])
    from tools import website_policy as policy
    from cron import scheduler as sched
    from hermes_cli import config
    from cron import scheduler_detached_worker as detached

    # A fresh Context isolates policy tokens from other tests, including failures.
    ctx = contextvars.Context()
    assert ctx.run(policy.is_strict_website_policy) is False, 'synthetic attended baseline must be non-strict'
    seen = []

    def record(label, value=None):
        def call(*args, **kwargs):
            seen.append((label, policy.is_strict_website_policy()))
            return value
        return call

    monkeypatch.setattr(config, 'require_parseable_user_config', record('config'))
    monkeypatch.setattr(sched, '_apply_monitor_gate', record('monitor', (None, None)))
    monkeypatch.setattr(sched, '_build_job_prompt', record('prompt', 'synthetic prompt'))
    monkeypatch.setattr(sched, '_resolve_job_workdir', record('workdir', None))

    class Scope:
        def __init__(self, *args):
            record('scope')()
            self.workdir = None
            self.task_id = 'synthetic-task'
        enter = record('enter')
        exit = record('exit')

    monkeypatch.setattr(sched, '_CronRunScope', Scope)
    monkeypatch.setattr(sched, '_reload_dotenv_and_publish_delivery_target', record('delivery'))
    monkeypatch.setattr(sched, '_load_cron_job_config', record('job_config', SimpleNamespace(cfg={}, model='synthetic')))
    monkeypatch.setattr(sched, '_resolve_cron_agent_setup', record('setup', sched._CronAgentSetup(model='synthetic')))
    monkeypatch.setattr(sched, '_open_cron_session_db', record('db', None))
    agent = SimpleNamespace(run_conversation=record('worker', {'final_response': 'synthetic reply'}))
    monkeypatch.setattr(sched, '_construct_cron_agent', record('agent', agent))
    monkeypatch.setattr(sched, '_cron_inactivity_seconds', lambda: 0)
    monkeypatch.setattr(sched, '_write_usage_audit', record('audit'))
    monkeypatch.setattr(sched, '_teardown_cron_agent', record('teardown'))
    monkeypatch.setattr(detached, 'defer_teardown_to_running_worker', record('detached', False))
    job = {'id': 'synthetic', 'name': 'synthetic', 'prompt': 'synthetic prompt'}
    return SimpleNamespace(s=sched, p=policy, ctx=ctx, seen=seen, record=record,
                           job=job, agent=agent, detached=detached, scope=Scope)


def invoke(lane, **kwargs):
    return lane.ctx.run(lane.s.run_job, lane.job, **kwargs)


def assert_restored(lane):
    assert lane.ctx.run(lane.p.is_strict_website_policy) is False


@pytest.mark.parametrize('prior', [False, True])
def test_success_and_no_agent_preserve_callers_context(lane, monkeypatch, prior):
    p = lane.p
    token = lane.ctx.run(p.begin_unattended_website_policy) if prior else None
    try:
        result = invoke(lane)
        assert result[0] is True and result[2] == 'synthetic reply'
        assert ('worker', True) in lane.seen
        assert lane.seen and all(strict for _, strict in lane.seen)
        assert lane.ctx.run(p.is_strict_website_policy) is prior

        lane.seen.clear()
        lane.job['no_agent'] = True
        expected = (True, 'script doc', 'script output', None)
        monkeypatch.setattr(lane.s, '_run_no_agent_job', lane.record('script-only', expected))
        # Real policy begin is allowed above; no_agent must not even acquire a token.
        def forbidden_begin():
            pytest.fail('no_agent activated website policy')
        monkeypatch.setattr(p, 'begin_unattended_website_policy', forbidden_begin)
        assert invoke(lane) == expected
        assert lane.seen == [('script-only', prior)]
        assert lane.ctx.run(p.is_strict_website_policy) is prior
    finally:
        if token is not None:
            lane.ctx.run(p.end_unattended_website_policy, token)
    assert_restored(lane)


@pytest.mark.parametrize('gate', ['none', 'wake', 'injection', 'monitor', 'blocked'])
def test_real_early_return_gates_restore_policy(lane, monkeypatch, gate):
    s = lane.s
    if gate == 'none':
        monkeypatch.setattr(s, '_build_job_prompt', lane.record('prompt-none'))
    elif gate == 'wake':
        lane.job['script'] = 'synthetic.py'
        monkeypatch.setattr(s, '_run_job_script_with_claim_heartbeat',
                            lane.record('script', (True, '{"wakeAgent": false}')))
    elif gate == 'injection':
        def blocked(*a, **k):
            lane.record('scanner')()
            raise s.CronPromptInjectionBlocked('synthetic blocked input')
        monkeypatch.setattr(s, '_build_job_prompt', blocked)
    elif gate == 'monitor':
        monkeypatch.setattr(s, '_apply_monitor_gate',
                            lane.record('monitor', ((True, '', s.SILENT_MARKER, None), None)))
    else:
        monkeypatch.setattr(s, '_resolve_cron_agent_setup', lane.record('setup',
            s._CronAgentSetup(blocked=(False, 'blocked', '', 'synthetic preflight'))))
    result = invoke(lane)
    assert result[0] is (gate not in ('injection', 'blocked'))
    assert not any(label == 'worker' for label, _ in lane.seen)
    assert lane.seen and all(strict for _, strict in lane.seen)
    assert_restored(lane)


@pytest.mark.parametrize('boundary', ['prompt', 'scope', 'enter', 'delivery', 'setup', 'detached', 'exit', 'teardown'])
@pytest.mark.parametrize('error_type', [RuntimeError, StopRun])
def test_setup_and_cleanup_errors_restore_policy(lane, monkeypatch, boundary, error_type):
    error = error_type('synthetic boundary failure')
    def fail(*a, **k):
        lane.record('failure')()
        raise error
    targets = {
        'prompt': (lane.s, '_build_job_prompt'),
        'scope': (lane.s, '_CronRunScope'),
        'enter': (lane.scope, 'enter'),
        'delivery': (lane.s, '_reload_dotenv_and_publish_delivery_target'),
        'setup': (lane.s, '_resolve_cron_agent_setup'),
        'detached': (lane.detached, 'defer_teardown_to_running_worker'),
        'exit': (lane.scope, 'exit'),
        'teardown': (lane.s, '_teardown_cron_agent'),
    }
    monkeypatch.setattr(*targets[boundary], fail)
    if error_type is RuntimeError and boundary in ('enter', 'delivery', 'setup'):
        result = invoke(lane)
        assert result[0] is False and 'synthetic boundary failure' in result[3]
    else:
        with pytest.raises(error_type) as raised:
            invoke(lane)
        assert raised.value is error
    assert ('failure', True) in lane.seen
    assert all(strict for _, strict in lane.seen)
    assert_restored(lane)


@pytest.mark.parametrize('module', ['run_agent', 'cron.scheduler_detached_worker'])
def test_llm_and_cleanup_import_failure_is_inside_policy_scope(lane, monkeypatch, module):
    real_import = builtins.__import__
    def import_gate(name, *a, **k):
        if name == module:
            lane.record('import')()
            raise ImportError('synthetic agent import failure')
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, '__import__', import_gate)
    with pytest.raises(ImportError, match='synthetic agent import failure'):
        invoke(lane)
    assert ('import', True) in lane.seen
    assert_restored(lane)


def test_actual_copied_worker_retains_strict_after_parent_reset(lane, monkeypatch):
    started, release = threading.Event(), threading.Event()
    observed = []
    futures = []
    def conversation(*a, **k):
        observed.append(lane.p.is_strict_website_policy())
        started.set()
        if not release.wait(10):
            raise AssertionError('parent did not release synthetic worker')
        observed.append(lane.p.is_strict_website_policy())
        return {'final_response': 'synthetic late reply'}
    lane.agent.run_conversation = conversation

    # Use the real executor, real submitted Context.run and real future. Interrupt
    # only the parent's wait boundary, after the worker is demonstrably running.
    import concurrent.futures
    def interrupted_wait(fs, **kwargs):
        futures.extend(fs)
        assert started.wait(5)
        raise RuntimeError('synthetic parent abandonment')
    monkeypatch.setattr(concurrent.futures, 'wait', interrupted_wait)
    try:
        result = invoke(lane, cancel_event=threading.Event())
        assert result[0] is False
        assert started.is_set()
        assert_restored(lane)
    finally:
        release.set()
        for future in futures:
            future.result(timeout=10)
    assert observed == [True, True]
