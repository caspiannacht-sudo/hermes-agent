"""Hosted-only red/green/wiring discriminator. No live services or private fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
PYTHON = str(ROOT / '.test-env/bin/python')
TEST = 'tests/gateway/test_aurelian_status_reset.py'
EXPECTED = {'test_fresh_status_reset_and_normal_merge', 'test_reset_first_write_and_selective_profile_removal', 'test_startup_status_reset_wiring'}
OUT = Path(tempfile.mkdtemp(prefix='status-evidence-'))

def run_phase(name, expected_failures):
    home = OUT / name / 'home'
    home.mkdir(parents=True)
    xml = OUT / name / 'junit.xml'
    env = {'PATH': str(ROOT / '.test-env/bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
           'HOME': str(home), 'HERMES_PYTHON': PYTHON,
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    cmd = ['/bin/bash','scripts/run_tests.sh','-j','1','--file-timeout','90','--file-retries','0',TEST,'--','--junitxml='+str(xml),'-v']
    # The disposable GitHub VM/job deadline is the outer containment boundary.
    # Canonical runner owns its subprocess groups; no host services are present.
    done = subprocess.run(cmd, env=env, capture_output=True, text=True)
    (OUT / name / 'runner.log').write_text(done.stdout + done.stderr)
    print('=== PHASE',name,'EXIT',done.returncode,'===',flush=True)
    print(done.stdout, done.stderr, flush=True)
    assert xml.is_file(), 'No JUnit receipt; collection/setup/timeout is not red evidence'
    raw = xml.read_text()
    print(raw,flush=True)
    cases = ET.fromstring(raw).findall('.//testcase')
    assert len(cases) == 3 and {c.attrib['name'] for c in cases} == EXPECTED
    assert not any(c.find('error') is not None or c.find('skipped') is not None for c in cases)
    failures = {c.attrib['name']:c.find('failure') for c in cases if c.find('failure') is not None}
    assert set(failures) == expected_failures, 'Unexpected failure set'
    assert done.returncode == (1 if expected_failures else 0), 'Unexpected runner result'
    for name_, failure in failures.items():
        text = failure.attrib.get('message','') + (failure.text or '')
        if name_ == 'test_startup_status_reset_wiring':
            assert 'startup must explicitly reset all platform diagnostics' in text
        else:
            assert 'TypeError' in text and 'reset_platforms' in text and 'unexpected keyword' in text
    print(json.dumps({'phase':name,'tests':len(cases),'failures':sorted(failures),'junit_sha256':hashlib.sha256(raw.encode()).hexdigest()}),flush=True)

run_phase('baseline', EXPECTED)
subprocess.run(['git','apply','--check','ci/status-reset.patch'], check=True)
subprocess.run(['git','apply','ci/status-reset.patch'], check=True)
run_phase('patched', set())
startup = ROOT / 'gateway/run_startup.py'
patched = startup.read_bytes()
baseline = subprocess.check_output(['git','show','HEAD:gateway/run_startup.py'])
startup.write_bytes(baseline)
try:
    run_phase('wiring-negative-control', {'test_startup_status_reset_wiring'})
finally:
    startup.write_bytes(patched)
print('STATUS_SLICE_ACCEPTED: helper I/O + structural wiring only; no gateway startup or deployment qualification',flush=True)
