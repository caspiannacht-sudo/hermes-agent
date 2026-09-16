"""Hosted-only behavioral red/green regression driver; exact JUnit receipts."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
plan = json.loads((ROOT / 'ci/regression-plan.json').read_text())
OUT = Path(tempfile.mkdtemp(prefix='regression-evidence-'))
PYTHON = str(ROOT / '.test-env/bin/python')

def phase(name, expected_failures):
    home = OUT / name / 'home'
    home.mkdir(parents=True)
    xml = OUT / name / 'junit.xml'
    env = {'PATH': str(ROOT / '.test-env/bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
           'HOME': str(home), 'HERMES_PYTHON': PYTHON,
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    cmd = ['/bin/bash', 'scripts/run_tests.sh', '-j', '1', '--file-timeout', '90',
           '--file-retries', '0', plan['test'], '--', '--junitxml='+str(xml), '-v']
    done = subprocess.run(cmd, env=env, capture_output=True, text=True)
    print('=== PHASE', name, 'EXIT', done.returncode, '===', flush=True)
    print(done.stdout, done.stderr, flush=True)
    assert xml.is_file(), 'Missing JUnit; import/setup/timeout is not expected red'
    raw = xml.read_bytes()
    cases = ET.fromstring(raw).findall('.//testcase')
    assert len(cases) == len(plan['tests'])
    assert {c.attrib['name'] for c in cases} == set(plan['tests'])
    assert not any(c.find('error') is not None or c.find('skipped') is not None for c in cases)
    failures = {c.attrib['name']: c.find('failure') for c in cases if c.find('failure') is not None}
    assert set(failures) == set(expected_failures)
    assert done.returncode == (1 if failures else 0)
    for case, failure in failures.items():
        text = failure.attrib.get('message', '') + (failure.text or '')
        assert plan['failure_signature'] in text
    # Hex preserves exact bytes through timestamped Actions log lines.
    print('JUNIT_HEX '+name+' '+raw.hex(), flush=True)
    print('RECEIPT '+json.dumps({'phase': name, 'tests': len(cases), 'failures': sorted(failures),
          'errors': 0, 'skipped': 0, 'exit': done.returncode,
          'junit_sha256': hashlib.sha256(raw).hexdigest()}), flush=True)

phase('baseline', plan['baseline_failures'])
subprocess.run(['git', 'apply', '--check', plan['patch']], check=True)
subprocess.run(['git', 'apply', plan['patch']], check=True)
phase('patched', [])
subprocess.run(['git', 'apply', '--reverse', plan['patch']], check=True)
phase('reverted', plan['baseline_failures'])
print('REGRESSION_ACCEPTED: '+plan['scope'], flush=True)
