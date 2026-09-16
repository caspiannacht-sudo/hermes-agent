"""Hosted-only coherent-policy and combined-candidate qualification."""
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
PLAN = json.loads((ROOT / 'ci/policy-plan.json').read_text())
OUT = Path(tempfile.mkdtemp(prefix='policy-candidate-'))
PYTHON = str(ROOT / '.test-env/bin/python')


def run_case(key, file, expected_count, *, selector=None, expected_failure=None):
    work = OUT / key
    home = work / 'home'
    home.mkdir(parents=True)
    xml = work / 'junit.xml'
    env = {'PATH': str(ROOT / '.test-env/bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
           'HOME': str(home), 'HERMES_PYTHON': PYTHON,
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    cmd = ['/bin/bash', 'scripts/run_tests.sh', '-j', '1', '--file-timeout', '90',
           '--file-retries', '0', file, '--', '--junitxml=' + str(xml), '-v']
    if selector:
        cmd += ['-k', selector]
    done = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=150)
    print('=== CASE', key, 'EXIT', done.returncode, '===', flush=True)
    print(done.stdout, done.stderr, flush=True)
    assert xml.is_file(), 'Missing JUnit: collection/setup failure is not expected red'
    raw = xml.read_bytes()
    cases = ET.fromstring(raw).findall('.//testcase')
    # Emit exact raw evidence even if a later acceptance assertion fails.
    chunks = [raw.hex()[i:i+4000] for i in range(0, len(raw.hex()), 4000)]
    for index, chunk in enumerate(chunks):
        print('XML_CHUNK ' + key + ' ' + str(index) + ' ' + chunk, flush=True)
    receipt = {'key': key, 'file': file, 'exit': done.returncode, 'count': len(cases),
               'chunks': len(chunks), 'sha256': hashlib.sha256(raw).hexdigest(),
               'failures': [c.attrib['name'] for c in cases if c.find('failure') is not None],
               'errors': [c.attrib['name'] for c in cases if c.find('error') is not None],
               'skipped': [c.attrib['name'] for c in cases if c.find('skipped') is not None]}
    print('POLICY_RECEIPT ' + json.dumps(receipt), flush=True)
    assert len(cases) == expected_count and not receipt['errors'] and not receipt['skipped']
    failures = [c.find('failure') for c in cases if c.find('failure') is not None]
    if expected_failure:
        assert done.returncode == 1 and len(failures) == expected_count
        assert all(expected_failure in (f.attrib.get('message', '') + (f.text or '')) for f in failures)
    else:
        assert done.returncode == 0 and not failures


# The baseline swaps ONE reviewed production file back to the public predecessor.
# Tests use only the old public API; missing-new-API imports are not a red result.
engine = ROOT / 'tools/website_policy.py'
final_engine = engine.read_bytes()
try:
    engine.write_bytes(subprocess.check_output(['git', 'show', PLAN['base'] + ':tools/website_policy.py']))
    run_case('engine-baseline', 'tests/tools/test_website_policy_strict.py', 12,
             selector='test_strict_requires_enabled_matching_allowlist',
             expected_failure='assert None is not None')
finally:
    engine.write_bytes(final_engine)

# Policy engine, context lifetime, shared dispatch and actual guarded transport
# must all qualify before the combined status/banner/startup-prefix stage begins.
for item in PLAN['policy_tests']:
    run_case(item['key'], item['file'], item['count'])
print('COHERENT_POLICY_TESTS_PASSED', flush=True)
for item in PLAN['combined_tests']:
    run_case(item['key'], item['file'], item['count'])

# Discriminating actual-callsite control: retain patched status helper but restore
# the predecessor startup module. The real start-prefix test must detect stale I/O.
startup = ROOT / 'gateway/run_startup.py'
final_startup = startup.read_bytes()
try:
    startup.write_bytes(subprocess.check_output(['git', 'show', PLAN['base'] + ':gateway/run_startup.py']))
    run_case('startup-negative', 'tests/gateway/test_startup_status_native.py', 1,
             expected_failure='native startup retained stale platform diagnostics')
finally:
    startup.write_bytes(final_startup)
assert not subprocess.check_output(['git', 'diff', '--name-only']).strip(), 'Tracked candidate bytes changed'
print('COMBINED_CANDIDATE_ACCEPTED: bounded native policy, banner, status and startup-prefix coverage only', flush=True)
