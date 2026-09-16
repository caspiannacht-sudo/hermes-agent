"""Hosted-only native startup successor; no prior policy matrix rerun."""
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
PLAN = json.loads((ROOT / 'ci/startup-plan.json').read_text())
# Short, unique hosted scratch keeps native AF_UNIX paths within macOS limits.
OUT = Path(tempfile.mkdtemp(prefix='as-', dir='/tmp'))
PYTHON = str(ROOT / '.test-env/bin/python')
assert subprocess.check_output(['git', 'rev-parse', 'HEAD^'], text=True).strip() == PLAN['base']
for name, digest in PLAN['input_hashes'].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name

for item in PLAN['tests']:
    key = item['key']
    home = OUT / key / 'home'
    home.mkdir(parents=True)
    xml = OUT / key / 'junit.xml'
    env = {'PATH': str(ROOT / '.test-env/bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
           'HOME': str(home), 'HERMES_PYTHON': PYTHON,
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    cmd = ['/bin/bash', 'scripts/run_tests.sh', '-j', '1', '--file-timeout', '90',
           '--file-retries', '0', item['file'], '--', '--basetemp=' + tempfile.mkdtemp(prefix='', dir='/tmp'),
           '--junitxml=' + str(xml), '-v']
    done = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=150)
    print('=== CASE', key, 'EXIT', done.returncode, '===', flush=True)
    print(done.stdout, done.stderr, flush=True)
    assert xml.is_file(), 'Missing JUnit; collection/setup failure is not qualification'
    raw = xml.read_bytes()
    cases = ET.fromstring(raw).findall('.//testcase')
    chunks = [raw.hex()[i:i+4000] for i in range(0, len(raw.hex()), 4000)]
    for index, chunk in enumerate(chunks):
        print('XML_CHUNK ' + key + ' ' + str(index) + ' ' + chunk, flush=True)
    receipt = {'key': key, 'file': item['file'], 'exit': done.returncode,
               'count': len(cases), 'chunks': len(chunks),
               'sha256': hashlib.sha256(raw).hexdigest(),
               'names': [c.attrib['name'] for c in cases],
               'failures': [c.attrib['name'] for c in cases if c.find('failure') is not None],
               'errors': [c.attrib['name'] for c in cases if c.find('error') is not None],
               'skipped': [c.attrib['name'] for c in cases if c.find('skipped') is not None]}
    print('STARTUP_RECEIPT ' + json.dumps(receipt), flush=True)
    assert receipt['names'] == item['names']
    assert done.returncode == 0 and not receipt['failures'] and not receipt['errors'] and not receipt['skipped']
for name, digest in PLAN['input_hashes'].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
assert not subprocess.check_output(['git', 'diff', 'HEAD', '--name-only']).strip()
print('STARTUP_SLICE_ACCEPTED: scope and substitutions in startup-plan.json; no production transition', flush=True)
