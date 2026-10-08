"""Check frozen CLI resource loading and dry-run exits; never applies policy."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
import certlock

release = root / 'dist' / 'CertLock_v2.1.0-portable'
exe = release / 'CertLock.exe'
preset = release / '常用预设-保留WPS.json'


def run(*args):
    return subprocess.run([str(exe), *map(str, args)], timeout=30, check=False).returncode


assert not preset.exists(), 'Refusing to overwrite an existing release preset'
assert run('--preset-export', preset) == 0
assert json.loads(preset.read_text(encoding='utf-8')) == certlock.build_common_template()
with tempfile.TemporaryDirectory(prefix='certlock-package-test-') as tmp:
    invalid = Path(tmp) / 'invalid.json'
    invalid.write_text('{"format_version":"2.0","rules":[]}', encoding='utf-8')
    assert run('--dry-run', '--template-import', invalid) == certlock.EXIT_OPERATION_FAILED
assert run('--preset-export', preset) == certlock.EXIT_OPERATION_FAILED
print('Packaged EXE: embedded certificates, export and invalid-template handling verified')
