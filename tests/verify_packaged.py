"""Check frozen CLI resource loading and dry-run exits; never applies policy."""
import json
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
import certlock

parser = argparse.ArgumentParser()
parser.add_argument('--release-dir', type=Path,
                    default=root / 'dist' / ('CertLock_v' + certlock.APP_VERSION + '-portable'))
release = parser.parse_args().release_dir.resolve()
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
    from signature_fixtures import make_pe, make_signed_fixture
    signed, _, _ = make_signed_fixture()
    signed_file = Path(tmp) / 'signed-fixture.exe'
    signed_file.write_bytes(make_pe(signed))
    assert run('--dry-run', '--block', signed_file) == 0
    signed_file.write_bytes(make_pe(signed, duplicate=True))
    assert run('--dry-run', '--block', signed_file) != 0
    assert run('--hash', signed_file) == certlock.EXIT_OPERATION_FAILED
assert run('--preset-export', preset) == certlock.EXIT_OPERATION_FAILED
print('Packaged EXE: embedded certificates, export and invalid-template handling verified')
