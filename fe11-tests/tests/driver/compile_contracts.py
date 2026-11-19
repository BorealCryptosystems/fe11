# SPDX-License-Identifier: Apache-2.0
"""Check public Rust type contracts against an explicitly identified Fe11 rlib.

Only compiler metadata is emitted: no fixture is linked or executed. Every
negative has a positive control. A failed import, missing dependency or unrelated
diagnostic cannot satisfy a negative. The caller supplies an isolated new output
directory and the matching compiler/dependency directory from its own build.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--rlib', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--dependency', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    compiler = args.rustc.resolve(strict=True)
    library = args.rlib.resolve(strict=True)
    manifest = args.manifest.resolve(strict=True)
    root = args.output.resolve()
    root.mkdir(parents=False, exist_ok=False)
    temporary = root/'tmp'
    temporary.mkdir()
    env = dict(os.environ)
    for key in list(env):
        if key.upper().startswith(('CARGO_', 'RUST')):
            del env[key]
    env.update(TEMP=str(temporary), TMP=str(temporary), TMPDIR=str(temporary))
    inputs = dict(compiler_sha256=digest(compiler), library_sha256=digest(library),
                  manifest_sha256=digest(manifest))
    directories = sorted({library.parent, *(p.resolve(strict=True) for p in args.dependency)})
    def dependency_hashes():
        return {str(p): digest(p) for directory in directories for p in directory.iterdir()
                if p.is_file() and p.suffix in ('.rlib', '.rmeta', '.dll', '.so', '.dylib')}
    dependencies = dependency_hashes()
    inputs['dependencies'] = dependencies
    version = subprocess.check_output([str(compiler), '-Vv'], text=True, env=env)
    rows = json.loads(manifest.read_text(encoding='utf8'))
    assert rows and len({row['id'] for row in rows}) == len(rows)
    results = []
    for index, row in enumerate(rows):
        phases = []
        for phase in ('positive', 'negative'):
            specification = row[phase]
            source = (manifest.parent/specification['file']).resolve(strict=True)
            assert source.parent == manifest.parent and not source.is_symlink()
            assert digest(source) == specification['sha256']
            output = root/(str(index)+'-'+phase+'.rmeta')
            command = [str(compiler), '--edition=2021', '--crate-type=lib',
                       '--crate-name', 'contract_'+str(index)+'_'+phase,
                       '--emit=metadata', '--error-format=json', '-Dwarnings',
                       '--extern', 'fe11='+str(library), '-o', str(output), str(source)]
            for directory in directories:
                command.extend(['-L', 'dependency='+str(directory)])
            process = subprocess.run(command, env=env, capture_output=True, timeout=3600)
            prefix = root/(str(index)+'-'+phase)
            prefix.with_suffix('.stderr.jsonl').write_bytes(process.stderr)
            prefix.with_suffix('.stdout').write_bytes(process.stdout)
            diagnostics = [json.loads(line) for line in process.stderr.splitlines() if line]
            errors = [d for d in diagnostics if d.get('level') == 'error' and d.get('code')]
            warnings = [d for d in diagnostics if d.get('level') == 'warning']
            if phase == 'positive':
                valid = process.returncode == 0 and output.is_file() and not errors and not warnings
            else:
                valid = (process.returncode != 0 and not output.exists() and not warnings
                         and len(errors) == 1
                         and errors[0]['code']['code'] == specification['code']
                         and any(s['is_primary'] and s['line_start'] == specification['line']
                                 and Path(s['file_name']).resolve() == source
                                 for s in errors[0]['spans']))
            valid = valid and digest(source) == specification['sha256']
            phases.append(dict(phase=phase, status='PASS' if valid else 'FAIL',
                               source_sha256=digest(source), exit_code=process.returncode,
                               diagnostic_sha256=hashlib.sha256(process.stderr).hexdigest(),
                               errors=[d['code']['code'] for d in errors]))
            if not valid:
                break
        passed = len(phases) == 2 and all(p['status'] == 'PASS' for p in phases)
        results.append(dict(id=row['id'], status='PASS' if passed else 'FAIL', phases=phases))
        # Continue independent compiler cases; every failure remains visible.
    unchanged = (digest(compiler) == inputs['compiler_sha256']
                 and digest(library) == inputs['library_sha256']
                 and digest(manifest) == inputs['manifest_sha256'])
    unchanged = unchanged and dependencies == dependency_hashes()
    status = 'PASS' if unchanged and all(r['status'] == 'PASS' for r in results) else 'FAIL'
    report = dict(status=status, inputs=inputs, compiler_version=version,
                  results=results, sources_unchanged=unchanged, runtime_tests_executed=False)
    (root/'result.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    print(json.dumps(dict(status=status, cases=len(results),
                          passed=sum(r['status'] == 'PASS' for r in results))))
    return 0 if status == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
