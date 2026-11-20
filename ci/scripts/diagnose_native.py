# SPDX-License-Identifier: Apache-2.0
"""Collect typed evidence for a frozen selection of failed native cases once."""
import argparse
import json
from pathlib import Path
import shutil
import sys
import traceback
from types import SimpleNamespace

sys.dont_write_bytecode = True
from common import digest, save
from native_matrix import install, context, catalogue_for
from native_verdict import classify, fingerprint, observation
from soft_hsm_gate import prepare


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--row', type=json.loads, required=True)
    p.add_argument('--root', type=Path, required=True)
    args = p.parse_args()
    root = args.root.resolve(strict=True)
    selection = json.loads(Path(__file__).with_name('diagnostic-selection.json').read_text())
    selected = [s for s in selection if s['context'] == context(args.row)]
    if not selected or len({s['case'] for s in selected}) != len(selected):
        raise ValueError('empty or repeated diagnostic selection')
    opts, runtime = install(args.row, root)
    kit, gate, output = root / 'native-kit', root / 'native-gate', root / 'diagnostics'
    output.mkdir()
    save(output / 'identity.json', dict(selection_sha256=digest(Path(__file__).with_name('diagnostic-selection.json')),
         kit=json.loads((kit / 'identity.json').read_text()), runtime=runtime['receipt'], selected=selected))
    prepare(SimpleNamespace(**opts, output=gate))
    sys.path.insert(0, str(opts['package'] / 'tests/driver'))
    from case import run_case
    from report_validation import read_records
    cases = catalogue_for(opts['package'])
    policy = json.loads(Path(__file__).with_name('native-divergences.json').read_text())
    frozen = dict(rust=args.row['rust'], recipe_name='openssl-full', backend=args.row['backend'],
        interface=args.row['interface'], source_sha256=opts['source_sha256'], worker=kit / 'worker',
        worker_sha256=digest(kit / 'worker'), gate=gate / 'gate.json', gate_sha256=digest(gate / 'gate.json'),
        recipe=opts['recipe'], verify_engine=kit / 'engine.so', verify_engine_sha256=digest(kit / 'engine.so'))
    counts = {}
    with (output / 'observations.jsonl').open('x') as journal:
        for index, item in enumerate(selected):
            identity = item['case']
            manifest, axes = cases[identity]
            if item['context'] not in axes:
                raise ValueError('diagnostic outside the case contexts')
            definition, = [d for d in json.loads(manifest.read_text()) if d['id'] == identity]
            if fingerprint(definition) != item['definition_sha256']:
                raise ValueError('diagnostic case definition changed')
            work = root / ('diagnostic-case-' + str(index))
            failure = None
            try:
                result = run_case(SimpleNamespace(**frozen, case=identity, manifest=manifest,
                    manifest_sha256=digest(manifest), root=work))
            except Exception as error:
                origin = traceback.extract_tb(error.__traceback__)[-1]
                failure = dict(type=type(error).__name__, file=Path(origin.filename).name, line=origin.lineno)
                result = json.loads((work / 'result.json').read_text()) if (work / 'result.json').is_file() else {'status':'INCOMPLETE'}
            row = dict(case=identity, context=item['context'], result=result, driver_failure=failure,
                       definition_sha256=item['definition_sha256'])
            # result.json has typed public records, hashes and process status.
            # Raw streams, generated key bytes, configuration and tokens never leave the runner.
            if (work / 'observer.json').is_file():
                row['observed_functions'] = json.loads((work / 'observer.json').read_text())['functions']
            if (work / 'token-cleanup.json').is_file():
                row['token_cleanup'] = json.loads((work / 'token-cleanup.json').read_text())
            try:
                row['ci_verdict'] = classify(policy, identity, item['context'], item['definition_sha256'], result, work, runtime)
                if result.get('status') == 'FAIL':
                    row['observation_sha256'] = observation(result, work, runtime, prerequisite=not result.get('body_started'))
            except Exception as error:
                row['classification_error'] = type(error).__name__
            journal.write(json.dumps(row) + '\n')
            journal.flush()
            counts[result['status']] = counts.get(result['status'], 0) + 1
            print(json.dumps(dict(completed=index+1,total=len(selected),case=identity,status=result['status'])), flush=True)
            if (work / 'tokens').exists() or row.get('token_cleanup') != {'status':'REMOVED'}:
                raise ValueError('diagnostic token cleanup incomplete')
            # Only this numbered directory was created by this invocation.
            if work.is_symlink() or work.resolve().parent != root:
                raise ValueError('diagnostic cleanup outside runner root')
            shutil.rmtree(work)
    save(output / 'summary.json', dict(selected=len(selected), results=counts, attempts_per_case=1))
    # This is a collector, not an acceptance gate: failures remain explicit in the records.


if __name__ == '__main__':
    main()
