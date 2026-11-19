# SPDX-License-Identifier: Apache-2.0
"""Sequential, separately observed processes sharing or isolating token stores."""
import shlex
import shutil
from pathlib import Path
from process import execute
from run import digest, save, read_records, verify_worker, trace_matches
from dependencies import verify as verify_dependencies
from owned_storage import OwnedTokens

HERE = Path(__file__).resolve().parent
OPEN = ['C_Initialize', 'C_OpenSession', 'C_Login']
EMPTY = ['C_FindObjectsInit', 'C_FindObjects', 'C_FindObjectsFinal']
ONE = ['C_FindObjectsInit', 'C_FindObjects', 'C_FindObjects', 'C_FindObjectsFinal']
CLOSE = ['C_Logout', 'C_CloseSession', 'C_Finalize']
SEQUENCES = {
    'producer': OPEN + EMPTY + ['C_CreateObject', 'C_GetAttributeValue'] + CLOSE,
    'consumer': OPEN + ONE + ['C_GetAttributeValue', 'C_DestroyObject'] + EMPTY + CLOSE,
    'isolated': OPEN + EMPTY + ['C_CreateObject', 'C_GetAttributeValue', 'C_DestroyObject'] + EMPTY + CLOSE,
}


def observe(root, role, environment, wire, command, identities, recipe, gate, functions):
    """Each actor has its own terminal record, native trace and dependency check."""
    vector = root / (role + '.txt')
    with vector.open('x') as stream:
        stream.write('store-process\n' + role + '\n')
    control = root / (role + '-control')
    control.mkdir(mode=0o700)
    output = control / 'observation'
    worker = command('object-contract', 'store-' + role)
    worker[-1] = str(vector)
    report = output / 'worker.jsonl'
    # The observer creates its symbol-root beside its configuration, not beside
    # the trace. Give each actor a distinct configuration parent as well.
    observer_config = control / 'observer.json'
    if not output.resolve().is_relative_to(observer_config.parent.resolve()):
        raise ValueError('observer trace must be inside its control directory')
    save(observer_config, dict(module=worker[5], module_sha256=recipe['sha256'],
                              functions=list(functions), output=str(output / 'trace.jsonl')))
    gdb = shutil.which('gdb', path=environment['PATH'])
    if gdb is None or any('\n' in v or '\r' in v for v in worker + [str(report)]):
        raise ValueError('invalid observed actor command')
    args = ' '.join(shlex.quote(v) for v in worker[1:]) + ' > ' + shlex.quote(str(report))
    observer_script = str(HERE / 'native_observer.py')
    # Continue in the same Python command only after observer installation has
    # succeeded. A script failure must never run unobserved native work.
    observe_then_continue = ("python __import__('runpy').run_path(" + repr(observer_script)
                             + ", run_name='__main__'); __import__('gdb').execute('continue')")
    invocation = [gdb, '-nx', '-nh', '-batch', '-iex', 'set auto-load no',
                  '-iex', 'set debuginfod enabled off', '-iex', 'set print frame-arguments none',
                  '-iex', 'set confirm off', '-iex', 'set disable-randomization off',
                  '-ex', 'set environment LD_DEBUG files', '-ex', 'set args ' + args,
                  '-ex', 'starti', '-ex', observe_then_continue, worker[0]]
    process = execute(invocation, dict(environment, FE11_OBSERVER_CONFIG=str(observer_config)), output, wire)
    dependencies = verify_dependencies(output / 'stderr.raw', gate['dependencies'])
    trace = read_records(output / 'trace.jsonl', maximum=65536)
    if not trace or trace[-1].get('kind') != 'observer_terminal':
        raise ValueError('incomplete actor observation')
    records = verify_worker(report, dict(process, exit_code=trace[-1].get('exit_code')),
                            dict(identities, case='store-' + role), 'terminal', require_success=False)
    expected_exit = 0 if records[-1]['status'] == 'PASS' else 1
    matched = trace_matches(trace, SEQUENCES[role], recipe['sha256'], digest(HERE / 'native_observer.py'),
                            functions, expected_exit_code=expected_exit)
    pids = {r['process'] for r in trace if r.get('kind') == 'entry'}
    if len(pids) != 1:
        raise ValueError('actor must have exactly one observed native process')
    return dict(role=role, process_id=pids.pop(), worker_records=records,
                status='PASS' if matched and process['state'] == 'EXITED' and process['exit_code'] == 0
                and records[-1]['status'] == 'PASS' else 'FAIL',
                native_sequence=[r['function'] for r in trace if r.get('kind') == 'entry'],
                native_sequence_matches=matched, dependencies=dependencies,
                vector_sha256=digest(vector), trace_sha256=digest(output / 'trace.jsonl'))


def execute_composition(root, case, vector, env, wire, command, identities, recipe, gate, functions, owners):
    variant = case['store_visibility']
    if (variant not in ('shared', 'isolated') or case['worker_mode'] != 'object-contract'
            or vector.read_bytes() != ('store-process\n' + variant + '\n').encode()):
        raise ValueError('store visibility fixture mismatch')
    actors = [observe(root, 'producer', env, wire, command, identities, recipe, gate, functions)]
    secondary_provision = None
    try:
        if variant == 'isolated' and actors[0]['status'] == 'PASS':
            secondary = root / 'isolated-store'
            secondary.mkdir(mode=0o700)
            owner = OwnedTokens(secondary)
            owners.append(owner)
            if owner.path.samefile(root / 'tokens'):
                raise ValueError('isolation requires distinct token directories')
            config = secondary / 'softhsm.conf'
            backend = next(line for line in (root / 'softhsm.conf').read_text().splitlines()
                           if line.startswith('objectstore.backend = '))
            config.write_text('directories.tokendir = ' + str(owner.path) + '\n' + backend + '\nlog.level = ERROR\n')
            env_b = dict(env, SOFTHSM2_CONF=str(config), TMPDIR=str(secondary), TMP=str(secondary), TEMP=str(secondary))
            process = execute(command('provision', 'case-provision'), dict(env_b, LD_DEBUG='files'),
                              secondary / 'provision', wire)
            verify_worker(secondary / 'provision/stdout.raw', process, dict(identities, case='case-provision'), 'preparation_terminal')
            secondary_provision = dict(process=process,
                dependencies=verify_dependencies(secondary / 'provision/stderr.raw', gate['dependencies']))
            actors.append(observe(secondary, 'isolated', env_b, wire, command, identities, recipe, gate, functions))
    finally:
        # The producer's successful ownership transfer must be discharged even
        # if the distinct-store actor fails. The stores are removed after every
        # child has exited; no native-cleanup success is inferred from deletion.
        if actors[0]['status'] == 'PASS':
            actors.append(observe(root, 'consumer', env, wire, command, identities, recipe, gate, functions))
    sequence = [name for actor in actors for name in actor['native_sequence']]
    expected_roles = ['producer', 'isolated', 'consumer'] if variant == 'isolated' else ['producer', 'consumer']
    passed = ([a['role'] for a in actors] == expected_roles and all(a['status'] == 'PASS' for a in actors)
              and len({a['process_id'] for a in actors}) == len(actors)
              and sequence == case['expected_native_calls'])
    return dict(status='PASS' if passed else 'FAIL', attribution='NONE' if passed else 'UNKNOWN',
                body_started=True, composition_actors=actors, secondary_provision=secondary_provision,
                worker_records=actors[-1]['worker_records'], native_sequence=sequence,
                native_sequence_matches=passed, observer_script_sha256=digest(HERE / 'native_observer.py'),
                scope='Distinct processes; same token store persistence versus separately provisioned stores with identical token/object labels. No concurrent mutation or cross-process session-handle claim.')
