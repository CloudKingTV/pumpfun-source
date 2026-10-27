"""Optional, main-only .text input ordering and complete lld input receipts."""
import hashlib
import json
import platform
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULE = '  .text : { *(.text*) } :text'
SELECTOR = re.compile(r'^    \*[A-Za-z0-9_.:$+@/-]+\("\.text[A-Za-z0-9_.$:+@/-]*"\)$')
SUFFIXES = {'.o': 'object', '.obj': 'object', '.a': 'archive', '.rlib': 'archive',
            '.so': 'shared-object', '.dylib': 'shared-object', '.bc': 'bitcode'}
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_script(default, script):
    assert default.count(RULE) == 1
    head, tail = default.split(RULE)
    opening, closing = head + '  .text : {\n', '\n    *(.text*)\n  } :text' + tail
    assert script.startswith(opening) and script.endswith(closing)
    inner = script[len(opening):-len(closing)]
    lines = inner.split('\n') if inner else []
    assert all(SELECTOR.fullmatch(line) for line in lines), 'unexpected linker statement'
    assert len(lines) == len(set(lines)), 'duplicate selector'
    return len(lines)


def rust_lld_host(system=None, machine=None):
    """Host triple of the platform-tools ``rust-lld`` used to link sBPF.

    The ordered-text recipe used to key only on ``platform.machine()`` and
    always selected an Apple Darwin rustlib. On Linux that path does not
    exist, so ``--text-section-order`` could not run the build that matches
    the original program's ``/home/runner`` sysroot strings.
    """
    system = system if system is not None else platform.system()
    machine = machine if machine is not None else platform.machine()
    triples = {
        ('Darwin', 'arm64'): 'aarch64-apple-darwin',
        ('Darwin', 'x86_64'): 'x86_64-apple-darwin',
        ('Linux', 'x86_64'): 'x86_64-unknown-linux-gnu',
        ('Linux', 'aarch64'): 'aarch64-unknown-linux-gnu',
    }
    try:
        return triples[(system, machine)]
    except KeyError as error:
        raise SystemExit(
            f'unsupported host for the text-order linker: {system} {machine}'
        ) from error


def configure(order, out, sdk, crate_name, physical_wrapper):
    default = (HERE / 'pump_text_layout_default.ld').read_text()
    script = Path(order).read_text()
    count = check_script(default, script)
    dest = Path(out) / 'ordered.ld'
    dest.write_text(script)
    host = rust_lld_host()
    linker = Path(sdk) / f'rust/lib/rustlib/{host}/bin/rust-lld'
    assert linker.is_file(), f'missing rust-lld for {host}: {linker}'
    files = [HERE / name for name in ['pump_text_layout.py', 'pump_text_layout_rustc.py',
             'pump_text_layout_linker.py', 'pump_text_layout_default.ld']]
    record = {'scope': 'Optional main-only compiler/link recipe; no original ELF input or byte patching.',
              'selectors': count, 'script': str(dest), 'script_sha256': sha(dest),
              'helper_sha256': {str(p): sha(p) for p in files},
              'real_linker': str(linker), 'real_linker_sha256': sha(linker),
              'external_wrapper': str(physical_wrapper), 'external_wrapper_sha256': sha(physical_wrapper),
              'link_receipt': str(Path(out) / 'link/linker-invocation.json')}
    env = {'RUSTC_WRAPPER': str(HERE / 'pump_text_layout_rustc.py'),
           'PUMP_TEXT_ROOT_CRATE': crate_name,
           'PUMP_TEXT_PHYSICAL_WRAPPER': str(physical_wrapper),
           'PUMP_TEXT_LINKER': str(linker), 'PUMP_TEXT_SCRIPT': str(dest),
           'PUMP_TEXT_RECORD_DIR': str(Path(out) / 'link')}
    record['environment'] = env
    return env, record


def rustc_command(rustc, args, env):
    # Cargo also asks rustc for its version/target facts without compiling.
    name = args[args.index('--crate-name') + 1] if '--crate-name' in args else None
    kinds = [args[i + 1] for i, value in enumerate(args[:-1]) if value == '--crate-type']
    result = list(args)
    if name == env['PUMP_TEXT_ROOT_CRATE'] and 'cdylib' in kinds:
        result += ['-C', 'linker=' + str(HERE / 'pump_text_layout_linker.py')]
    return [sys.executable, env['PUMP_TEXT_PHYSICAL_WRAPPER'], rustc, *result]


def declared_inputs(args):
    result = {}
    skip = {'-o', '--output', '-L', '--library-path', '--script', '-T', '-z', '-flavor'}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in skip:
            assert i + 1 < len(args)
            i += 2
            continue
        assert not arg.startswith('@'), 'response-file input unsupported'
        assert not (arg.startswith('-l') or arg == '--library' or arg.startswith('--library=')), 'library lookup unsupported'
        # These options introduce additional files not present in the admitted
        # SBF recipe. Refuse them rather than leave an unbound file input.
        assert not arg.startswith(('--just-symbols', '--dynamic-list', '--retain-symbols-file',
                                   '--symbol-ordering-file', '--version-script ')), 'unsupported file option'
        if arg == '--version-script':
            assert i + 1 < len(args)
            result[args[i + 1]] = 'version-script'
            i += 2
            continue
        if arg.startswith('--version-script='):
            result[arg.split('=', 1)[1]] = 'version-script'
        elif not arg.startswith('-') and Path(arg).suffix in SUFFIXES:
            result[arg] = SUFFIXES[Path(arg).suffix]
        elif not arg.startswith('-') and Path(arg).is_file():
            raise AssertionError('unclassified file input: ' + arg)
        i += 1
    return result


def check_bindings(args, records):
    assert declared_inputs(args).keys() == records.keys(), 'input set differs'
    for path, kind in declared_inputs(args).items():
        rec = records[path]
        assert kind == rec['kind']
        data = Path(rec['copy']).read_bytes()
        assert len(data) == rec['bytes'] and hashlib.sha256(data).hexdigest() == rec['sha256'], path


def prepare_link(args, env):
    directory = Path(env['PUMP_TEXT_RECORD_DIR'])
    directory.mkdir(parents=True, exist_ok=True)
    default = (HERE / 'pump_text_layout_default.ld').read_text()
    replacement = Path(env['PUMP_TEXT_SCRIPT'])
    check_script(default, replacement.read_text())
    records = {}
    for index, (path, kind) in enumerate(declared_inputs(args).items()):
        data = Path(path).read_bytes()
        dest = directory / 'inputs' / f'{index:04d}' / Path(path).name
        dest.parent.mkdir(parents=True)
        dest.write_bytes(data)
        records[path] = {'kind': kind, 'copy': str(dest), 'bytes': len(data),
                         'sha256': hashlib.sha256(data).hexdigest()}
    after, scripts = [], 0
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('--script', '-T'):
            assert Path(args[i + 1]).read_text() == default, 'unexpected SDK script'
            after += [arg, str(replacement)]
            scripts += 1
            i += 2
            continue
        if arg.startswith('--script='):
            assert Path(arg.split('=', 1)[1]).read_text() == default
            arg = '--script=' + str(replacement)
            scripts += 1
        elif arg.startswith('--version-script='):
            arg = '--version-script=' + records[arg.split('=', 1)[1]]['copy']
        elif arg in records:
            arg = records[arg]['copy']
        after.append(arg)
        i += 1
    assert scripts == 1
    after.append('-Map=' + str(directory / 'link.map'))
    check_bindings(args, records)
    record = {'input_binding_version': 1, 'incoming': args, 'forwarded': after,
              'link_inputs': records, 'real_linker': env['PUMP_TEXT_LINKER'],
              'real_linker_sha256': sha(env['PUMP_TEXT_LINKER']),
              'replacement_script_sha256': sha(replacement)}
    (directory / 'linker-invocation.json').write_text(json.dumps(record, indent=2) + '\n')
    return [env['PUMP_TEXT_LINKER'], *after]


def finish(record):
    assert sha(record['script']) == record['script_sha256']
    assert sha(record['real_linker']) == record['real_linker_sha256']
    assert sha(record['external_wrapper']) == record['external_wrapper_sha256']
    assert all(sha(path) == digest for path, digest in record['helper_sha256'].items())
    inv = json.loads(Path(record['link_receipt']).read_text())
    check_bindings(inv['incoming'], inv['link_inputs'])
    assert inv['replacement_script_sha256'] == record['script_sha256']
    assert inv['real_linker_sha256'] == record['real_linker_sha256']
    # Verify the actual forwarded file operands point at the bound copies.
    expected = {rec['copy'] for rec in inv['link_inputs'].values()}
    assert set(declared_inputs(inv['forwarded'])) == expected
    return dict(record, linker_invocation_sha256=sha(record['link_receipt']),
                bound_inputs=len(inv['link_inputs']))
