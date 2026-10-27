#!/usr/bin/env python3
"""Derive a Linux .text input order from the Round29 Mac order.

The published ``ordered.ld`` names Mac codegen-unit hashes and Mac rlib
metadata. This rewrites every selector onto the Linux object that actually
contains the matching symbol. Symbols are paired by exact name when the
instantiating hash survived, otherwise by the stable prefix plus the
normalized function body. The captured ELF is not a compiler input.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

from pump_compare_function_bytes import normalize
from pump_quote_control_function_match import sections
from pump_text_layout import check_script

ROOT = Path(__file__).resolve().parents[1]
HASH = re.compile(r'17h[0-9a-f]{16}E$')
SELECTOR = re.compile(
    r'^\s+\*([A-Za-z0-9_.:$+@/-]+)\("(\.text[A-Za-z0-9_.$:+@/-]*)"\)$'
)


def prefix(name):
    match = HASH.search(name)
    return name[: match.start()] if match else name


def crate_of(obj):
    lib = obj.split(':', 1)[0]
    if lib.startswith('lib') and lib.endswith('.rlib'):
        return lib[3:].rsplit('-', 1)[0]
    return obj.split('.', 1)[0]


def elf_symbols(blob):
    image_sections = sections(blob)
    shoff, = struct.unpack_from('<Q', blob, 0x28)
    shentsize, shnum, _shstrndx = struct.unpack_from('<HHH', blob, 0x3A)
    hdrs = [struct.unpack_from('<IIQQQQIIQQ', blob, shoff + i * shentsize) for i in range(shnum)]
    text = image_sections['.text']
    out = []
    for header in hdrs:
        if header[1] != 2:
            continue
        strings = hdrs[header[6]]
        entry = header[9]
        for index in range(header[5] // entry):
            nameoff, info, _other, _shndx, value, size = struct.unpack_from(
                '<IBBHQQ', blob, header[4] + index * entry
            )
            if size == 0 or (info & 0xF) != 2:
                continue
            if not (text['addr'] <= value < value + size <= text['addr'] + text['size']):
                continue
            start = strings[4] + nameoff
            name = blob[start:blob.index(b'\0', start)].decode()
            raw = blob[value - text['addr'] + text['offset']: value - text['addr'] + text['offset'] + size]
            masked, _operands = normalize(raw, value, image_sections)
            out.append({'name': name, 'address': value, 'size': size, 'body': masked})
    return out


def mac_order(script):
    rows = []
    for line in script.splitlines():
        match = SELECTOR.fullmatch(line)
        if not match:
            continue
        section = match.group(2)
        assert section.startswith('.text.')
        rows.append({
            'object': match.group(1),
            'symbol': section[len('.text.'):],
            'section': section,
        })
    return rows


def ar_members(data):
    assert data[:8] == b'!<arch>\n', 'not an archive'
    cursor = 8
    longnames = b''
    while cursor + 60 <= len(data):
        header = data[cursor:cursor + 60]
        cursor += 60
        size = int(header[48:58])
        body = data[cursor:cursor + size]
        cursor += size + (size & 1)
        name = header[:16]
        if name.startswith(b'#1/'):
            length = int(name[3:])
            real = body[:length].split(b'\0', 1)[0].decode()
            yield real, body[length:]
        elif name.strip() == b'//':
            longnames = body
        elif name.startswith(b'/') and name.strip() != b'/':
            offset = int(name.strip()[1:])
            end = longnames.index(b'\n', offset)
            yield longnames[offset:end].decode().rstrip('/'), body
        else:
            yield name.decode().strip(), body


def text_sections(obj):
    if len(obj) < 64 or obj[:4] != b'\x7fELF':
        return
    shoff, = struct.unpack_from('<Q', obj, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', obj, 0x3A)
    if shoff == 0 or shnum == 0 or shstrndx >= shnum:
        return
    hdrs = [struct.unpack_from('<IIQQQQIIQQ', obj, shoff + i * shentsize) for i in range(shnum)]
    strtab = hdrs[shstrndx]
    for header in hdrs:
        start = strtab[4] + header[0]
        name = obj[start:obj.index(b'\0', start)].decode()
        if name.startswith('.text.') and header[5] > 0:
            yield name[len('.text.'):]


def index_rlibs(paths):
    found = {}
    for path in paths:
        data = path.read_bytes()
        for member, obj in ar_members(data):
            if not member.endswith('.o'):
                continue
            for symbol in text_sections(obj):
                found.setdefault(symbol, []).append((path.name, member))
    return found


def assign(rows, mac_by_name, linux_syms, section_index):
    grouped = {}
    by_name = {}
    for sym in linux_syms:
        grouped.setdefault(prefix(sym['name']), []).append(sym)
        by_name.setdefault(sym['name'], []).append(sym)
    for pool in grouped.values():
        pool.sort(key=lambda item: item['address'])
    used = set()
    assigned, missing = [], []
    exact_name = body_match = 0
    for row in rows:
        mac = mac_by_name.get(row['symbol'])
        if mac is None:
            missing.append({**row, 'reason': 'absent-from-mac-elf'})
            continue
        chosen = None
        kind = None
        for candidate in by_name.get(row['symbol'], []):
            if id(candidate) not in used:
                chosen, kind = candidate, 'exact-name'
                break
        if chosen is None:
            pool = [item for item in grouped.get(prefix(row['symbol']), []) if id(item) not in used]
            exact = [item for item in pool if item['body'] == mac['body'] and item['size'] == mac['size']]
            if len(pool) == 1:
                exact = exact or pool
            if exact:
                chosen, kind = exact[0], 'body'
        if chosen is None:
            missing.append({**row, 'reason': 'no-linux-symbol'})
            continue
        homes = section_index.get(chosen['name'], [])
        crate = crate_of(row['object'])
        same = [home for home in homes if crate_of(home[0] if ':' not in home[0] else home[0]) == crate or crate_of(
            f'{home[0]}:{home[1]}') == crate]
        # crate_of on "libfoo.rlib" works; also try member.
        same = [home for home in homes if crate_of(home[0]) == crate or crate_of(home[1]) == crate]
        home = (same or homes)
        if not home:
            missing.append({**row, 'reason': 'symbol-not-in-rlib', 'linux': chosen['name']})
            continue
        used.add(id(chosen))
        if kind == 'exact-name':
            exact_name += 1
        else:
            body_match += 1
        archive, member = home[0]
        assigned.append({
            'linux': chosen['name'],
            'archive': archive,
            'member': member,
            'mac_object': row['object'],
        })
    return assigned, missing, exact_name, body_match


def selector(row):
    owner = f"{row['archive']}:{row['member']}"
    return f'    *{owner}(".text.{row["linux"]}")'


def render(default, assigned):
    rule = '  .text : { *(.text*) } :text'
    head, tail = default.split(rule)
    script = head + '  .text : {\n' + '\n'.join(selector(row) for row in assigned) + '\n    *(.text*)\n  } :text' + tail
    check_script(default, script)
    return script


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mac-script', type=Path,
                        default=ROOT / 'repro/pump/main-contract-round29-20261027/ordered.ld')
    parser.add_argument('--mac-elf', type=Path,
                        default=ROOT / 'repro/pump/main-contract-round29-20261027/unstripped.so')
    parser.add_argument('--linux-elf', type=Path, required=True)
    parser.add_argument('--deps', type=Path, required=True)
    parser.add_argument('--sysroot-lib', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    rlibs = sorted(args.deps.glob('*.rlib')) + sorted(args.sysroot_lib.glob('*.rlib'))
    print(f'indexing {len(rlibs)} rlibs', file=sys.stderr)
    section_index = index_rlibs(rlibs)
    print(f'indexed {len(section_index)} text symbols', file=sys.stderr)
    mac_rows = mac_order(args.mac_script.read_text())
    mac_by_name = {item['name']: item for item in elf_symbols(args.mac_elf.read_bytes())}
    linux_syms = elf_symbols(args.linux_elf.read_bytes())
    assigned, missing, exact_name, body_match = assign(mac_rows, mac_by_name, linux_syms, section_index)
    script = render((ROOT / 'scripts/pump_text_layout_default.ld').read_text(), assigned)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(script)
    reasons = {}
    for row in missing:
        reasons[row['reason']] = reasons.get(row['reason'], 0) + 1
    report = {
        'mac_selectors': len(mac_rows),
        'linux_assigned': len(assigned),
        'exact_name': exact_name,
        'body_match': body_match,
        'missing': len(missing),
        'missing_reasons': reasons,
        'indexed_symbols': len(section_index),
        'output': str(args.output),
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.report:
        args.report.write_text(text + '\n')
    return 0 if assigned else 1


if __name__ == '__main__':
    raise SystemExit(main())
