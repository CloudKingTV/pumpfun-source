#!/usr/bin/env python3
"""Build reconstructed programs and compare them to the captured originals.

The reference binaries are the ProgramData ELF payloads already stored under
``evidence/``. Program IDs live in ``repro/programs.json`` and in each
``evidence/**/capture.json``. ``--check-chain`` re-fetches those program-data
accounts from Solana mainnet and checks the payload hash. It does not send a
transaction.

``--build pump`` compiles ``programs/pump`` with platform-tools v1.44
(Agave/Anza Linux archive SHA-256
6719b889d60677a8a2fcf4c82f68441a1afe0ab093edd2efe9f84a67a808b3e9,
rustc 1.79.0-dev, LLVM 18.1.7) via ``scripts/pump_build_verified.py``.
The captured ELF is never a compiler input.

Function windows come from the Round29 inventory. A window is raw-equal when
its bytes occur in the candidate ``.text``. It is normalized-equal when the
same is true after masking internal relative-call immediates and ``lddw``
values that point into an ELF section. Other immediates, including Anchor
source line numbers, still have to match.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import subprocess
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compare import compare as compare_bytes  # noqa: E402

PLATFORM_V144_SHA256 = (
    "6719b889d60677a8a2fcf4c82f68441a1afe0ab093edd2efe9f84a67a808b3e9"
)
DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
EVIDENCE = {
    "pump": ROOT / "evidence/original/pump/deployed.so",
    "pump_amm": ROOT / "evidence/original/pump_amm/deployed.so",
    "pump_fees": ROOT / "evidence/original/pump_fees/deployed.so",
    "mayhem": ROOT / "evidence/original/mayhem/deployed.so",
    "donation_relay": ROOT / "evidence/dependencies/donation_relay/deployed.so",
    "spl_token": ROOT / "evidence/dependencies/spl_token/deployed.so",
    "spl_token_2022": ROOT / "evidence/dependencies/spl_token_2022/deployed.so",
    "associated_token": ROOT / "evidence/dependencies/associated_token/deployed.so",
    "token_metadata": ROOT / "evidence/dependencies/token_metadata/deployed.so",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sections(blob: bytes) -> dict:
    shoff, = struct.unpack_from("<Q", blob, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
    hdrs = [
        struct.unpack_from("<IIQQQQIIQQ", blob, shoff + i * shentsize)
        for i in range(shnum)
    ]
    strtab = hdrs[shstrndx]

    def name(off: int) -> str:
        start = strtab[4] + off
        return blob[start : blob.index(b"\0", start)].decode()

    return {
        name(header[0]): {"addr": header[3], "offset": header[4], "size": header[5]}
        for header in hdrs
    }


def meaningful_end(blob: bytes, secs: dict) -> int:
    end = 0
    for sec in secs.values():
        end = max(end, sec["offset"] + sec["size"])
    shoff, = struct.unpack_from("<Q", blob, 0x28)
    shentsize, shnum, _ = struct.unpack_from("<HHH", blob, 0x3A)
    return max(end, shoff + shentsize * shnum)


def mask_body(raw: bytes, address: int, image_sections: dict) -> bytes:
    masked = bytearray(raw)
    cursor = 0
    while cursor < len(raw):
        op, regs, _offset, immediate = struct.unpack_from("<BBhi", raw, cursor)
        if op == 0x18:
            if cursor + 16 > len(raw):
                break
            value = struct.unpack_from("<I", raw, cursor + 4)[0] | (
                struct.unpack_from("<I", raw, cursor + 12)[0] << 32
            )
            targets = [
                sec_name
                for sec_name, sec in image_sections.items()
                if sec["addr"] > 0 and sec["addr"] <= value < sec["addr"] + sec["size"]
            ]
            if targets:
                masked[cursor + 4 : cursor + 8] = b"\0" * 4
                masked[cursor + 12 : cursor + 16] = b"\0" * 4
            cursor += 16
        else:
            if op == 0x85 and regs >> 4 == 1 and immediate != -1:
                masked[cursor + 4 : cursor + 8] = b"\0" * 4
            cursor += 8
    return bytes(masked)


def text_of(blob: bytes, secs: dict) -> bytes:
    text = secs[".text"]
    return blob[text["offset"] : text["offset"] + text["size"]]


def symbols(blob: bytes) -> list[tuple[int, int, str]]:
    shoff, = struct.unpack_from("<Q", blob, 0x28)
    shentsize, shnum, _shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
    hdrs = [
        struct.unpack_from("<IIQQQQIIQQ", blob, shoff + i * shentsize)
        for i in range(shnum)
    ]
    found = []
    for header in hdrs:
        if header[1] != 2:
            continue
        strsh = hdrs[header[6]]
        ent = header[9]
        for index in range(header[5] // ent):
            off = header[4] + index * ent
            nameoff, info, _other, _shndx, value, size = struct.unpack_from(
                "<IBBHQQ", blob, off
            )
            if size == 0 or (info & 0xF) != 2:
                continue
            start = strsh[4] + nameoff
            name = blob[start : blob.index(b"\0", start)].decode(errors="replace")
            found.append((value, size, name))
    return found


def load_inventory(path: Path) -> list[dict]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as stream:
        return json.load(stream)["windows"]


def match_windows(original: bytes, candidate: bytes, windows: list[dict]) -> dict:
    original_sections = sections(original)
    candidate_sections = sections(candidate)
    original_text = text_of(original, original_sections)
    candidate_text = text_of(candidate, candidate_sections)
    candidate_masked = mask_body(
        candidate_text, candidate_sections[".text"]["addr"], candidate_sections
    )
    text = original_sections[".text"]
    raw = normalized = 0
    raw_bytes = normalized_bytes = 0
    matched = []
    for window in windows:
        offset = window["start"] - text["addr"]
        body = original_text[offset : offset + window["bytes"]]
        masked = mask_body(body, window["start"], original_sections)
        is_raw = body in candidate_text
        is_norm = masked in candidate_masked
        raw += is_raw
        normalized += is_norm
        if is_raw:
            raw_bytes += window["bytes"]
        if is_norm:
            normalized_bytes += window["bytes"]
        matched.append({**window, "raw_equal": is_raw, "normalized_equal": is_norm})
    return {
        "original_text_bytes": len(original_text),
        "candidate_text_bytes": len(candidate_text),
        "windows": len(windows),
        "raw_equal": raw,
        "normalized_equal": normalized,
        "raw_equal_text_bytes": raw_bytes,
        "normalized_text_bytes": normalized_bytes,
        "details": matched,
    }


def near_misses(original: bytes, candidate: bytes, details: list[dict], limit: int) -> list[dict]:
    original_sections = sections(original)
    candidate_sections = sections(candidate)
    by_size = defaultdict(list)
    text = candidate_sections[".text"]
    for addr, size, name in symbols(candidate):
        if not (text["addr"] <= addr < text["addr"] + text["size"]) or size % 8:
            continue
        chunk = candidate[
            addr - text["addr"] + text["offset"] : addr - text["addr"] + text["offset"] + size
        ]
        by_size[size].append((addr, name, mask_body(chunk, addr, candidate_sections), chunk))
    rows = []
    original_text = original_sections[".text"]
    for window in details:
        if window["normalized_equal"]:
            continue
        choices = by_size.get(window["bytes"])
        if not choices:
            continue
        offset = window["start"] - original_text["addr"]
        body = original[
            original_text["offset"] + offset : original_text["offset"] + offset + window["bytes"]
        ]
        masked = mask_body(body, window["start"], original_sections)
        best = None
        for addr, name, candidate_masked, candidate_body in choices:
            diffs = []
            for index in range(0, len(masked), 8):
                if masked[index : index + 8] != candidate_masked[index : index + 8]:
                    diffs.append(index)
            if best is None or len(diffs) < best[0]:
                best = (len(diffs), addr, name, diffs, candidate_body, body)
        if best is None:
            continue
        count, addr, name, diffs, candidate_body, original_body = best
        kinds = []
        for index in diffs[:6]:
            op = original_body[index]
            imm_o = struct.unpack_from("<i", original_body, index + 4)[0]
            imm_c = struct.unpack_from("<i", candidate_body, index + 4)[0]
            off = struct.unpack_from("<h", original_body, index + 2)[0]
            if op == 0x62 and off <= -200:
                kind = "anchor-source-line"
            elif op in (0x62, 0x6A, 0x7A, 0xB4, 0xB7, 0x07, 0x04):
                kind = "immediate"
            else:
                kind = "structural"
            kinds.append(
                {
                    "offset": index,
                    "opcode": op,
                    "stack_or_branch": off,
                    "original_immediate": imm_o,
                    "candidate_immediate": imm_c,
                    "kind": kind,
                }
            )
        rows.append(
            {
                "original_start": window["start"],
                "bytes": window["bytes"],
                "candidate_start": addr,
                "symbol": name,
                "different_slots": count,
                "samples": kinds,
            }
        )
    rows.sort(key=lambda row: (row["different_slots"], row["bytes"]))
    return rows[:limit]


def identity(original: bytes, candidate: bytes) -> dict:
    shared = min(len(original), len(candidate))
    identical = sum(a == b for a, b in zip(original[:shared], candidate[:shared]))
    report = compare_bytes(original, candidate)
    report["identical_bytes_in_shared_prefix"] = identical
    report["identical_percent_of_shared_prefix"] = (100.0 * identical / shared) if shared else 0.0
    original_sections = sections(original)
    candidate_sections = sections(candidate)
    original_meaning = original[: meaningful_end(original, original_sections)]
    candidate_meaning = candidate[: meaningful_end(candidate, candidate_sections)]
    shared_meaning = min(len(original_meaning), len(candidate_meaning))
    identical_meaning = sum(
        a == b
        for a, b in zip(original_meaning[:shared_meaning], candidate_meaning[:shared_meaning])
    )
    report["meaningful_original_bytes"] = len(original_meaning)
    report["meaningful_candidate_bytes"] = len(candidate_meaning)
    report["meaningful_identical_bytes"] = identical_meaning
    report["meaningful_identical_percent"] = (
        100.0 * identical_meaning / shared_meaning if shared_meaning else 0.0
    )
    section_rows = []
    for name in sorted(set(original_sections) | set(candidate_sections)):
        left = original_sections.get(name)
        right = candidate_sections.get(name)
        if not left or not right or name == "":
            continue
        left_bytes = original[left["offset"] : left["offset"] + left["size"]]
        right_bytes = candidate[right["offset"] : right["offset"] + right["size"]]
        shared_section = min(len(left_bytes), len(right_bytes))
        same = sum(a == b for a, b in zip(left_bytes, right_bytes))
        section_rows.append(
            {
                "section": name,
                "original_bytes": left["size"],
                "candidate_bytes": right["size"],
                "identical_prefix_bytes": same,
                "equal_size": left["size"] == right["size"],
                "identical_percent_of_shorter": (
                    100.0 * same / shared_section if shared_section else 0.0
                ),
            }
        )
    report["sections"] = section_rows
    report["home_runner_strings"] = {
        "original": original.count(b"/home/runner/work/platform-tools"),
        "candidate": candidate.count(b"/home/runner/work/platform-tools"),
        "candidate_users_runner": candidate.count(b"/Users/runner/work/platform-tools"),
    }
    return report


def evidence_rows() -> list[dict]:
    programs = json.loads((ROOT / "repro/programs.json").read_text())
    dependencies = json.loads((ROOT / "repro/dependencies.json").read_text())
    ids = {**programs, **dependencies}
    rows = []
    for name, path in EVIDENCE.items():
        blob = path.read_bytes()
        capture_path = path.with_name("capture.json")
        capture = json.loads(capture_path.read_text()) if capture_path.is_file() else {}
        rows.append(
            {
                "name": name,
                "program_id": ids.get(name) or capture.get("program"),
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256(blob),
                "bytes": len(blob),
                "capture_payload_sha256": capture.get("payload_sha256"),
                "capture_matches_file": capture.get("payload_sha256") == sha256(blob)
                if capture.get("payload_sha256")
                else None,
                "captured_at_utc": capture.get("captured_at_utc"),
                "last_deploy_slot": capture.get("last_deploy_slot"),
                "programdata": capture.get("programdata"),
            }
        )
    return rows


def rpc(url: str, method: str, params: list) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def check_chain(url: str, names: list[str]) -> list[dict]:
    import base64

    rows = []
    for row in evidence_rows():
        if names and row["name"] not in names:
            continue
        programdata = row.get("programdata")
        if not programdata:
            rows.append({**row, "chain": "no programdata address in capture"})
            continue
        result = rpc(
            url,
            "getAccountInfo",
            [programdata, {"encoding": "base64", "commitment": "finalized"}],
        )
        value = result["result"]["value"]
        data = base64.b64decode(value["data"][0])
        # Upgradeable ProgramData: 4-byte tag, 8-byte slot, 1-byte option, 32-byte authority.
        header = 45 if len(data) > 45 and data[12] == 1 else 13
        payload = data[header:]
        rows.append(
            {
                "name": row["name"],
                "program_id": row["program_id"],
                "programdata": programdata,
                "context_slot": result["result"]["context"]["slot"],
                "account_bytes": len(data),
                "payload_bytes": len(payload),
                "payload_sha256": sha256(payload),
                "matches_captured_file": sha256(payload) == row["sha256"],
            }
        )
    return rows


def build_pump(output: Path, sdk: Path, registry_home: Path) -> None:
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    command = [
        sys.executable,
        str(ROOT / "scripts/pump_build_verified.py"),
        "--source-directory",
        str(ROOT / "programs/pump"),
        "--sdk",
        str(sdk),
        "--registry-home",
        str(registry_home),
        "--workspace-layout",
        "--output",
        str(output),
    ]
    subprocess.run(command, cwd=ROOT, check=True)


def self_test() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from pump_text_layout import rust_lld_host

    assert rust_lld_host("Linux", "x86_64") == "x86_64-unknown-linux-gnu"
    assert rust_lld_host("Darwin", "arm64") == "aarch64-apple-darwin"
    assert rust_lld_host("Darwin", "x86_64") == "x86_64-apple-darwin"
    original = (ROOT / "evidence/original/pump/deployed.so").read_bytes()
    mac = (ROOT / "repro/pump/main-contract-round29-20261027/unstripped.so").read_bytes()
    windows = load_inventory(
        ROOT / "repro/pump/main-contract-round29-20261027/inventory.json.gz"
    )
    scored = match_windows(original, mac, windows)
    assert scored["raw_equal"] == 135, scored["raw_equal"]
    assert scored["normalized_equal"] == 723, scored["normalized_equal"]
    print(json.dumps({"self_test": "ok", **{k: v for k, v in scored.items() if k != "details"}}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", choices=["pump"], help="Compile this program before comparing")
    parser.add_argument("--sdk", type=Path, default=Path.home() / ".cache/solana/v1.44/platform-tools")
    parser.add_argument("--registry-home", type=Path, default=Path("/tmp/cargo-home"))
    parser.add_argument("--build-output", type=Path, default=ROOT / "work/pump-linux-v144")
    parser.add_argument("--candidate", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument(
        "--inventory",
        type=Path,
        default=ROOT / "repro/pump/main-contract-round29-20261027/inventory.json.gz",
    )
    parser.add_argument("--check-chain", action="store_true")
    parser.add_argument("--rpc", default=DEFAULT_RPC)
    parser.add_argument("--chain-program", action="append", default=[])
    parser.add_argument("--near-miss-limit", type=int, default=12)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.build:
        build_pump(args.build_output, args.sdk, args.registry_home)
        args.candidate.append(f"pump={args.build_output / 'unstripped.so'}")
    report = {
        "reference_binaries": evidence_rows(),
        "platform_tools_v144_sha256": PLATFORM_V144_SHA256,
        "candidates": [],
    }
    if args.check_chain:
        report["chain"] = check_chain(args.rpc, args.chain_program)
    windows = load_inventory(args.inventory) if args.candidate else []
    for item in args.candidate:
        name, path_text = item.split("=", 1)
        program = "pump" if name.startswith("pump") else name
        original = EVIDENCE[program].read_bytes()
        candidate = Path(path_text).read_bytes()
        scored = match_windows(original, candidate, windows) if program == "pump" else None
        entry = {
            "name": name,
            "program": program,
            "path": path_text,
            "sha256": sha256(candidate),
            "bytes": len(candidate),
            "file": identity(original, candidate),
        }
        if scored:
            entry["functions"] = {k: v for k, v in scored.items() if k != "details"}
            entry["functions"]["normalized_percent"] = (
                100.0 * scored["normalized_equal"] / scored["windows"]
            )
            entry["functions"]["text_covered_percent"] = (
                100.0 * scored["normalized_text_bytes"] / scored["original_text_bytes"]
            )
            entry["nearest_unmatched"] = near_misses(
                original, candidate, scored["details"], args.near_miss_limit
            )
        report["candidates"].append(entry)
    text = json.dumps(report, indent=2)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
