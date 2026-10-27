# Pump byte-identity status — Linux v1.44 rebuild, 27 October 2026

This run compared the reconstructed sources to the captured ProgramData ELF payloads in `evidence/`. Those files are the reference binaries. On 27 October 2026, finalized mainnet `getAccountInfo` for each program-data account returned the same payload SHA-256 as the file in the repo (context slots 462117798–462117806). The captures from 24 October 2026 are still the deployed programs. No `solana program dump` binary was required; the RPC payload is the dump.

`scripts/build_and_compare_originals.py` rebuilds Pump with the pinned toolchain and scores the result. `--self-test` checks that the published Round29 Mac artifact still scores 135 raw-equal and 723 normalized windows.

## Programs and reference hashes

| Program | Program ID | Captured ELF SHA-256 | Bytes |
| --- | --- | --- | --- |
| Pump | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | `7a19affaa2c6187e04a5fe0ea298cee81fa5eb8c24cfcc30d85f615e89f7b02d` | 10,485,715 |
| PumpSwap / AMM | `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` | `6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7` | 10,485,715 |
| Fees | `pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ` | `4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e` | 948,944 |
| Mayhem | `MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e` | `a87fa9f866272514e6acb852b668c4a08aeb173d56c883039991d114d1199bdb` | 777,408 |
| Donation Relay | `RLAYHr9TRFcKB2ubYQhspcnXiaGpaVzNQvHytt47RZu` | `367f07a62e3f74d358187d175cf3228848e81a56c781a9a75b9df7fed1268563` | 830,448 |
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | `8190d3f7ceb6cb7a7a8d8924bff89f9f611e15ce1f806f2b6237f3311a98f697` | 108,600 |
| Token-2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | `15a2e615a42e20f31714bbaaee43002ae6f1cda2e8d7118243117ab3c1342e2d` | 1,382,016 |
| Associated Token | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | `6804554e69fd3a58caa191dc4a58f4c67223d30ca28ab8987f39fc18d2f7374d` | 105,032 |
| Token Metadata | `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` | `31f0a627dba051a938de650464e55cc5397a4be0fd496929c1f9cf02fe5e9011` | 793,991 |

Each captured file's SHA-256 equals `payload_sha256` in its `capture.json`. Mainnet confirmed that equality again for Pump, PumpSwap, Fees, Mayhem, and Donation Relay.

## Toolchain

The new Pump build used the official Linux platform-tools v1.44 archive:

- URL: `https://github.com/anza-xyz/platform-tools/releases/download/v1.44/platform-tools-linux-x86_64.tar.bz2`
- SHA-256: `6719b889d60677a8a2fcf4c82f68441a1afe0ab093edd2efe9f84a67a808b3e9`
- size: 490,710,349
- `rustc 1.79.0-dev`, LLVM 18.1.7, host `x86_64-unknown-linux-gnu`
- rustc SHA-256: `c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97`
- cargo `1.79.0 (804e32543 2025-01-29)`
- Anza rust commit recorded in the archive `version.md`: `08b7341888ab480dfaaa0698300cbbbbb2d75b53`
- profile from `programs/pump`: `opt-level=3`, `panic=abort`, `overflow-checks=on`, `lto=false`, `codegen-units=1`, `-Zremap-cwd-prefix=`
- Anchor `0.31.1`, direct `spl-type-length-value 0.7.0`, lockfile version 4
- strip used the same v1.44 `llvm-objcopy --strip-all` (the historical Mac recipe stripped with v1.52)

The v1.44 Linux sysroot contains `/home/runner/work/platform-tools/...`, which is the path family embedded in the deployed Pump ELF. The published Round29 candidate was linked on macOS and embeds `/Users/runner/work/platform-tools/...` instead.

`scripts/pump_text_layout.py` previously chose `x86_64-apple-darwin` for every x86_64 host, so `--text-section-order` could not find `rust-lld` on Linux. It now selects `x86_64-unknown-linux-gnu` on Linux. The Round29 `ordered.ld` still names the Mac codegen-unit hash and Mac symbol hashes, so this Linux build did not reuse that script. 385 of its 529 selectors have a unique Linux symbol prefix; 140 are ambiguous monomorphizations and 4 are missing. A Linux order file has to be regenerated from a link map.

## REA

REA 6.8.0 (`rea-agents@6.8.0`, cloned from `https://github.com/morluto/rea`) was used as follows.

- `rea decompile` on `evidence/original/pump/deployed.so` returns `unsupported ELF architecture`. Unmodified REA does not admit EM_SBF. Ghidra 12.1.4 and the sBPF processor described in `docs/REA.md` were not installed here, so there is no decompiler listing.
- `rea inspect-with-objdump file_headers` through GNU `objdump` reports `architecture: UNKNOWN!` and `file format elf64-little`.
- The same REA command with `REA_OBJDUMP_COMMAND` pointed at platform-tools v1.44 `llvm-objdump` returns `file format elf64-sbf` and the real section headers (`.text` 0x1b58d0 at VMA 0x120, `.rodata` 0x7d1f, `.data.rel.ro` 0x2870). Evidence id for that section-header run: `ev_045ae99291108493a17be11af3d882f9266a2b276453458652992644b1d585a9`.
- REA's symbol disassembly passes GNU `--disassemble=<symbol>`. This `llvm-objdump` rejects that flag, so function bodies below were diffed from the ELF bytes directly. That comparison is what decides a match.

## Pump rebuild

Command:

```sh
python3 scripts/build_and_compare_originals.py \
  --build pump \
  --registry-home /tmp/cargo-home \
  --build-output work/pump-linux-v144
```

The crate sources hashed for this build are the Round29 primary sources (52 files, no mismatch with `programs/pump`). `work/` is gitignored. Fresh `cargo fetch --locked` used the v1.44 cargo.

| Artifact | SHA-256 | Bytes | Whole-file equal to original |
| --- | --- | --- | --- |
| Original Pump ELF | `7a19affaa2c6187e04a5fe0ea298cee81fa5eb8c24cfcc30d85f615e89f7b02d` | 10,485,715 | — |
| Linux unstripped | `60083be78b2e64d072eed2fe7bdc22a134ff237cc504df61db080dd5ff7154a3` | 2,518,168 | no |
| Linux stripped (`llvm-objcopy --strip-all`) | `eb53cefc0d6dd74f024d28ff6031c31347474de2149787eb884122f61213d1fb` | 1,837,432 | no |
| Round29 Mac unstripped (previous checkpoint) | `2e2e5dbd8f72cc86c2801c911ab9844ee6582b8576ed1c251a419d171de19157` | 2,518,168 | no |
| Round29 Mac stripped | `6791b39c866bae8c1c3ceb6f1b9786e2ad2a8c7adfb7b7c75ce00c474569efd1` | (checkpoint) | no |

First differing byte of the Linux unstripped file versus the original is offset 24. Shared-prefix identity against the 10,485,715-byte allocation image is not a useful completeness number: the candidate is shorter, and bytes past the original's 1,934,800-byte ELF image are loader zero-fill while the unstripped candidate still has symbol sections.

Prefix identity of the original meaningful ELF (1,934,800 bytes) against the candidate:

| Build | Identical bytes in that prefix | Percent |
| --- | ---: | ---: |
| Linux v1.44 unstripped | 870,097 | 44.97% |
| Round29 Mac unstripped | 872,450 | 45.09% |

Section sizes (Linux vs original):

| Section | Original | Linux | Identical bytes at the same file offset |
| --- | ---: | ---: | ---: |
| `.text` | 1,792,208 | 1,699,328 | 764,180 (44.97% of the shorter section) |
| `.rodata` | 32,031 | 31,723 | 1,636 |
| `.data.rel.ro` | 10,352 | 11,528 | 6,425 |
| `.rel.dyn` | 98,352 | 92,992 | 77,365 |
| `.dynstr` | 288 | 288 | 288 (100%) |

Same-offset `.text` identity understates recovery. Functions are not laid out at the original addresses, so call immediates and `lddw` pointers move. The window comparison masks only those operands.

## Function windows

Inventory: `repro/pump/main-contract-round29-20261027/inventory.json.gz` (1,035 original windows). A window is normalized-equal when every byte matches after masking internal relative calls and `lddw` values that point into a section. Line-number immediates are not masked.

| Build | Raw-equal windows | Normalized windows | Original text covered by normalized windows |
| --- | ---: | ---: | ---: |
| Linux v1.44 | 119 / 1,035 | **723 / 1,035 (69.9%)** | **886,312 / 1,792,208 (49.5%)** |
| Round29 Mac | 135 / 1,035 | **723 / 1,035 (69.9%)** | **886,312 / 1,792,208 (49.5%)** |

The Linux codegen matches the Mac checkpoint's normalized set exactly, including the covered byte count. It loses 16 raw-equal windows (10,872 bytes). All 16 are still normalized-equal. They are the bodies whose absolute pointers or call offsets were pinned by the Mac linker script and do not survive the default Linux link. Linux does embed the original `/home/runner/work/platform-tools` strings (9 hits in the unstripped ELF, 8 in the original, 0 `/Users/runner` hits). The Mac artifact has the opposite path (0 and 9).

312 windows remain unmatched (905,896 original text bytes). Against same-size candidate symbols, the closest misses are a single instruction. The instruction is `stw [r10-248], <line>` (opcode 0x62). Examples from the Linux build:

| Original | Bytes | Candidate symbol | Original line immediate | Candidate line immediate |
| --- | ---: | --- | ---: | ---: |
| `0x410b0` | 520 | `pump_recovered::migrate::execute` closure | 280 | 55 |
| `0x4bb40` | 520 | `pump_recovered::migrate_v2::execute` closure | 309 | 109 |
| `0x135580` | 672 | `toggle_create_v2` | 114 | 72 |
| `0x135820` | 672 | `toggle_cashback_enabled` | 121 | 77 |
| `0x135ac0` | 672 | `toggle_mayhem_mode` | 149 | 87 |

The file pointer next to those stores is `programs/pump/src/lib.rs` in both binaries. Relocation-backed `Location` records tell the same story: the original `programs/pump/src/lib.rs` has static locations through line 2664, while the reconstructed file is 529 lines and its `require_neq!` for `toggle_create_v2` sits on line 72. Original `migrate.rs` records line 659 (reconstructed file is 84 lines) and `migrate_v2.rs` records line 820 (reconstructed file is 141 lines). Inserting blank lines to force `line!()` would be fabricated coordinates, not recovered source, and would also shift locations that already match.

Other one-slot misses are real constants rather than line numbers. `SetMayhemVirtualParams`'s `AccountsExit` is 576 bytes and differs by `add64 r8, 488` versus `add64 r8, 440`. That 48-byte gap is consistent with one extra exited account or a larger frame, and it is not fixed here.

Five original 56-byte windows are `TypeId` materializers (`lddw` of two halves, two stores, `exit`). Their constants do not occur in the Linux or Mac candidate. Four candidate `core::error::Error::type_id` bodies of the same size write a different id (`0xf40641168066fddd` / `0xa407aa3eaf931aef`). The original ids are `0x1b204ea073ccb1b7` / `0x0e61d2cabdb5e3d` (four copies) and `0xa3f5295a8e9e84c1` / `0xca6c34d708d27ee8` (one copy). Those are type-path hashes, not something a line-number edit repairs.

## What is still byte-different, and what to do next

Whole-ELF identity is still false for Pump. Normalized coverage is unchanged from Round29: 69.9% of windows, 49.5% of original text. The Linux rebuild is the right host for the original sysroot strings, and it reproduces every normalized window the Mac checkpoint had.

Next work, in order:

1. Regenerate the `.text` input order on Linux now that `rust-lld` resolves. Match original addresses for the 723 normalized windows before chasing new bodies. That is what recovered the 16 raw windows on Mac, and the Linux object name is `pump_recovered.pump_recovered.94c3b8b0e9dec8ee-cgu.0.rcgu.o`.
2. Recover real file layout for the source locations above (`lib.rs` through at least line 2664, `migrate.rs` through 659, `migrate_v2.rs` through 820, `volume_accumulator.rs`, `create_v2.rs`) so the `stw` line immediates match. Do not pad blank lines.
3. Explain the `AccountsExit` 488-versus-440 immediate and the five unmatched `TypeId` bodies before editing those handlers.
4. Install Ghidra 12.1.4 and the sBPF processor from `docs/REA.md` if decompiler pseudocode is needed. Byte identity still has to be decided by the compiler output, not by the decompiler.
5. The other maintained programs were not rebuilt in this run. Their captured hashes match mainnet. Prior checkpoints remain: Fees 580/585 normalized windows, Mayhem 430/441, PumpSwap 640/785, Donation Relay 492/492 with meaningful-ELF identity.
