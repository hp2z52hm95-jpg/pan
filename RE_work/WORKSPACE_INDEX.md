# Pandora Tool Reverse Engineering Workspace Index

This directory contains the artifacts produced during deep static reverse
engineering of the Pandora Tool installation snapshot at the repository root.
All outputs are **read-only / descriptive**; no DRM circumvention is performed.

## Top-level documents
| File | Purpose |
|---|---|
| `../REVERSE_ENGINEERING_REPORT.md` | Part 1 — high-level stack, architecture, inventory, protocol overview. |
| `DEEP_REFERENCE.md` | Part 2 — deep technical reference (compiler forensics, MetaCore API index, blob formats, protocol map, disassembly hints). |
| `WORKSPACE_INDEX.md` | This file. |

## Sub-directories

### `rsrc/`
Extracted Win32 PE resources from each binary.  Each binary is a subdirectory.

* `rsrc/main/` — PandoraTool.exe resources (manifest, version, icons/MAINICON group). The main EXE is UPX-packed, so RCDATA (DFMs) are compressed and not directly extractable; only uncompressed resources (manifest, version, icon group, 13 icon sizes) were dumped.
* `rsrc/updater/` — PandoraUpdater.exe resources:
  * `MANIFEST.1.L1033.xml` — embedded manifest (asInvoker, PerMonitorV2, longPathAware, Win10 supportedOS).
  * `VERSION.1.L1033.bin` — VS_VERSION_INFO.
  * `RCDATA.MSG_INFO.png`, `MSG_WARNING.png`, `MSG_ERROR.png` — task-dialog icons (64x64).
  * `RCDATA.DVCLAL.L0.bin` — Delphi VCL alignment marker.
  * `RCDATA.PACKAGEINFO.L0.bin` — Delphi package/unit info blob.
  * `RCDATA.PLATFORMTARGETS.L1033.bin` — platform target flags (`\x01\x00\x00\x00` = Win32).
  * `ICON.*.bin`, `CURSOR.*.bin`, `GRPICON.*.bin`, `GRPCURSOR.*.bin` — image/cursor assets.
  * `STRING.*.bin` — raw UTF-16LE string blocks.
  * `decoded_strings.txt` — 389 Delphi/VCL strings decoded into plain text (JSON parser errors, theme errors, printer errors, OLE errors, button captions, etc.). Confirms use of System.JSON, Vcl.Themes, Vcl.Printers, Vcl.StdStyleHooks.
* `rsrc/metacore/`, `rsrc/sz7/`, `rsrc/lz4/`, `rsrc/sqlite/`, `rsrc/adbapi/`, `rsrc/adbusb/` — version/manifest/icon groups for the corresponding third-party DLLs.

### `metacore/`
MetaCore.dll (MediaTek META_DLL) API index.

* `exports.txt` — alphabetized list of all **3,419 named exports** (one per line).
* `exports_by_category.md` — categorized Markdown reference grouping exports by `META_*` subsystem (`META_NVRAM`, `META_MMRf`, `META_Rf`, `META_ERf`, `META_3Grf`, `META_C2K`, `META_FAT`, `META_MISC`, `META_MMC2K`, `META_NRf`, `META_Util`, `META_BB`, `META_COMM`, `META_PMIC`, `META_MDLogging`, etc.).

### `parsers/`
Read-only analytical scripts (Python 3, no dependencies beyond stdlib):

| Script | Inspects | Output |
|---|---|---|
| `emi_dump.py` | `emi_base.db3` EMI/DRAM init records (29,941 rows) | Decodes header fields (DRAM type, rank, eMMC CID, RAM vendor tag, flags); supports `--stats`, `--brand`, `--model`, `--id`, `--hex-dump` |
| `firmwares_dump.py` | `Firmwares.db3` firmware catalog (7,307 files, ~30 TB cumulative) | `--stats` shows brand distribution, total hits, size; lists by brand/updated/hits |
| `models_dump.py` | `models.mdb` (SQLite) encrypted model database (11,652 models) | Lists id/brand/model/codename/platform/cpu/payload length/flag byte; `--stats` shows db_meta, platform counts, catalog mtimes, payload-length distribution |
| `da_dump.py` | `Data/` — Download Agents / FDL / preloaders | Identifies ASCII inner tag (e.g. `MTK_DOWNLOAD_AGENT`, `SC7731E`, `SC-53F.bin`, `Poco_C61_Redmi_A3_MT6765_sec2024`), detects ARM reset vectors / GZIP / PE signatures |

All scripts take `--help`.

### `ida/`
Disassembler-ready label scripts:

* `metacore_idapython.py` — IDAPython script that renames all 3,419 MetaCore.dll exports by RVA. Load MetaCore.dll into IDA (x86 PE), wait for auto-analysis, then **File → Script File…** and run this. Every `META_*`/`SP_META_*` export becomes a named public symbol.
* `metacore_ghidra.py` — Same labels, in Ghidra Jython format (Window → Script Manager → Run).

## How to extend this analysis

1. **Unpack PandoraTool.exe (on a Windows workstation).**
   * Install UPX (`upx -d PandoraTool.exe`) — try versions 3.96, 4.0.2, 4.2.x since
     the UPX! header version was stripped.
   * After unpacking, re-run the resource-dump PE parser from the Part 2
     script (the same Python code in this repo, invoked with
     `process_pe('PandoraTool.exe')`) against the unpacked file. This will expose:
     - All VCL DFM forms (RT_RCDATA entries named after TForm-descendant
       classes, starting with TPF0 for binary DFMs).
     - DVCLAL, PACKAGEINFO (full unit list for the main EXE — hundreds of units).
     - Any embedded PNGs/sounds.
   * Convert binary DFM to text with Delphi's `convert.exe` or open-source
     `dfm2txt.py` to see every component's published properties (Name, Caption,
     OnClick handler names, widths, tabs, sub-components).

2. **Extract the full import table of the unpacked EXE.**
   That will reveal (a) whether the main EXE links dynamically to
   `sqlite3.dll`/`liblz4.dll`/`7z.dll`/`MetaCore.dll`/`AdbWinApi.dll` or loads
   them via `LoadLibrary`; (b) the precise set of Windows APIs used.
   We already know statically that it imports AdbWinApi, bcrypt, cfgmgr32,
   comctl32, comdlg32, gdi32, gdiplus, iphlpapi, kernel32, liblz4, MetaCore,
   msvcrt, ncrypt, netapi32, ole32, oleacc, oleaut32, setupapi, shell32,
   SHFolder, UIAutomationCore, user32, version, winhttp, wininet, winmm,
   winscard, winspool, WTSAPI32.

3. **Load MetaCore.dll into IDA/Ghidra and run the labeling script.**
   You'll be able to:
   * Cross-reference `META_MISC_SetIMEIValue` → locate IMEI write path from GUI.
   * Find `META_ConnectInMetaModeByUSB` → trace how Pandora opens META mode.
   * Find `META_MMC2K_WritePart` / `META_MMC2K_ReadPart` → partition I/O.

4. **For protocol research (interoperability with open-source tools):**
   * The MediaTek BROM protocol is already documented by projects like
     `mtkclient`, `brom-dll`, `SP Flash Tool` reverse engineering; Pandora
     uses it identically (public cmd IDs), plus per-brand DAs to bypass
     SLA/DAA auth.
   * Spreadtrum FDL protocol matches ResearchDownload/UpgradeDownload.
   * Qualcomm Sahara/Firehose is fully public (Qualcomm publishes the
     programmer spec under NDA, but open-source implementations like
     `bkerler/edl` and `ufshacker`/`qdload` exist).

## Boundary reminder

The crypto used for `soft_magic_v1` payloads and `aes_softkey_v1` catalogs is
intentionally not recovered in this workspace — those keys are the DRM
protecting Pandora's proprietary model catalog. This RE workspace is for
educational/forensic understanding of the binary's structure and the
protocols it uses, not for bypassing activation or cloning the tool.
