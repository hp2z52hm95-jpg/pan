# Pandora Tool — Deep Reverse-Engineering Reference (Part 2)

_Companion to `REVERSE_ENGINEERING_REPORT.md`_
_Outputs live under `RE_work/`._

---

## PART A — BINARY FORENSICS & BUILD FINGERPRINT

### A.1 Compiler identification (forensically confirmed)

String recovered verbatim from `PandoraUpdater.exe` RT_RCDATA/RT_STRING:

```
Embarcadero Delphi for Win32 compiler version 37.0 (37.0.57242.3601)
```

That exact build tag is emitted by the Delphi compiler (`dcc32`) into every
Delphi-linked binary via the `PACKAGEINFO` resource; it cannot be faked
without post-link editing. Mapping of Delphi compiler versions:

| RTL version | Product |
|---|---|
| 32.0 | Delphi 10.2 Tokyo |
| 33.0 | Delphi 10.3 Rio |
| 34.0 | Delphi 10.4 Sydney |
| 35.0 | Delphi 11 Alexandria |
| 36.0 | Delphi 12 Athens (released late 2024) |
| **37.0** | **Delphi 13 (or 12.x minor that bumped the compiler version), released c. 2025/2026** |

So the product is built with a **2025/2026-era Delphi**, not a legacy copy.

### A.2 RTL/VCL unit inventory (from PandoraUpdater.exe RTTI strings)

Complete list of Delphi RTL/VCL namespaces observed:

**Core RTL** (`System.*`):
`System`, `SysInit`, `System.SysUtils`, `System.SysConst`, `System.Classes`,
`System.Types`, `System.UITypes`, `System.UIConsts`, `System.TypInfo`,
`System.Rtti`, `System.Variants`, `System.VarUtils`, `System.StrUtils`,
`System.AnsiStrings`, `System.Character`, `System.Math`, `System.Masks`,
`System.MaskUtils`, `System.DateUtils`, `System.TimeSpan`, `System.Hash`,
`System.IniFiles`, `System.Diagnostics`, `System.Contnrs`, `System.WideStrUtils`,
`System.SyncObjs`, `System.Messaging`, `System.RTLConsts`, `System.ZLib`,
`System.Actions`, `System.Generics.Collections`, `System.Generics.Defaults`,
`System.HelpIntfs`, `System.ImageList`, `System.JSON`, `System.Threading`,
`System.Internal.ExcUtils`, `System.Win.ComObj`, `System.Win.ComConst`,
`System.Win.Crtl`, `System.Win.Registry`, `System.Win.Taskbar`,
`System.Win.TaskbarCore`, `System.IOUtils` (implied by "LongPathAware", TPath usage).

**VCL framework** (`Vcl.*`):
`Vcl.Forms`, `Vcl.Controls`, `Vcl.Graphics`, `Vcl.Menus`, `Vcl.StdCtrls`,
`Vcl.ComCtrls`, `Vcl.ComCtrls2`, `Vcl.Dialogs`, `Vcl.ExtCtrls`, `Vcl.Themes`,
`Vcl.Clipbrd`, `Vcl.Consts`, `Vcl.ComStrs`, `Vcl.GraphUtil`, `Vcl.ImgList`,
`Vcl.ActnList`, `Vcl.StdActns`, `Vcl.ListActns`, `Vcl.ToolWin`,
`Vcl.Mask`, `Vcl.Printers`.

**Windows API wrappers** (`Winapi.*`):
`Winapi.Windows`, `Winapi.Messages`, `Winapi.CommCtrl`, `Winapi.CommDlg`,
`Winapi.Dlgs`, `Winapi.ShellAPI`, `Winapi.ShlObj`, `Winapi.ShellScaling`,
`Winapi.ActiveX`, `Winapi.Ole2` (via ole32), `Winapi.WinInet` (HTTP client),
`Winapi.WinSpool` (printing), `Winapi.Winsock2` (sockets), `Winapi.Wtsapi32`
(session info), `Winapi.Dwmapi` (composition/DWM), `Winapi.MultiMon`
(multi-monitor), `Winapi.UxTheme` (visual styles), `Winapi.ImageHlp`,
`Winapi.PsAPI` (process info), `Winapi.SHFolder`, `Winapi.KnownFolders`,
`Winapi.FlatSB`, `Winapi.Imm`, `Winapi.IpExport`, `Winapi.RegStr`,
`Winapi.RichEdit`, `Winapi.MsCTF`, `Winapi.MsInkAut`, `Winapi.UIAutomation`,
`Winapi.PenInputPanel`, `Winapi.TpcShrd`, `Winapi.UrlMon`, `Winapi.ObjectArray`,
`Winapi.PropSys`, `Winapi.StructuredQueryCondition`, `Winapi.Wincodec` (WIC
imaging), `Winapi.Qos`.

**Application-specific units** (the project's own code, named in RTTI):
- `uPandoraUpdateCore.pas` — update engine: defines `TAppliedFile`,
  `TPendingFile` (generic lists of them), handles manifest download, file
  comparison, EULA verification, in-place patching, restart scheduling.
- `uPandoraUpdaterForm.pas` — form class `TPandoraUpdaterForm` with method
  `StartApply` (async, multiple nested anonymous closures → progress UI +
  chunked download + apply).
- `uCallbackMessage.pas`, `uTimeout.pas`, `uVersion.pas`, `uFlags.pas`
  — helpers (cross-thread Windows messaging, operation timeouts, version
  parsing, bit-flag operations).
- A small number of obfuscated unit names (`uAJt`, `uBj@`, `uDJt`, `uDhX`,
  `uENt`, `uFFF`, `uOf`, `uXt`) — likely either the authors' light obfuscation
  or auto-generated units.

### A.3 Language/framework NOT present

Verified absent from import tables and from RTTI/string markers in the
unpacked updater (and, by identical-import inference, in the main EXE):

- .NET/CLR (COM descriptor directory `cli_rva = 0` in every PE header).
- C/C++ runtime used directly by the EXE (no `MSVCP*.dll`, `VCRUNTIME*.dll`,
  `libstdc++-*.dll` in imports; only `msvcrt.dll` for OS-provided libc and
  MSVC9 only for MetaCore.dll).
- Qt, wxWidgets, MFC, ATL, WTL.
- Electron/NW.js/Chromium Embedded Framework (`libcef.dll`, `chrome_elf.dll`,
  `CEF` strings — all absent).
- Java/JAR, Python, Go, Rust.
- Indy (`IdHTTP`, `IdTCPClient`, `IdSSLIOHandlerSocketOpenSSL`).
- `System.Net.HttpClient` (the Delphi-native HTTP component from XE8+),
  `REST.Client` (Embarcadero REST components).
- Database component suites: `FireDAC.`, `Data.DB`, `Data.SqlExpr`,
  `UniDAC`, `Zeos`, `MyDac` — DB access is done through direct C ABI calls
  to `sqlite3.dll` (static imports in PandoraTool.exe include `sqlite3_*`
  would be in the packed section; updater doesn't use DB).
- UI component suites: DevExpress, TeeChart, VirtualTreeView, TMS,
  AlphaControls, Devart, Raize/Konopka, SynEdit, VirtualShellTools,
  Sciter, Skia4Delphi, CEF4Delphi. UI is stock VCL (with Vcl.Styles theming).
- Exception catchers: madExcept, EurekaLog, JclDebug.
- Alternate memory managers: FastMM4/FastMM5 (no `FastMM4Messages`, no
  `This application has requested the Runtime...` strings). They rely on the
  RTL built-in Simple MM or the MS-compatible one.

### A.4 Packaging: UPX

The main `PandoraTool.exe` is packed with **UPX** (Ultimate Packer for
eXecutables), confirmed by:
- Three consecutive sections named `.upx0`, `.upx1`, `.upx2` with UPX-style
  layout (`.upx0`/`.upx2` code, `.upx1` small IAT/import shell).
- String `UPXYY` visible in binary.
- All raw pointer/size fields of `.text/.itext/.data/.idata/.didata/.edata/.tls/.rdata`
  are 0 — meaning those sections are decompressed at runtime by the UPX stub
  attached after `.upx2`.

The updater (`PandoraUpdater.exe`) is **not** packed, which is why RTTI was
fully recoverable from it. It is built from the same codebase and compiler.

### A.5 Installer

Installer technology is **Inno Setup 6.5.0** (data schema 7.0.0.3), as
reported inside `unins000.exe` markers. No MSI, no NSIS, no InstallAware,
no Wise. Inno Setup is consistent with Delphi shops (it's written in Delphi).

### A.6 Application manifest & DPI

Embedded manifest (extracted to `RE_work/rsrc/main/MANIFEST.1.*.xml` and
`RE_work/rsrc/updater/MANIFEST.1.*.xml`):

- `requestedExecutionLevel level="requireAdministrator"` (main tool) — needs
  admin rights for driver install (libusb0, WinUSB filter), raw device I/O,
  and writing to Program Files during self-update.
- `requestedExecutionLevel level="asInvoker"` (updater) — downloads into a
  staging area and triggers a restart with elevation on the main EXE.
- `dpiAware=true/pm` (system/per-monitor DPI) + `dpiAwareness=PerMonitorV2`
- `longPathAware=true` (can handle paths >260 chars)
- `supportedOS` declared for Vista, Win7, Win8, Win8.1, Win10 IDs (no
  Win11-specific ID yet — but it runs on Win11).
- References `Microsoft.Windows.Common-Controls` v6 for themed controls.

---

## PART B — VISUAL COMPONENT LAYOUT (DFM / FORM RECONSTRUCTION)

Neither EXE stores its DFM in classic `.dfm.bin` (TPF0) form in RT_RCDATA —
because Delphi in newer releases links forms directly into the executable via
the new custom RCDATA naming scheme that does not use the form class name as
the resource ID the same way older Delphi did. However, **VCL RTTI on
TPandoraUpdaterForm reveals the form's component tree and published
properties indirectly**, and the STRING resources (extracted to
`RE_work/rsrc/updater/STRING.*.bin`) contain the user-visible labels.

Decoded string resources (group 4072–4096 = Delphi form/module string groups,
English LANG_NEUTRAL):

```
"&Close"
"Downloading update ..."
"Pandora Updater"
"Preparing update ..."
"Downloading update manifest ..."
"Applying update ..."
"Restarting %s ..."
"Checking for updates ..."
"Do you want to restart now?"
"Update downloaded successfully."
"Update failed: %s"
"No updates available."
"Downloading file %d of %d"
"Cancel"
"Retry"
"Error"
"Information"
"Warning"
"Are you sure you want to cancel?"
...(exact list in RE_work/rsrc/updater/decoded_strings.txt)
```

The dialog buttons visible: Close / Cancel / Retry, plus three embedded PNGs in
RCDATA: `MSG_INFO`, `MSG_WARNING`, `MSG_ERROR` (each a 64×64 32-bit PNG
task-dialog icon — Photoshop ICC profile intact). So the updater uses a
custom task-dialog style (not the Win32 TaskDialogIndirect API), with its
own themed icons.

The main application forms (in PandoraTool.exe) are under UPX and cannot be
dumped statically without first running the UPX unpacker, but the 639 GUI
keys and 2952 log keys in `Languages/*.json` effectively catalog the entire
UI surface of the main program. All UI labels map to keys like:
`"Flash Firmware"`, `"Read Info"`, `"Repair IMEI"`, `"Reset FRP"`, etc. The
translation file is essentially the UI at a "string table" level.

---

## PART C — MetaCore.dll (META_DLL) FULL API INDEX

`MetaCore.dll` is MediaTek's **Mobile Engineering Testing Architecture**
(META) DLL — the official factory-level service library. Internal name is
`META_DLL.dll`. Built with MSVC 9 (VS 2008) / MSVCR90 + MSVCP90.

### C.1 Export stats

- Total exported **symbols**: 4,708
- Exported **by name**: 3,419
- C++ mangled symbols (MSVC `??`-prefixed): ~1,289 (C++ classes/operators from
  MSVCP90, containers, internal helpers)
- `META_*` exports: ~2,991 (the factory API)
- `SP_META_*` exports: ~33 (SmartPhone (modern Android) META variant of
  NVRAM/IMEI helpers)

Full export list: **`RE_work/metacore/exports.txt`**
Categorized reference: **`RE_work/metacore/exports_by_category.md`**

### C.2 Top-level API categories (by prefix)

| Category (prefix) | Count | Purpose |
|---|---:|---|
| `META_NVRAM_*` / `SP_META_NVRAM_*` | ~626 | NVRAM read/write, IMEI compose/decompose, BT/Wi-Fi MAC, RF calibration data regions |
| `META_MMRf_*` | 301 | Multi-mode RF (2G/3G/4G/5G) — AFC, power control, Rx/Tx calibration |
| `META_Rf_*` | 294 | Base RF test/control |
| `META_ERf_*` | 240 | Extended RF |
| `META_3Grf_*` | 190 | 3G (WCDMA/TD-SCDMA) RF (AFC, RSSI, FHC, IQ dump, MIPI code word, ELNA, LNA, PA drift, temperature, path loss, RxTx cal) |
| `META_C2K_*` | 105 | CDMA2000 RF, NVRAM init/read/write/flush, NVRAM clear |
| `META_FAT_*` | 98 | FAT filesystem on the target (read/write/delete files) |
| `META_MISC_*` | 80 | IMEI Get/Set, version/info queries, BT/Wi-Fi MAC, secure boot cfg, NVRAM folder count |
| `META_MMC2K_*` | 53 | eMMC/UFS storage (read/write partitions, HW info, health, boot regions, RPMB) |
| `META_NRf_*` | 39 | 5G NR RF |
| `META_Util_*` | 33 | Utility helpers (buffer, port, time) |
| `META_BB_*` | 12 | Baseband control |
| `META_COMM_*` | 9 | Communication (connect/disconnect, port enumeration) |
| `META_UploadFilesToTarget_*` | 9 | File upload to target flash over META |
| `META_Init_*` / `META_Deinit_*` | 6 | Library init/shutdown |
| `META_MDLogging_*` | 6 | Modem debug logging control |
| `META_PMIC_*` | 4 | PMIC register read/write |
| `META_BackupCalibrationData_*` / `META_RestoreCalibrationData_*` | 3 each | Calibration backup/restore |
| `META_Check*`, `META_Cancel*`, `META_Customer*`, `META_Aux*`, `META_Debug*`, `META_WatchDog*`, `META_EnableLocalFrameCompression` | misc | Diagnostics and test helpers |

Connection-handling exports (key to understand how Pandora hooks in):
```
META_ConnectInMetaMode / META_DisconnectInMetaMode
META_ConnectInMetaModeByUSB
META_ConnectWithTarget / META_ConnectWithTargetEx
META_ConnectWithTargetByUSB / META_ConnectWithTargetByUSBEx
META_ConnectWithMultiModeTarget
META_GetDynamicUSBComPort / META_GetDynamicUSBComPortEx
META_GetAvailableHandle
META_EnableLocalFrameCompression
META_CancelAllBlockingCall
META_EnableWatchDogTimer
```

IMEI-specific:
```
META_MISC_GetIMEILocation / _r
META_MISC_GetIMEIRecNum / _r
META_MISC_GetIMEIValue / _r
META_MISC_SetIMEIValue / _r
META_NVRAM_Calculate_IMEI_CD        (check-digit)
META_NVRAM_Compose_IMEISV / _ex / _NoCheck
META_NVRAM_Decompose_IMEISV
META_NVRAM_IMEISV_Len
SP_META_NVRAM_*                      (same set for SP/Android boot path)
```

MMC/eMMC/UFS partition I/O (used for Read/Write/Raw BIN operations):
```
META_MMC2K_CheckPartDone / _r
META_MMC2K_CreatePartition / _r
META_MMC2K_DeletePartition / _r
META_MMC2K_Format / _r
META_MMC2K_GetCardInfo / _r
META_MMC2K_GetExtCSD / _r
META_MMC2K_ReadPart / _r
META_MMC2K_WritePart / _r
META_MMC2K_Erase / _r
META_MMC2K_SetBootPartition / _r
... plus RPMB functions
```

The `_r` suffix convention is MediaTek's standard naming for synchronous/
"reentrant" variants (the version that returns a result code through a
result pointer rather than raising).

### C.3 IDA/Ghidra ready-to-use label scripts

Generated scripts (just run them from within your disassembler to rename all
MetaCore exports):

- **`RE_work/ida/metacore_idapython.py`** — IDAPython for IDA Pro/Binary Ninja
- **`RE_work/ida/metacore_ghidra.py`** — Jython script for Ghidra

Load `MetaCore.dll` into the disassembler first (x86 PE, image base
0x10000000 by default on DLL load) and run the script; all 3,419 named
exports get renamed in the public-name space.

---

## PART D — DATABASE BINARY BLOB FORMATS (READ-Only)

### D.1 `emi_base.db3` — EMI record layout

Table: `EmiInfo(id INTEGER PK, version INT, brand TEXT, model TEXT, emmc_id TEXT,
sub_ver INT, m_type INT, id_len INT, emi_crc INT, data BLOB, data_size INT,
src_name TEXT, src_path TEXT, created INT)`

**Record counts by data_size:**
160 bytes (9,231 records), 84 bytes (8,772), 188 bytes (8,518), 168 bytes (1,574),
176 bytes (806), 184 bytes (582), 136 bytes (456), 144 bytes (2).

**Header layout (common prefix across all sizes)**
(offsets are from start of `data` BLOB):

| Offset | Size | Meaning |
|---:|---:|---|
| `0x00` | 4 | Record version / flags: `0x00000001` = primary EMI record; `0x00000000` = secondary/alt variant |
| `0x04` | 2 | **DRAM type code** (little-endian): `0x0203`=DDR3, `0x0206`=LPDDR4/X family; `0x0205`=LPDDR3; `0x0204`/`0x0207`=newer families (decoded empirically from id 1 vs id 16) |
| `0x06` | 2 | DRAM topology: `0x0000`=single-rank/chip-select; `0x0002`=dual-rank |
| `0x08` | 2 | `id_len` (eMMC CID byte length that is stored in record — matches column, typically 8 or 9) |
| `0x0A` | 2 | Reserved (0) |
| `0x0C` | 4 | Reserved (0) |
| `0x10` | 2 | Status/flags bitfield (common values: `0x0115`, `0x0190`, `0x0170`, `0x01f4`, `0x01f2`, `0x0222`; top byte `0x01`=record valid; low byte selects RAM vendor/geometry profile) |
| `0x12` | 1 | Zero / count |
| `0x13` | 1 | `id_len` echoed? |
| `0x14` | `id_len` | **Raw eMMC CID prefix** (binary, not hex — e.g. `33 56 36 43 4D 42` = ASCII "3V6CMB"; the column `emmc_id` stores this as an ASCII-hex string with a 3-byte prefix (`15 01 00`) prepended, giving `"150100335636434D42"`) |
| varies | pad | Zero padding to offset 0x24 |
| `0x24` | 5 | ASCII RAM chip ID tag — e.g. `54 31 53 32 23` = "T1S2#"; `42 69 77 69 6E 20` = "Biwin "; `4B 49 4E 47 53 54` = "KINGST" (first 5-8 bytes of RAM chip vendor/name) |
| `0x2C` | 2 | Zero / small flags |
| `0x2E` | 2 | Register payload size / checksum type |
| `0x30`… | varies | **DRAM EMI register init block** — DWORD register address/value pairs written to DDR controller by preloader during RAM bring-up. Values repeat symmetrically on dual-rank records (`59 30 84 04` appears twice at offset 0x76/0x7B on record id=1) |
| last 4 | 4 | Record checksum / trailing signature (observed `01 00 00 00` pattern, with `80 00 00 00` offset markers within the block) |

The `m_type` column is MediaTek's memory-type enumeration (defined in
`preloader.h` / `emi.h` in MediaTek's open-source ALPS/preloader):

| m_type | RAM generation (typical) | #records |
|---:|---|---:|
| 0 | Unknown/generic | 521 |
| 2 | MCP (old combo NAND+RAM) | 113 |
| 3 | Discrete LPDDR/DDR | 535 |
| 4 | LPDDR2 | 71 |
| 6 | DDR2/LPDDR2 era | 3,753 |
| 9 | LPDDR3 | 352 |
| 11 | DDR3 | 576 |
| 12 | DDR3L | 296 |
| 257 | LPDDR3 | 143 |
| 258 | LPDDR3 dual-channel | 84 |
| 513 | LPDDR4 | 37 |
| **514** | **LPDDR4X (Helio G/P class)** | 4,045 |
| **515** | **LPDDR4X (largest bucket)** | 9,142 |
| 516 | LPDDR4 dual | 47 |
| **518** | **LPDDR4X / UFS combo (2020-2024 phones)** | 4,805 |
| 774 | UFS LPDDR5 | 5,081 |
| 776 | UFS LPDDR5 variant | 128 |
| 777 | UFS LPDDR5 alt | 39 |
| 4266 | LPDDR5T | 10 |
| 458752 | UFS 4.0 / special | 7 |

These m_type values are exactly what the MTK preloader's `emi_init()` uses to
select the appropriate EMI configuration. Pandora is essentially shipping the
extracted EMI segments you'd otherwise need a preloader + CID match for.

A read-only reference parser is written to **`RE_work/parsers/emi_dump.py`** (created below).

### D.2 `models.mdb` — `PNDMODEL1` payload (ciphertext, descriptive only)

The BLOB `payload` for each model has:

| Offset | Size | Value |
|---:|---:|---|
| `0x00` | 9 | Magic ASCII: `"PNDMODEL1"` (constant `\x50\x4e\x44\x4d\x4f\x44\x45\x4c\x31`) |
| `0x09` | 1 | Payload type/version/flags byte: `0x08`, `0x3e`, `0x90`, `0x91`, `0xab` observed — this flags which schema/decryption path applies |
| `0x0A` | `len-10` | Encrypted model-configuration payload |

Because `db_meta.payload_crypto = soft_magic_v1`, the payload is XOR/
stream-obfuscated with a soft-coded key that the main EXE contains; recovering
the key is DRM circumvention and is out of scope. What can be stated
descriptively:

- Payloads that share the same 9th-byte prefix are **byte-identical across
  many different devices** that share the same SoC (you can see id=5/6/10/20
  all have identical bytes from offset `0x0A` onward). This means the payload
  is platform/loader configuration, not per-device data.
- Same-SoC devices (e.g. all SC7731E Spreadtrum) produce identical payload
  prefixes (id=50/100/1000/2000 all flag `0xAB` and identical first ~1000
  bytes).
- Payload lengths cluster around 1289, 1545, 2057, 2569, 2825 bytes —
  corresponding to 5 SoC payload templates.
- The plaintext inside describes: which DA/preloader to pick, whether BROM
  bypass is needed, auth libraries required, allowed operations (read/write/
  format/repair/FRP/unlock permissions), protocol timings, partition table
  offsets, etc.

### D.3 `models.mdb` — `catalogs.data` (`PNDCAT01`)

- Magic 8 bytes `"PNDCAT01"` at offset 0.
- `db_meta.catalog_crypto = aes_softkey_v1` → encrypted with AES using a
  binary-wrapped key blob with PKCS#7 padding.
- Each catalog covers one SoC platform (MEDIATEK/SPREADTRUM/QUALCOMM/EXYNOS/
  KIRIN/RKCHIP) and contains the brand/model tree (JSON-serializable after
  decryption).
- `json_mtime` is a Unix timestamp of when the catalog was generated.

### D.4 `.crp` (crypted DA / preloader) format

Files ending `.crp` are containerized encrypted loaders. Header observed:

- `preloader.crp` / `preloader2.crp` / `preloader5.crp` start with an ARM
  reset-vector pattern (`0x0E 0x00 0x00 0xEA` = `B reset`), but they're only
  ~16 KB and start with a 64-byte obfuscated header — they are **small
  bootstrap loaders** (not full preloaders) used to bootstrap BROM comms.
- `preloader3.crp`, `preloader4.crp` are larger (395–478 KB) and are
  packaged preloaders (likely with a Pandora-custom header wrapping the
  actual preloader binary).
- `preloader3_v6_MT*.crp` are chip-specific v6 preloader packages for MT6781,
  MT6789, MT6835, MT6855, MT6886, MT6895, MT6983 (Dimensity 8xx/9xxx series).
- `DA_v6.crp`, `MTK_AllInOne_DA_v2.crp` are encrypted Download Agents
  (standard DAA/SLA-wrapped custom DAs used for auth bypass).

After decryption (in-memory by PandoraTool.exe), these are standard MediaTek
DA images starting with magic `MTK_DOWNLOAD_AGENT`.

### D.5 Spreadtrum FDL format (plaintext)

`Data/FDL1` (1.19 MB) and `Data/FDL2` (16.4 MB) start with an 8-byte ASCII
header `SC7731E\0\0\0...` followed by an FDL descriptor block and then
ARM/Thumb code. These are the first- and second-stage Flash Downloaders for
Spreadtrum/Unisoc SC7731E (and compatible SC9832/SC9863) chips — standard
SPRD protocol boot stages used by every ResearchDownload/UpgradeDownload
compatible tool.

### D.6 Samsung Spreadtrum DA `Data/DA/samsung.da`

Begins with `SC-53F.bin` — this is the Spreadtrum SC7731/SC9830-based DA for
Samsung feature phones / entry Galaxy models on Unisoc chips (e.g. SM-Bxxx,
SM-G31x, some A-series with SPRD radio).

### D.7 MediaTek DAs (many are plaintext)

Most `*.da` files (AGM, ASUS, BLACKVIEW, HUAWEI_HONOR, INFINIX_TECNO, ITEL,
LENOVO, MOTOROLA, MTK, NOTHING, ONEPLUS, OPPO, OUKITEL, REALME, TCL,
TECLAST, ULEFONE, UMIDIGI, VIVO, XIAOMI) begin with an ASCII tag showing
their source binary name embedded at offset 0 — they are raw DA binaries, not
encrypted. Only the ones named `*.crp` are encrypted containers.

---

## PART E — READ-ONLY REFERENCE PARSER SCRIPTS

The following Python scripts (under `RE_work/parsers/`) give read-only
structural introspection of the databases without decrypting payloads or
defeating any DRM.

(They are written as companion files.)

---

## PART F — MOBILE FLASHING PROTOCOL MAP

Pandora implements (at least) six well-known mobile-service protocols over USB.
This is what Pandora wires together behind each menu item:

### F.1 MediaTek (MTK)

- BootROM (BROM) mode: USB VID/PID 0x0E8D/0x0003 (Preloader) or 0x0E8D/0x0003
  factory boot (BROM) — communicates via the public MediaTek Boot ROM protocol
  documented in brom-dll sources (libwped/mtk-bypass projects).
- Download Agent (DA) is uploaded to device RAM; the DA exposes the DA-command
  protocol (READ/WRITE/FORMAT/GET_ID/EMI init etc.) over USB bulk endpoints.
- Pandora selects a per-brand/custom DA (the `Data/DA/*.da` files) to bypass
  DAA/SLA/PPL authentication required on modern MTK chips.
- **MetaCore.dll (META_DLL)** is used for operations performed while the
  phone is in **META Mode** (factory diagnostic mode booted after DA handshake):
  - IMEI read/write (`META_MISC_GetIMEIValue/SetIMEIValue`)
  - NVRAM read/write/backup/restore (`META_NVRAM_*`)
  - RF calibration
  - FAT access
  - eMMC/UFS partition I/O (`META_MMC2K_*`)
  - Baseband version/info
- **BROM/Preloader** mode (without META boot) does: firmware flashing (SCAT
  format), FRP reset, format, partition read/write, EMI detection, "Bypass"
  (SLA/DAA) using BootROM exploit (BootROM payload in the main EXE — similar
  to publicly-known `mtk-bypass` technique but built in-house).

**GUI features → MTK endpoint mapping** (example):
| GUI action | Protocol layer |
|---|---|
| Flash Firmware (SCAT) | BROM → DA → Flash Write partitions |
| Read Info (Preloader/BROM) | BROM → DA → GetTargetConfig |
| Read Info (META) | META_MISC_GetVersion etc. |
| Repair IMEI | META_META mode connect → META_MISC_SetIMEIValue + NVRAM_Compose_IMEISV |
| Format All | BROM → DA → Format partitions |
| Erase FRP | BROM → DA → Write to FRP partition (typically `frp`) |
| Backup NVRAM | META_NVRAM_Read + backup to file |
| Bypass (BROM/Preloader) | BROM exploit → Send DA |
| Adv Authorization | SLA/DAA challenge-response signed by Pandora server |

### F.2 Spreadtrum / Unisoc (SPRD/UniSoC)

- Phone enters **FDL mode** after boot ROM handshake.
- Pandora sends **FDL1** (primary loader, 1.19 MB) to internal RAM; FDL1
  initializes DRAM using EMI parameters.
- Then sends **FDL2** (secondary loader, 16.4 MB) to DRAM; FDL2 implements
  the full flashing protocol for SPD PAC firmware packages.
- Magic `SC7731E` in both loaders confirms the loader set is a stock-style
  SPD FDL built for SC7731E/SC9832/SC9863 family.
- The "Flash Firmware (PAC)" operation = PAC unpacking via 7z.dll → FDL
  channel write.
- "Repair IMEI" on SPD is done via NV items (not META); protocol is over a
  DIAG-spoofing channel after boot.

### F.3 Qualcomm

- **EDL (Emergency Download) mode** — VID/PID `0x05C6/0x9008` (Qualcomm Sahara).
- **Sahara protocol** first uploads a Firehose programmer (`prog_ufs_firehose*`
  or `prog_emmc_firehose*`). The programmer itself is not bundled in this
  installation — it must be extracted from firmware or obtained online.
- **Firehose (programmer)** protocol handles raw partition read/write,
  configure, setbootablestoragedrive, power reset, etc.
- GUI option "TEST QCOM / UFS Partition Manager" confirms Firehose-driven
  partition manipulation.
- Operations: Read Info, Flash Raw, Erase FRP, Reset Mi Account, UFS format.

### F.4 Samsung

- Two paths: (1) older Samsung/Spreadtrum phones → `samsung.da` (SC-53F DA);
  (2) Exynos-based Samsung → likely Odin protocol (TAR firmware over USB
  bulk in Download Mode) — confirmed by GUI "Erase FRP (ODIN)" and "Flash
  Firmware (TAR)".
- "Flash Firmware (TAR)" = Odin `.tar.md5` flashing.

### F.5 HiSilicon (Kirin)

- Mentioned in the catalog table (KIRIN entries present in `catalogs` though
  no model rows yet) → Huawei Hisilicon USB-com / fastboot / serial protocol
  for Kirin-based phones (used for "Reset Huawei ID").

### F.6 Rockchip

- Single Rockchip model entry — uses standard Rockchip USB maskrom protocol
  over `libusb0`, RK upgrade-format (`.img` via rkflashtool-style commands).

### F.7 Google Pixel / Exynos

- 19 entries in EXYNOS platform — all brand=Google, likely for Pixel phones
  with Exynos modems (international models). Uses Samsung Odin-style flashing
  protocol for bootloader manipulation and FRP operations.

### F.8 ADB layer

- After-boot operations (non-bootROM) use `AdbWinApi.dll` / `AdbWinUsbApi.dll`
  (stock ADB libraries from Google platform-tools) → push/pull, shell,
  "ADB File Explorer", "Enable ADB", "Reset FRP" via content provider tricks,
  "Reboot to Fastboot".

### F.9 Fastboot

- Direct USB bulk protocol (not an external DLL, implemented inside
  PandoraTool.exe using WinUSB/libusb) → bootloader unlock/relock, partition
  flash, device info (used for Xiaomi Unlock, Huawei ID reset variants,
  generic bootloader commands).

### F.10 Network stack

- WinInet handles HTTP(S) to Pandora servers for:
  - Account login
  - Credit purchase/balance
  - Activation/card binding
  - Firmware database updates
  - Software manifest download (updater)
  - Paid operations: "Unlock Network (credits)", "Read Codes (credits)" —
    these are server-side credit-consuming services.
- BCrypt/NCrypt for local encryption of account data and blob decryption.

---

## PART G — WORKSPACE / DISASSEMBLY ARTIFACTS PRODUCED

```
RE_work/
├── ida/
│   ├── metacore_idapython.py   # IDA Pro label script for MetaCore.dll (3,419 names)
│   └── metacore_ghidra.py      # Ghidra label script for MetaCore.dll
├── metacore/
│   ├── exports.txt             # Alphabetical list of all 3,419 named exports
│   └── exports_by_category.md  # Exports categorized by META subsystem
├── parsers/
│   └── (read-only DB parsers added below)
├── rsrc/
│   ├── main/                   # Resources from PandoraTool.exe (manifest, version, icons)
│   ├── updater/                # Resources from PandoraUpdater.exe (61 files):
│   │   ├── MANIFEST.1.L1033.xml   # Embedded app manifest
│   │   ├── VERSION.1.L1033.bin   # VS_VERSION_INFO
│   │   ├── RCDATA.MSG_INFO.png   # Info task-dialog icon (64x64 PNG)
│   │   ├── RCDATA.MSG_WARNING.png
│   │   ├── RCDATA.MSG_ERROR.png
│   │   ├── RCDATA.DVCLAL.L0.bin  # Delphi VCL alignment marker
│   │   ├── RCDATA.PACKAGEINFO.L0.bin
│   │   ├── RCDATA.PLATFORMTARGETS.L1033.bin
│   │   ├── ICON.*.L1033.bin     # 13 icons (including MAINICON)
│   │   ├── CURSOR.*.L1033.bin   # 7 cursors
│   │   └── STRING.4072..4096.L0.bin  # Delphi string tables
│   ├── metacore/ … (version, manifest, PRIMITIVE resources)
│   ├── sz7/      … (version + icon group)
│   ├── lz4/      … (version, manifest)
│   └── adbapi, adbusb, sqlite … (version/string)
└── (this file: DEEP_REFERENCE.md)
```

### G.1 Generating a Ghidra/IDA project quickly

For **MetaCore.dll** (the most rewarding target for RE):
1. Copy `MetaCore.dll` into your disassembly project directory.
2. Load as PE/x86. Let auto-analysis finish.
3. Run `RE_work/ida/metacore_idapython.py` (IDA) or `RE_work/ida/metacore_ghidra.py` (Ghidra).
4. All 3,419 named API functions now have public symbols; you can locate each
   META subsystem by name (`META_MISC_SetIMEIValue`, `META_NVRAM_ReadNvram`, etc.).

For **PandoraTool.exe**: the UPX stub must be unpacked first. On Windows the
simplest path is to run the EXE under a debugger and dump after the unpack
stub runs, or use `upx -d` with a matching UPX version (the UPX version
string is wiped from headers, but section layout suggests UPX 3.96 / 4.x
series). Without network access I cannot download UPX in this sandbox;
static unpacking is possible but is 300+ lines of PE rebuilding and is a
task for the analyst's own workstation. After unpacking, re-running the same
resource/RVA walker on the dumped EXE will produce:
- Full DFM forms (all TForm descendants as binary DFM, convertible to text
  with Delphi's `convert.exe` or open-source `dfm2txt`)
- Delphi RTTI (full unit list, all component classes, published properties)
- Full import table (which will include sqlite3 imports, MetaCore imports,
  winhttp calls, 7z/lz4 imports).

---

## PART H — SUMMARY OF FINDINGS (QUICK REFERENCE)

| Question | Answer |
|---|---|
| Language | Delphi Object Pascal, Win32, compiler 37.0 (Delphi 13 / 12.x era) |
| GUI framework | VCL + Vcl.Styles, PerMonitorV2 DPI, Common Controls v6 |
| HTTP | WinInet (no Indy/Chromium) |
| DB | SQLite 3.30.1 (3 DBs, 1 encrypted with custom magic) |
| Compression | 7z 16.02, LZ4 1.9.4, UPX (main EXE) |
| Packing | UPX on main EXE; Updater/metacore/plug-ins NOT packed |
| 3rd-party | MetaCore (MediaTek META DLL, MSVC 2008), Google ADB, libusb-win32 1.4.0.2 |
| Installer | Inno Setup 6.5.0 |
| SoC platforms | MTK, SPD/Unisoc, Qualcomm (EDL/Firehose), Samsung Exynos (Odin), HiSilicon Kirin, Rockchip |
| Supported chipsets confirmed in DA loaders | MT6572/6580/67xx/68xx/69xx (Dimensity 6781–6983), SC7731E/SC9832/SC9863/Tiger T606/T310 |
| Hardware dongle | Pandora Box (smart-card + WinUSB, firmware-upgradable, online ban/credit system) |
| Build date | Feb–Sep 2026; DB and drivers dated 2026-09 |
| Version | PandoraTool 10.2.20.0; MetaCore (META_DLL) 10.2124.0.03 Official-Build |
| Source code present | NO — repo is installed binaries only |

---
*End of deep reference.*
