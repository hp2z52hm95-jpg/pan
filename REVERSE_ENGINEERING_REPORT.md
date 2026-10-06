# Pandora Tool — Full Reverse Engineering / Stack Analysis Report

**Repository:** `hp2z52hm95-jpg/pan` (branch `arena/4b293c8c-pan`)
**Single-commit checkout of commit:** `1f629eb 8`
**Date of analysis:** 2026-10-06
**Analyst tooling:** Python `struct` PE parser, `strings`, manual header parsing, SQLite introspection.
---

## 1. WHAT THIS REPOSITORY IS

This is **NOT a source-code repository**. It is a verbatim snapshot of an installed
distribution of a commercial Windows software product called **"Pandora Tool"**
(version **10.2.20.0**) — a professional mobile-phone / smartphone servicing,
flashing, unlocking and IMEI-repair application sold under the Pandora brand
(popularly known in GSM-service markets for MTK / Spreadtrum / Qualcomm work).

The tree contains:
* the main GUI EXE (`PandoraTool.exe`),
* the companion auto-updater (`PandoraUpdater.exe`),
* the core flashing/engineering DLL renamed as `MetaCore.dll`
  (MediaTek **META_DLL** — Mobile Engineering Testing Architecture),
* DA (Download Agent) binaries, preloader boot images, FDL1/FDL2 loaders for
  MediaTek and Spreadtrum/Unisoc chipsets,
* two SQLite databases (EMI/DRAM timing table + firmware catalog),
* one encrypted SQLite model database (file named `models.mdb` but actually
  SQLite, not JET/MDB),
* multi-language UI translations (24 locales),
* third-party runtime DLLs (SQLite, 7-Zip, LZ4, Google ADB, libusb-win32),
* and an Inno Setup uninstall log/binary (`unins000.exe`, `unins000.dat`).

There is **no source code**, **no build scripts**, **no project files**, **no
package.json/CMake/Makefile/Delphi .dpr/.dproj** anywhere in the tree. Every
binary is a final PE/Win32 binary ready to run on Windows. Reverse engineering
was performed by static binary inspection.

---

## 2. STACK / LANGUAGE / FRAMEWORK (CORE FINDING)

| Layer | Technology | Version identified |
|---|---|---|
| **Programming language** | **Embarcadero Delphi (Object Pascal)** for Win32 | **Compiler version 37.0.57242.3601** (very recent Delphi; 37.x maps to post-Delphi-12-Athens / Delphi 13 era; released c. 2025) |
| GUI framework | **VCL (Visual Component Library)** | Modern VCL with `Vcl.Forms`, `Vcl.Controls`, `Vcl.Menus`, `Vcl.ComCtrls`, `Vcl.Themes`, `Vcl.Graphics` etc. — namespaces match the *unit-scoped* style introduced in Delphi XE2 |
| Generics/RTL | Delphi RTL with generics (`TArray<T>`, `TList<T>`, `TObjectList<T>`, `TDictionary<K,V>`, `TEnumerator<T>`, `TComparer<T>`, `TPair<K,V>`) | Confirms XE2+ (generics) and XE3+ (namespaces) |
| VCL Styles / Theming | Enabled (`TStyleHook`, `TFormStyleHook`, `TSysStyleHook`, `TChildControlInfo`, `TMainMenuBarStyleHook`) | |
| HTTP client | **Winapi.WinInet** (no Indy, no System.Net.HttpClient, no CEF/Chromium, no libcurl) | |
| Process packing | **UPX** (sections `.upx0`, `.upx1`, `.upx2`) on `PandoraTool.exe`; `PandoraUpdater.exe` is **NOT UPX packed** (which is why it was used for symbol/unit discovery) | UPX shell present; exact version string not preserved in overlay |
| Installer | **Inno Setup 6.5.0** (engine data marker: `Inno Setup Setup Data (7.0.0.3)`; uninstall log says 6.5.0 messages) | |
| Architecture | **32-bit x86 (PE32, machine 0x14c)** for the main EXE, MetaCore DLL and all bundled native DLLs. Includes ARM64 + x86 + x64 versions of `libusb0.sys/dll` kernel driver for user-side USB access on those OSes. | |
| Subsystem | Windows GUI (`subsystem=2`) for `PandoraTool.exe`/`PandoraUpdater.exe` | |
| Manifest | DPI **PerMonitorV2** aware, `longPathAware=true`, **`requireAdministrator`** (main tool; needs it to install USB drivers and talk to bootROM), Common Controls v6, supports Vista through Windows 10 (IDs in manifest) | |
| Windows API imports | kernel32, user32, gdi32, gdiplus, comctl32, comdlg32, ole32, oleaut32, shell32, advapi32, bcrypt, ncrypt, cfgmgr32, setupapi, winhttp, wininet, iphlpapi, netapi32, winscard, winmm, winspool, version, SHFolder, UIAutomationCore, oleacc, WTSAPI32 | Raw Win32, no MFC, no .NET, no Qt, no wxWidgets |
| .NET | **None** (`cli_rva = 0` in COM descriptor for every PE) | Confirmed *not* a .NET / WPF / WinForms app |
| Database engine | **SQLite 3.30.1** (`sqlite3.dll`) — used directly via C ABI from Delphi (likely via a wrapper like `DISQLite3`, `ASQLite`, or custom import units) | 3.30.1 = released 2019-10-10 |
| Compression | (a) **7-Zip 16.02** (`7z.dll`) for firmware archive (.zip/.7z) decompression; (b) **LZ4 1.9.4** (`liblz4.dll`) for fast data compression (likely used in USB protocol with phone/box); (c) UPX on EXE | |
| ADB support | **Google Android Debug Bridge** helper libraries (`AdbWinApi.dll`, `AdbWinUsbApi.dll`) — stock Android platform-tools build; used for the "ADB File Explorer" feature and post-boot operations | Uses WinUSB (`WINUSB.DLL`) on the UsbApi side |
| Low-level USB | **libusb-win32 1.4.0.2** (driver date 01/09/2026!) — tri-arch (x86/amd64/arm64) `libusb0.sys` + `libusb0.dll`, with filter installer; default INF PnP ID is `VID_0B05&PID_190E` (ASUS Zenfone in diagnostic/bootROM mode) | The included INF explicitly lists the device class as "libusb-win32 devices" |
| Smart card / dongle API | `winscard.dll` (WinSCard) imported → confirms **smart-card based hardware activation dongle/card** ("Activation card removed" strings confirm this) | |
| Crypto | `bcrypt.dll`, `ncrypt.dll` (CNG) for modern cryptography; payloads use internal cipher `soft_magic_v1` (XOR/obfuscation, magic `PNDMODEL1`) and catalogs use `aes_softkey_v1` (AES) per the `db_meta` table | |
| Runtime linkage | `msvcrt.dll` (DLLs); `MetaCore.dll` links against **MSVCR90/MSVCP90** = **Visual C++ 2008 (VC9)** — meaning the MTK META core was originally compiled with MSVC 9.0 | |
| Telemetry/networking | `winhttp.dll`, `wininet.dll`, `iphlpapi.dll`, `netapi32.dll`, `WTSAPI32.dll` (RDP/session enumeration), `winspool.drv` (printing) | Network used for activation, credit operations, software updates, and firmware database updates |

**Conclusion: 100% native Delphi VCL Win32 application**, not C#, not C++/Qt, not Electron.
The only C/C++ pieces are the third-party libraries (MetaCore/META_DLL is MediaTek's
own C/C++ library compiled with VS2008; SQLite, 7z, lz4, libusb, ADB are all C).

---

## 3. BINARY INVENTORY (SIGNED / VERSIONED)

| File | Size | FileVersion | Notes |
|---|---:|---|---|
| `PandoraTool.exe` | 29,287,424 (≈28 MB) | 10.2.20.0 | Main GUI. UPX-packed, 32-bit PE32, 13 sections (.upx0/1/2 markers), product "Pandora Tool" |
| `PandoraUpdater.exe` | 2,642,944 (≈2.5 MB) | 1.0.0.0 | Auto-updater helper. NOT packed. Delphi 37.0 compiled; contains units `uPandoraUpdateCore`, `uPandoraUpdaterForm`, `uCallbackMessage`, `uTimeout`, `uVersion`, `uFlags`. |
| `MetaCore.dll` | 14,846,464 (≈14 MB) | 10.2124.0.03 `[Official-Build - General] (Release Version)` | **MediaTek META_DLL.dll** (internal name) — "Mobile Engineering Testing Architecture DLL", Copyright (C) 2006 MediaTek Inc. Built with MSVC 9 (VS2008). **4,708** total exports, 3,419 by name — the entire META factory API surface. |
| `sqlite3.dll` | 932,223 | 3.30.1 | Official SQLite amalgamation build |
| `7z.dll` | 1,075,528 | 16.02 | Igor Pavlov's 7-Zip SDK |
| `liblz4.dll` | 97,792 | 1.9.4 | Yann Collet's LZ4 |
| `AdbWinApi.dll` | 96,256 | — | Google ADB Win32 API |
| `AdbWinUsbApi.dll` | 60,928 | — | Google ADB WinUSB backend |
| `unins000.exe` | 4,521,202 | — | Inno Setup uninstaller (6.5.0/7.0.0.3 data) |
| `unins000.dat` | 98,028 | — | Inno Setup uninstall log |
| `Firmwares.db3` | 1,134,592 | DB ver `2026_02_19_05_00_07` | SQLite — firmware file catalog (7,307 files) |
| `emi_base.db3` | 23,224,320 | schema 1 (date 1781340393 ≈ 2026) | SQLite — EMI / DRAM init table (**29,941** preloader/EMI records keyed by eMMC CID + chip ID) |
| `models.mdb` | 35,559,424 | db_version 1 | **SQLite** (despite `.mdb`). Encrypted model/payload DB: 11,652 phone models across 6 SoC platforms; payload magic `PNDMODEL1` encrypted with `soft_magic_v1`; catalogs encrypted with `aes_softkey_v1`. |

---

## 4. LOADERS / PAYLOADS (THE "DATA" DIRECTORY)

### 4.1 Spreadtrum / Unisoc FDL loaders (`Data/FDL1`, `Data/FDL2`)
- Magic header `SC7731E\0` — these are the Spreadtrum SC7731E (and compatible)
  **Flash Downloader** stages (FDL1 = tiny primary loader, FDL2 = full protocol
  runtime). 1.19 MB and 16.4 MB respectively.

### 4.2 MediaTek Download Agents (`Data/DA/*.da`, `Data/DA/*.bin`)
Per-brand Download Agent binaries for MediaTek BROM / Preloader protocol.
Each file starts with an embedded ASCII tag (its inner "source" DA name):

| File | Inner tag / source | Purpose |
|---|---|---|
| `MTK_AllInOne_DA.bin` | `MTK_DOWNLOAD_AGENT` | Generic MTK all-in-one DA (~17 MB) |
| `MTK.da` | `MTK_AllInOne_DA.bin` | MTK generic |
| `DA_v6.crp` | `MTK_DOWNLOAD_AGENT` | Encrypted/obfuscated v6 DA |
| `MTK_AllInOne_DA_v2.crp` | `MTK_DOWNLOAD_AGENT` | Encrypted v2 DA (~20 MB) |
| `AGM.da` | `PAD_P1.bin` | AGM rugged |
| `ASUS.da` | `AI2203.bin` | ASUS Zenfone |
| `BLACKVIEW.da` | `Active_8_pro.bin` | Blackview |
| `DOOGEE.da` | `allinone_v6.bin` | Doogee |
| `HUAWEI_HONOR.da` | `JDY-LX1.bin` | Huawei/Honor |
| `INFINIX_TECNO.da` | `allinone_v5_type_1.bin` | Infinix/Tecno (Transsion) |
| `ITEL.da` | `P1102GT_M11.bin` | Itel (Transsion) |
| `LENOVO.da` | `mt6897.bin` | Lenovo (Dimensity-class) |
| `MOTOROLA.da` | `MT6768_type_1.bin` | Motorola Helio G/P series |
| `NOTHING.da` | `CMF_Phone_1_(23114).bin` | Nothing/CMF |
| `ONEPLUS.da` | `CPH2411.bin` | OnePlus (OPPO-shared DA) |
| `OPPO.da` | `CPH2357.bin` | OPPO |
| `OUKITEL.da` | `allinone_v6.bin` | Oukitel |
| `REALME.da` | `RMP2204.bin` | Realme |
| `TCL.da` | `4163.bin` | TCL/Alcatel |
| `TECLAST.da` | `T65_MAX.bin` | Teclest tablet |
| `ULEFONE.da` | `allinone_v6.bin` | Ulefone |
| `UMIDIGI.da` | `G3_Tab_Ultra.bin` | Umidigi |
| `VIVO.da` | `allinone_v5_type_1.bin` | Vivo |
| `XIAOMI.da` | `Poco_C61_Redmi_A3_MT6765_sec2024` | Xiaomi/Redmi/Poco (MT6765 secure DA, 2024) |
| `samsung.da` | `SC-53F.bin` | **Spreadtrum**-based Samsung feature/Exynos? chip (SC-53F is a Unisoc/Spreadtrum model tag for Samsung entry phones) |

So the tool ships a *custom DA per brand* (a typical Pandora/Z3X/UMT/Hydra-style
behavior for bypassing DAA/SLA auth on MTK devices).

### 4.3 Preloader payloads (`Data/DA/preloader*.crp`)
A family of encrypted (`.crp` = crypted) preloader images for different SoCs:
* `preloader.crp`, `preloader2.crp`, `preloader5.crp` — small legacy (~16 KB), ARM vector table visible (`0x0E 0x00 0x00 0xEA` = ARM B opcode),
* `preloader3.crp` (478 KB), `preloader4.crp` (395 KB) — larger generic,
* `preloader3_v6_MT6781/MT6789/MT6835/MT6855/MT6886/MT6895/MT6983.crp` —
  chip-specific preloader v6 blobs for MT67xx/MT68xx/MT69xx (Dimensity) SoCs.

---

## 5. DATABASES IN DETAIL

### 5.1 `emi_base.db3` (SQLite, schema_ver = 1)
* One big table `EmiInfo` — **29,941 rows** of External Memory Interface (DRAM
  init / preloader EMI config) blobs.
* Columns: `id, version, brand, model, emmc_id, sub_ver, m_type, id_len, emi_crc, data, data_size, src_name, src_path, created`.
* Keyed by brand/model/eMMC ID + m_type (MTK Memory Type codes — values include
  514, 515, 518, 774, etc.; these correspond to eMMC/UFS families in the MTK
  preloader).
* Top brands by record count: OPPO 2,966, Realme 2,763, Tecno 2,216, Vivo 2,090,
  Infinix 1,480, Lenovo 1,371, Motorola 1,344, Samsung 1,120, BLU 1,116,
  "China Phones" 1,085, Xiaomi 863, etc. In total 100+ brands.
* `data` is binary EMI/DRAM init payload, used by the flashing engine to
  initialize RAM when connecting to a phone in BROM mode.
* Sample record: `AGM H5, eMMC id 150100335636434D42, m_type=518, src=preloader_ph01p44_agm_e62_e.bin`.

### 5.2 `Firmwares.db3` (SQLite, version tag `2026_02_19_05_00_07`)
* Tables: `Files`, `Version`.
* `Files` columns: `id, file_name, file_size, hits, active, new, created_at, updated_at`.
* **7,307 firmware file entries**; paths look like
  `2. Firmwares/<Brand>/<Model>/<filename>.zip` — these are *references* to
  stock firmware archives on Pandora's servers/hub (not bundled; 779 MB–2 GB
  typical size, `hits` = download count, `active/new` = flags).
* Recent `updated_at` timestamps go up to **2026-02-09** — very recent DB build.

### 5.3 `models.mdb` (despite extension, **SQLite**)
* Tables: `db_meta`, `models` (11,652 rows), `catalogs` (6 entries), `sqlite_sequence`.
* Metadata:
  * `payload_crypto = soft_magic_v1`
  * `catalog_crypto = aes_softkey_v1`
  * `crypto_migrated_at` timestamp present (schema migration happened).
* `models` columns: `id, brand, name, code_name, platform, cpu, payload, updated_at`.
  Payloads begin with magic `PNDMODEL1>` followed by obfuscated binary (per-model
  configuration: protocol parameters, loader selection, auth bypass flags,
  operation permissions).
* `catalogs` columns: `platform, data, json_mtime` — per-platform brand/model
  catalogs, magic `PNDCAT01`, AES-encrypted.
* **Platforms supported (model counts):**
  * **MEDIATEK** — 7,658 models
  * **SPREADTRUM** (Unisoc) — 2,628
  * **QUALCOMM** — 1,346 (EDL / Sahara / Firehose protocol)
  * **EXYNOS** — 19 (Google Pixel; likely Samsung/Exynos Pixel modems)
  * **RKCHIP** — 1 (Rockchip)
  * Plus `catalogs` entries for **KIRIN** (HiSilicon), present in catalogs
    though only a few models (more added via server).
* This is the "model selection" catalog that powers the GUI's Brand/Model
  dropdowns. Total 11,652 phone profiles.

---

## 6. MEDIATEK METACORE.DLL — API SURFACE

MetaCore.dll is MediaTek's official **META (Mobile Engineering Testing
Architecture)** DLL (its internal name is `META_DLL.dll`). It was built with
**MSVC 9 / Visual Studio 2008** (evidenced by `MSVCR90.dll`/`MSVCP90.dll`
imports). It exports **4,708 functions total (3,419 named)** covering the full
factory-level service API for MediaTek phones.  Functional categories observed
from exported names:

| Prefix/Group | Count | Purpose |
|---|---:|---|
| `META_NVRAM_*` / `SP_META_NVRAM_*` | 308+ (626 NVRAM) | Read/write NVRAM (IMEI, BT/Wi-Fi MAC, calibration data, RF cal, etc.) |
| `META_MMRf_*` | 301 | Multi-mode RF (GSM/WCDMA/LTE/NR calibration) |
| `META_Rf_*` | 294 | RF test/control |
| `META_ERf_*` | 240 | Extended RF |
| `META_3Grf_*` | 190 | 3G RF (WCDMA/TDSCDMA) |
| `META_C2K_*` | 105 | CDMA2000 / C2K RF & NVRAM |
| `META_FAT_*` | 98 | FAT filesystem access on device |
| `META_MISC_*` | 80 | IMEI get/set (`META_MISC_GetIMEIValue`, `META_MISC_SetIMEIValue`, `GetIMEILocation`, `GetIMEIRecNum`), BT/Wi-Fi MAC, version info |
| `META_MMC2K_*` | 53 | eMMC / UFS storage control |
| `META_NRf_*` | 39 | 5G NR RF |
| `META_Util_*` | 33 | Utility helpers |
| `META_BB_*` | 12 | Baseband control |
| `META_COMM_*`, `META_Init_*`, `META_ConnectInMetaMode*`, `META_ConnectWithTarget*` | 6–9 each | Connection management (USB/COM port enumeration, connect, disconnect, dynamic USB COM port detection) |
| `META_MDLogging_*` | 6 | Modem debug logging |
| `META_PMIC_*` | 4 | PMIC (power management IC) control |
| `META_BackupCalibrationData*`, `META_RestoreCalibrationData*` | 3 each | Calibration backup/restore |
| `META_UploadFilesToTarget_*` | 9 | File upload to target flash |
| `META_Check*`, `META_Cancel*`, `META_Aux*`, `META_Customer*`, `META_Debug*`, `META_WatchDog*`, `META_EnableLocalFrameCompression` | several | Miscellaneous |

Also `META_C2K_FlushNvram`, `META_C2K_ReadNvram`, `META_C2K_WriteNvram`, and
explicit IMEI routine families (`META_NVRAM_Calculate_IMEI_CD`,
`META_NVRAM_Compose_IMEISV*`, `META_NVRAM_Decompose_IMEISV*`, plus `SP_META_NVRAM*`
variants for "Smart Phone" META mode).

**Implication:** Pandora uses official MediaTek META protocol for MTK IMEI
repair, NVRAM read/write, RF calibration, FAT access, and backup/restore
operations (the same protocol used by MauiMETA / SN Write Tool).

---

## 7. UI FEATURE SET (derived from 639 GUI strings + 2,952 log strings in `Languages/*.json`)

24 language files are present (no English file — English is the source-string
key; 3 of them — ARA, FAS, HEB, URD — have `rtl:true` for right-to-left layout):

`ARA, BEN, DEU, FAS, FIL, FRA, HEB, HIN, IND, ITA, JPN, MSA, NLD, POL, PT, PT-BR, RUS, SPA, THA, TUR, UKR, URD, VIE, ZHO` (Arabic, Bengali, German, Farsi/Persian, Filipino, French, Hebrew, Hindi, Indonesian, Italian, Japanese, Malay, Dutch, Polish, Portuguese/EU, Portuguese/BR, Russian, Spanish, Thai, Turkish, Ukrainian, Urdu, Vietnamese, Chinese).

The UI exposes (feature keys translated from the English source strings):

### 7.1 Account / activation / business logic
- Account system (login/logout, auto sign-in, password reset via email reset code)
- "Credits" balance (paid operations)
- Smart-card / **BOX activation** (hardware dongle): activate/link/reactivate/bind to card, per-box SN, "ban" state, firmware upgrade for the Box itself
- EULA acceptance flow with versioned checksum (IMEI disclaimer file present at
  root: `EULA_IMEI.txt`)
- Operation authorization ("Operation not authorized" = server-gated operations)

### 7.2 Platform protocols / bootrom modes
- **MediaTek**: BROM / Preloader / META modes, Adv Authorization (BROM +
  Preloader) bypass, "Force BROM Mode", "Bypass [BROM]", "Bypass [Preloader]",
  `BROM disabled by EFUSE` detection
- **Qualcomm**: EDL / Sahara / Firehose — "TEST QCOM / UFS Partition Manager",
  firehose-style flashing
- **Spreadtrum/Unisoc**: FDL1/FDL2 PAC flashing (SC7731E loaders present)
- **Samsung**: Exynos + Spreadtrum Samsung ("Flash Firmware (TAR)", "Erase FRP (ODIN)")
- **ADB** (post-boot): File Explorer, "Enable ADB", Reboot to Fastboot
- **Fastboot**: bootloader unlock/relock, flash partitions
- **Huawei Kirin**: "Reset Huawei ID" support
- **Xiaomi**: "Reset Mi Account"
- **OPPO/Realme/Vivo**: dedicated DA files and NV features

### 7.3 Service operations
- **Flash Firmware** in multiple vendor formats: SCAT (MTK scatter), PAC (Spreadtrum), OFP (OPPO), KDZ (LG), NB0 (various), TAR (Samsung/Odin), OPS
- **Read Info** / **Read Phone Info** / **META Read Info** (version, IMEI, build ID, baseband, CSC, security patch, boot warranty bit, SIM state, platform, board name, activated slot, crypto state, OPPO NV ID, project/region/carrier)
- **Factory Reset** / **META Factory Reset**
- **Erase / Reset FRP** (Google Factory Reset Protection) — with and without wipe, via ODIN for Samsung, META for MTK
- **Repair IMEI** / **Read IMEI** / **META Repair IMEI** (dual-SIM support implied)
- **Repair SN** (serial number)
- **Backup / Read / Write NVRAM**, Backup NV, Write NV, write DIAG NV
- **Backup / Write / Format RPMB** (Replay Protected Memory Block)
- **Backup Security / Write Security / Wipe Security / Auto Backup Security**
- **Unlock Bootloader / Relock Bootloader / Auto unlock bootloader / Wipe data after BL unlock**
- **Unlock Network** / **Unlock Network (credits)** / **Unlock Regional Lock / Unlock Regional** / **Read Codes / Read Codes (credits)**
- **Reset Screen Lock Password** (data wipe on next boot)
- **Reset Mi Account**, **Reset Huawei ID**, **Reset Account**
- **Reset Dm-Verity Error**, **Reset Anti-Rollback**, **Reset HID**
- **Reset Battery** (battery stats/calibration reset)
- **Disable VBMETA verification**
- **Check eMMC Health**
- **Read OTP**, **Read Region**, **Read EMI from phone**
- **Read/Write/Raw BIN dump**, Partition Manager, Read Partitions, Wipe Partitions, Format All, Format selected partition/range, wipe userdata/cache/metadata
- **Flash APP**, **Flash KDZ**, **Flash NB0**, **Flash OFP**, **Flash OPS**, **Flash TAR**
- **UFS Format all** (LU0/LU1/LU2) with strong warning about bootloader destruction
- **"Repair Chip Damage"** (likely eMMC/UFS low-level reinit)
- **Auto patch after repair**
- **"Route USB through BOX"** (for hardware dongle with USB passthrough/port)

### 7.4 Software update system
- Self-updater via `PandoraUpdater.exe` which:
  * Downloads update manifest and files (chunked progress "Downloading update file N/M")
  * Verifies EULA checksums/URL/version
  * Shows FMainForm / TPandoraUpdaterForm
  * Uses custom classes `TAppliedFile`, `TPendingFile` (in unit `uPandoraUpdateCore`)
  * Uses **WinInet** (no Indy/System.Net), supports PerMonitorV2 DPI & long paths
  * Runs asInvoker, downloads into place and triggers a restart
- In-box firmware DB updates ("New firmwares database is available. Update now?")
- Box firmware (hardware dongle firmware) upgrade ("Upgrade Box", "Box: firmware update required", "Box: recovery mode", FDL/flash error `%.8X` reporting)

---

## 8. DELPHI-SPECIFIC INTERNALS (from PandoraUpdater.exe RTTI)

Because `PandoraTool.exe` is UPX-compressed, RTTI and method names are crushed
and mostly unrecoverable statically without unpacking. `PandoraUpdater.exe`,
however, is not packed, and preserves Delphi RTTI strings.

Identified compiled Delphi units/classes:
- `uPandoraUpdateCore` (core update logic)
  - Classes: `TAppliedFile`, `TPendingFile`
  - Heavy use of generics: `TList<TAppliedFile>`, `TArray<TAppliedFile>`, `TArray<TPendingFile>`, `TEnumerable<TAppliedFile>`, `IComparer<TAppliedFile>`, `TEnumerator<TAppliedFile>` — all with full RTTI
- `uPandoraUpdaterForm` (form class `TPandoraUpdaterForm`)
  - Async method `StartApply` with several nested anonymous-method closures
    (`$0$Intf`, `$0$0$Intf`, `$ActRec`, `$0$Body$ActRec`) — confirms heavy use of
    anonymous/async procedures (introduced in Delphi 2009/2010 and extended
    through XE versions).
- Helpers: `uCallbackMessage`, `uTimeout`, `uVersion`, `uFlags`, `uOf`, `uXt`
  (obfuscated unit names), and a few mangled `uAJt`/`uBj@`/`uDJt`/`uDhX`/`uENt`
  — the latter suggests the authors may have run some unit-name obfuscation on
  the main product but left the updater relatively clean.

Compiler marker exactly:
`Embarcadero Delphi for Win32 compiler version 37.0 (37.0.57242.3601)`

VCL unit namespaces referenced in RTTI:
`Vcl.Forms`, `Vcl.Menus`, `Vcl.ComCtrls`, `Vcl.Themes`, `Vcl.Controls`, `Vcl.Graphics`,
`System.Classes`, `System.UITypes`, `System.Types`, `Winapi.Windows`, `Winapi.WinInet`,
`Winapi.Imm`, `Winapi.ImageHlp`, `Winapi.MsInkAut`, `Winapi.RegStr`.

What is **not** present (i.e. not used):
- Indy (`IdHTTP`, `IdTCPClient`, etc.) — network is done directly via WinInet
- `System.Net.HttpClient` (Delphi's native HTTP client)
- CEF/Chromium/Sciter/Skia4Delphi (no embedded HTML/JS UI)
- DevExpress, TeeChart, VirtualTreeView, JVCL/JCL (no obvious strings)
- No `FireDAC`, no `UniDAC`, no `Zeos`, no `REST.Client` → database access is
  either direct C-level imports to `sqlite3.dll` or a custom SQLite wrapper.
- No madExcept/EurekaLog (no `madExcept`/`EurekaLog` markers)
- No FastMM4/FastCode (these strings would appear unmistakeably in the EXE;
  absence suggests they rely on the built-in RTL memory manager or compiled
  with `{$DEFINE UseMSMemoryManager}` or similar)

---

## 9. THIRD-PARTY COMPONENTS / RUNTIME SUMMARY

| Component | Purpose | Version/Build |
|---|---|---|
| MediaTek META_DLL | MTK servicing API (IMEI/NVRAM/RF/FAT) | 10.2124.0.03 Official-Build, 2006+ (MSVC 9.0 / VS 2008) |
| SQLite | Local metadata storage | 3.30.1 |
| 7-Zip (7z.dll) | Firmware archive extraction (.zip/.7z/.md5/.tar) | 16.02 (2016) |
| LZ4 | Fast wire-compression over USB | 1.9.4 (2020) |
| Google ADB (`AdbWinApi/AdbWinUsbApi`) | Android Debug Bridge transport | Stock Android platform-tools build |
| libusb-win32 (`libusb0.sys/.dll`) | Low-level USB device access (32/64/ARM64) | **1.4.0.2** driver date **01/09/2026** (fresh build) |
| UPX | Executable compression on main EXE | (presence only confirmed via section names `.upx0/.upx1/.upx2` and UPX! marker) |
| Inno Setup | Installer/uninstaller | Engine data 7.0.0.3 / messages 6.5.0 |
| Microsoft Visual C++ 2008 CRT | Used by MetaCore.dll (MSVCR90/MSVCP90) | 9.0.xxxxx |
| Microsoft Universal CRT (api-ms-win-crt-*) | Used by liblz4.dll | VS2015+ UCRT |
| VCRUNTIME140 | liblz4.dll dependency | VS2015+ |
| Microsoft Windows Common Controls v6 | ComCtl32 v6 visual styles | Declared in manifest |

---

## 10. CRYPTO / OBFUSCATION NOTES

1. **Model database (`models.mdb`)** payloads are prefixed with `PNDMODEL1` and
   are obfuscated with `soft_magic_v1` (likely multi-byte XOR or shuffle with a
   soft-coded key — the `soft` prefix suggests the key is present in the EXE
   binary rather than tied to a remote server).
2. **Catalog blobs** (`catalogs.data`) use `aes_softkey_v1` — AES with a
   soft-coded key (PKCS#7 padding, key-block validation, catalog cipher length
   checks — see error strings in the GUI: "Catalog cipher length invalid",
   "Catalog key block invalid size", "Catalog key block size invalid", "Catalog
   PKCS7 padding invalid").
3. **`.crp`** files in `Data/DA/` are encrypted/custom-packaged DAs and
   preloaders (suffix `crp` = crypted).
4. **BCrypt/NCrypt** (Windows CNG) imported for modern crypto primitives
   (likely for TLS client certs or activation signature verification).
5. **WinHTTP / WinINet** for HTTPS connections (activation server, updates,
   firmware downloads).
6. Error strings reveal internal API: `Box decrypt failed (status=%d)` — the
   hardware box does symmetric decryption/challenge-response.

---

## 11. HARDWARE / ACTIVATION MODEL

The tool is **hardware-protected**:
* A physical "Pandora Box" (or smart-card dongle) is required; detected over
  USB (libusb-win32 / WinUSB / smart-card API).
* Activation card is paired with a Box SN: "BOX linked to card %s",
  "The card is already used with another box", "Your BOX already binded to another CARD".
* Account system (email+password) links card/box to a user account
  ("This card is not linked to the account", "This computer is not linked").
* Credit-based paid features ("Unlock Network (credits)", "Read Codes (credits)").
* Boxes can be banned remotely ("Box is banned").
* Boxes have updatable firmware and can enter recovery mode.
* The updater can "Update card via Shell" (shell = companion shell software).
* "Route USB through BOX" suggests newer Pandora Boxes have an internal USB
  hub/controller so the phone plugs into the box rather than directly into PC.

---

## 12. DIRECTORY LAYOUT (installed copy)

```
pan/                                  # installation root
├── PandoraTool.exe                   # Main Delphi VCL GUI (UPX-packed, x86)
├── PandoraUpdater.exe                # Auto-updater (Delphi, not packed)
├── MetaCore.dll                      # MediaTek META_DLL (MSVC9)
├── sqlite3.dll                       # SQLite 3.30.1
├── 7z.dll                            # 7-Zip 16.02
├── liblz4.dll                        # LZ4 1.9.4
├── AdbWinApi.dll                     # Google ADB USB API
├── AdbWinUsbApi.dll                  # Google ADB WinUSB backend
├── 7z.dll                            # compression (duplicate noted)
├── emi_base.db3                      # EMI DRAM preloader DB (29,941 records)
├── Firmwares.db3                     # firmware file catalog (7,307 entries)
├── models.mdb                        # encrypted model/catalog DB (11,652 models, SQLite)
├── unins000.exe / unins000.dat       # Inno Setup uninstaller
├── EULA_IMEI.txt                     # IMEI legal warning
├── README.md                         # just "# pan" (repo placeholder)
├── Languages/                        # 24 JSON translation files (639 GUI + 2,952 log keys each)
│   ├── ARA.json, BEN.json, DEU.json, FAS.json, FIL.json, FRA.json, HEB.json,
│   ├── HIN.json, IND.json, ITA.json, JPN.json, MSA.json, NLD.json, POL.json,
│   ├── PT-BR.json, PT.json, RUS.json, SPA.json, THA.json, TUR.json, UKR.json,
│   ├── URD.json, VIE.json, ZHO.json
├── Data/
│   ├── FDL1                          # Spreadtrum FDL primary (SC7731E)
│   ├── FDL2                          # Spreadtrum FDL secondary (SC7731E)
│   └── DA/                           # Download Agents & preloaders
│       ├── MTK_AllInOne_DA.bin       # Generic MTK DA (~17 MB)
│       ├── MTK_AllInOne_DA_v2.crp    # Encrypted v2 DA
│       ├── DA_v6.crp                 # Encrypted v6 DA
│       ├── MTK.da, AGM.da, ASUS.da, BLACKVIEW.da, DOOGEE.da,
│       │   HUAWEI_HONOR.da, INFINIX_TECNO.da, ITEL.da, LENOVO.da,
│       │   MOTOROLA.da, NOTHING.da, ONEPLUS.da, OPPO.da, OUKITEL.da,
│       │   REALME.da, TCL.da, TECLAST.da, ULEFONE.da, UMIDIGI.da,
│       │   VIVO.da, XIAOMI.da, samsung.da
│       ├── preloader.crp, preloader2.crp, preloader3.crp, preloader4.crp,
│       │   preloader5.crp
│       └── preloader3_v6_MT{6781,6789,6835,6855,6886,6895,6983}.crp
└── libusb/                           # libusb-win32 driver bundle
    ├── libusb0.inf                   # Default ASUS Zenfone VID_0B05&PID_190E
    ├── libusb-win32-devel-filter-1.4.0.2.exe
    ├── libusb0.cat
    ├── x86/libusb0.sys, libusb0_x86.dll (+ install-filter + testlibusb)
    ├── amd64/libusb0.sys, libusb0.dll
    └── arm64/libusb0.sys, libusb0.dll
```

---

## 13. ARCHITECTURE INFERRED (HOW THE PIECES FIT TOGETHER)

```
┌─────────────────────────────────────────────────────────────────┐
│  PandoraTool.exe  (Delphi VCL x86, UPX-packed)                  │
│                                                                 │
│   • GUI (VCL Forms/Vcl.Themes/Common Controls)                  │
│   • Multi-language engine (JSON lang files, RTL support)        │
│   • Account/credits/activation (WinHTTP/WinInet HTTPS client)   │
│   • BOX (dongle) detection (WinSCard + WinUSB + libusb)         │
│   • Port enumeration (SetupAPI, CfgMgr32)                       │
│   ├─ MTK path   → MetaCore.dll (META API) + MTK*.da DAs         │
│   ├─ SPRD path  → FDL1+FDL2 loaders via libusb/serial           │
│   ├─ QCOM path  → Sahara/Firehose (internal) + EDL protocol     │
│   ├─ Exynos/Kirin/RK paths → platform-specific loaders          │
│   ├─ ADB path   → AdbWinApi/AdbWinUsbApi                        │
│   ├─ Fastboot   → direct USB bulk or libusb                     │
│   ├─ Firmware   → 7z.dll (extraction) + LZ4 (on-wire)           │
│   └─ Data/DB    → sqlite3.dll (emi_base, Firmwares, models)     │
│                                                                 │
│  Configuration blobs: models.mdb payloads AES/XOR-obfuscated    │
└─────────────────────────────────────────────────────────────────┘
        ▲                ▲
        │ updates        │ updates
        │                │
┌───────────────┐  ┌────────────────────┐
│ PandoraUpdater│  │ Pandora servers    │
│ .exe (Delphi, │  │ (HTTPS, WinInet)   │
│  not packed)  │  │ activation, credits│
└───────────────┘  │ firmware download, │
                   │ model/catalog sync │
                   └────────────────────┘

       ◄──── USB ────►   Pandora BOX / Smart-card dongle
                              ▲
                              │ USB passthrough (route USB through BOX)
                              ▼
                         Phone in BROM/PRELOADER/META/EDL/FDL/ADB/Fastboot
```

---

## 14. FORENSIC / TIMELINE NOTES

* `models.mdb` `created_at = 1777335075` ≈ **2026-04-27** UTC (Unix epoch seconds conversion).
* `models.mdb` `crypto_migrated_at = 1780377062` ≈ **2026-05-31** (encryption schema migration).
* `catalogs.json_mtime` for MEDIATEK = 1788884778 ≈ **2026-09-07** — catalogs refreshed ~1 month before analysis date (2026-10-06).
* `emi_base.db3` `db_date = 1781340393` ≈ **2026-06-11**.
* `Firmwares.db3` `ver = 2026_02_19_05_00_07`, `updated_at` as recent as **2026-02-09** → built Feb 2026.
* libusb driver date = **01/09/2026** (from INF — a September build).
* Delphi compiler build `37.0.57242.3601` is a 2025/2026-era Delphi.
* `PandoraTool.exe` FileVersion = **10.2.20.0**.
* `MetaCore.dll` FileVersion = **10.2124.0.03**.

This is a very recent build (2026) of a mature product.

---

## 15. SUMMARY (ONE-PAGE STACK OVERVIEW)

| Question | Answer |
|---|---|
| **Application type** | Commercial Windows GUI application for mobile phone servicing / flashing / unlocking / IMEI repair ("Pandora Tool") |
| **Primary language** | **Embarcadero Delphi (Object Pascal), Win32** — compiler version 37.0 (post-Delphi-12 / 13 era) |
| **GUI framework** | **VCL (Visual Component Library)** with VCL Styles/themes, PerMonitorV2 DPI, Common-Controls v6 |
| **Paradigm** | Event-driven native Win32, heavy use of Delphi generics & anonymous methods |
| **Network** | **WinInet** (updater and main app); no Indy/no Chromium/no Electron |
| **Hardware I/O** | libusb-win32 1.4.0.2 (custom driver, x86/amd64/arm64), WinUSB (via AdbWinUsbApi), SetupAPI/CfgMgr32 for device enumeration, WinSCard for smart-card/activation dongle |
| **Databases** | **SQLite 3.30.1** (3 databases — EMI timing, firmware catalog, encrypted model/payload catalog) |
| **Compression** | 7-Zip 16.02 (.zip/.7z extraction), **LZ4 1.9.4** (fast on-wire compression), UPX (EXE packer) |
| **Vendor/3rd-party APIs** | MediaTek META_DLL (MSVC 2008 C++ DLL, 4.7k exports) — core of MTK servicing; Google Android ADB libraries |
| **Supported SoC platforms** | MediaTek (BROM/Preloader/META), Spreadtrum/Unisoc (FDL1/FDL2/PAC), Qualcomm (EDL/Sahara/Firehose), Samsung Exynos, HiSilicon Kirin, Rockchip |
| **Packed / obfuscated** | Main EXE packed with UPX; model/catalog databases encrypted (`soft_magic_v1`, `aes_softkey_v1`); DA/preloader files in `.crp` encrypted form; some unit names in updater obfuscated (`uAJt`, `uBj@`, etc.) |
| **Installer** | Inno Setup 6.5.0 |
| **Supported OS** | Windows Vista through Windows 10 (manifest); `longPathAware`, PerMonitorV2 DPI, **requires administrator** |
| **Architecture** | 32-bit x86 main process with WOW64 support; includes native x86/x64/ARM64 kernel drivers for USB |
| **Architecture (logical)** | Delphi VCL client → pluggable platform protocols (MTK/SPRD/QCOM/Exynos/Kirin/RK) via USB/serial → encrypted local model DBs → remote Pandora servers for auth/credits/firmware catalog → hardware activation dongle ("Pandora Box") |
| **Source code available?** | **No.** The repository contains only the installed binaries, databases, translations, and drivers; no `.pas/.dpr/.dpk/.dfm/.rc` or any other source files are present. |

---
*End of report.*
