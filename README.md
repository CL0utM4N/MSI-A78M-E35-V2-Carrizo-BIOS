# MSI A78M-E35 V2 (MS-7721) — unofficial BIOS V6.6 with AMD Carrizo support

An unofficial BIOS for the **MSI A78M-E35 V2 (MS-7721)** that adds support for **AMD Carrizo FM2+ APUs**
such as the **A8-7680**, while still supporting the Kaveri and Godavari chips the board already runs.

| | |
|---|---|
| Board | MSI A78M-E35 V2, MS-7721 (check the sticker / silkscreen: it must say **MS-7721** and **V2**) |
| File | `E7721AMS.660` (8 MB / 8,388,608 bytes, full SPI chip image) |
| SHA-256 | `2c057042488261e79c379b27b8833eed23b31bb47a463e81624e4a85b11a51d3` |
| Based on | MSI A68HM-E33 V2 BIOS **V8.5** (2018-11-02, `E7721AMS.850`) |
| AGESA | CarrizoFM2r2PI **1.3.0.1X** (official A78M-E35 V2 V6.5 has 1.2.0.4X) |
| Tested | A6-7400K (Kaveri) and **A8-7680 (Carrizo)** on a real A78M-E35 V2: POSTs, boots, CPU temperature correct, model and version shown correctly |

> **Unofficial and at your own risk.** This is not made or supported by MSI. Flashing any BIOS can brick a
> board. Have a way to recover (a CH341A SPI programmer) and a **backup of your own chip** before you start.

## Why this version exists

MSI never released a Carrizo BIOS for the A78M-E35 V2. Its last BIOS, **V6.5**, uses AGESA 1.2.0.4X
and does not support the A8-7680.

The **A68HM-E33 V2** shares this board's BIOS project (`E7721AMS`, both are MS-7721). Its V8.5 BIOS
added *"Support new AMD Carrizo APU"* with AGESA 1.3.0.1X. The two BIOS families were built from the same
code base, so the A68HM-E33 V2 image runs on the A78M-E35 V2.

Transplanting only the CPU code into V6.5 was investigated in depth and rejected: AGESA's CPU init module
reads board-specific Setup variable offsets that differ between the two boards' builds, so a mixed image
would silently misconfigure the board. Instead, this release is the A68HM-E33 V2 V8.5 image with these
changes:

1. **Board name** — `A68HM-E33 V2` → `A78M-E35 V2` in Setup and in the SMBIOS/DMI tables (PCB
   version 9.0 → 6.0). The Click BIOS board photo is the A78M-E35 V2 one from V6.5.
2. **CPU temperature fix** — on V8.5 the Setup / hardware-monitor page showed **128 °C** for the CPU,
   because the new AGESA no longer feeds the Super I/O's CPU temperature input. The hardware-monitor
   driver now reads the CPU's own sensor, the same method Linux `k10temp` uses (D18F3xA4 on Kaveri/Godavari,
   SMU register 0xD8200CA4 on Carrizo). Only the "CPU temperature" reading is changed; fan control and
   every other sensor use the original code unchanged.
3. **Version** — shown as **V6.6** (`E7721AMS.660`), the next number after the last official A78M-E35 V2
   release.
4. **DMI is blank** — like any stock MSI image, it contains no serial number / UUID. See
   [Keep your board's own DMI](#keep-your-boards-own-dmi-recommended).

Everything else is MSI's V8.5 code, byte for byte. Each changed module was decompressed, edited,
recompressed and checked against the original plus only the intended edits (scripts in
[`build-scripts/`](build-scripts)).

### Differences from the official V6.5

- **Gained:** Carrizo APU support (A8-7680, A6-7480, …), newer AGESA 1.3.0.1X and microcode.
- **Same:** SATA ports 1–6, front and rear USB 3.0, VGA / DVI / HDMI outputs, fan control, memory
  options were all compared and are unchanged.
- **Lost:** the parallel port (LPT) setting is not in the A68HM-E33 V2 BIOS.
- **Settings reset:** NVRAM is MSI's default, so all BIOS settings go back to defaults after flashing.

## Installation

### 0. Back up your current BIOS (do not skip)

With a CH341A: read the chip **twice** and make sure the two files are identical, e.g.

```powershell
(Get-FileHash read1.bin).Hash -eq (Get-FileHash read2.bin).Hash
```

Or from Windows with AMI's tool (read only): `afuwinx64 backup.bin /O`

Keep this backup somewhere safe — it is your way back to V6.5, and it contains your board's DMI.

### 1. Verify the download

```powershell
(Get-FileHash E7721AMS.660 -Algorithm SHA256).Hash
```
Must be `2C057042488261E79C379B27B8833EED23B31BB47A463E81624E4A85B11A51D3`.

### 2. Keep your board's own DMI (recommended)

The release image has blank DMI (no serial / UUID). The board works without it, but Windows activation
and some software use the SMBIOS UUID. To keep yours, put your backup into the image
(needs [Python 3](https://www.python.org/), no extra packages):

```powershell
python tools\add_my_dmi.py E7721AMS.660 backup.bin E7721AMS_660_mydmi.bin
```

It copies only the two DMI data files from your backup, checks everything, and refuses to write on any
problem. Flash the `_mydmi.bin` file instead.

The tested board ran exactly this combination (release image + that board's own DMI). The release file
differs from it only in those two DMI data files, which are blank as in MSI's own V8.5 download.

### 3. Flash with a CH341A programmer (tested method)

1. Power off and unplug the PC. Remove the CMOS battery for a minute (or clear CMOS).
2. Clip the CH341A onto the 8 MB SPI chip (25-series, 3.3 V — check the clip's voltage).
3. Erase, write `E7721AMS.660` (or your `_mydmi.bin`), then **verify**.
4. Remove the clip, reconnect, power on. The first boot may restart once or twice while it trains memory.
5. Enter Setup (Del), load optimized defaults (F6), set your options, save (F10).

**Other methods:** MSI M-Flash and AMI AFU flashing of this image are **untested**. M-Flash may reject it
because it is the A68HM-E33 V2 BIOS family; forcing a flash with AFU is at your own risk. A CH341A is the
safe way, and also your recovery tool.

### Recovery

If the board does not POST, flash your backup (or the official V6.5) back with the CH341A.

## Checking it worked

- Setup shows **A78M-E35 V2** and **BIOS version V6.6**.
- Your Carrizo APU is detected with its correct name.
- CPU temperature on the hardware-monitor page is realistic (about 30–45 °C at idle), not 128 °C.

## Repository contents

| Path | What |
|---|---|
| Release asset `E7721AMS.660` | The BIOS image (download from [Releases](../../releases)) |
| [`tools/add_my_dmi.py`](tools/add_my_dmi.py) | Copies your board's DMI from your backup into the image |
| [`build-scripts/`](build-scripts) | The scripts that produced the image from MSI's V8.5, with their verifiers |

### Build steps (for the curious)

Starting from MSI `E7721AMS.850` (A68HM-E33 V2 V8.5) and an A78M-E35 V2 V6.5 image, run in order:
`crossflash.py` (DMI carry-over) → `rename.py` → `photo.py` → `hwm_patch.py` (needs `keystone-engine`
and `capstone`) → `version.py`. Each step has a matching `verify*.py` that checks the output differs from
its input only by the intended edits. `tianocomp.py` / `efidecomp.py` are the EFI (Tiano) compressor and
decompressor used for the modules; `fvlib.py` / `build.py` parse firmware volumes, fix FFS checksums and
rebase execute-in-place modules after a volume is re-laid.

## Disclaimer

The BIOS code is MSI's / AMI's / AMD's. This is an unofficial community modification with no warranty.
MSI, AMD and AMI are trademarks of their owners. This project is not affiliated with or endorsed by them.
