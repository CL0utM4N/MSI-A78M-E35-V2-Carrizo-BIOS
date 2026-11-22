## MSI A78M-E35 V2 (MS-7721) unofficial BIOS V6.6 — AMD Carrizo support

**Unofficial, at your own risk. Flash with a CH341A and keep a backup of your own chip.**

### What's new vs. the official V6.5
- Support for AMD **Carrizo** FM2+ APUs (tested: **A8-7680**), from MSI's A68HM-E33 V2 V8.5 BIOS
  (same MS-7721 BIOS project).
- AGESA CarrizoFM2r2PI **1.3.0.1X** (was 1.2.0.4X).
- Board shown as **A78M-E35 V2** in Setup and SMBIOS, with the A78M-E35 V2 Click BIOS photo.
- Fixed CPU temperature reading **128 °C** in Setup: now read from the CPU's own sensor
  (k10temp method), on Kaveri, Godavari and Carrizo.
- Version **V6.6** (`E7721AMS.660`).

### Known differences
- The parallel port (LPT) setting is not available.
- BIOS settings reset to defaults. DMI (serial / UUID) is blank — use `tools/add_my_dmi.py` with
  your backup to keep your board's own.
- M-Flash / AFU flashing untested; a CH341A programmer is the tested method.

### Tested on
A78M-E35 V2 with A6-7400K and A8-7680: POSTs, boots, correct CPU temperature, model and version.

### File
`E7721AMS.660`, 8,388,608 bytes
SHA-256 `2c057042488261e79c379b27b8833eed23b31bb47a463e81624e4a85b11a51d3`

See the README for full installation steps.
