# Roadmap

Milestones track the reverse-engineering progression from initial enumeration to a complete, documented protocol spec with working reference tools. Versioning is semantic-ish: **v0.x = research milestones**, **v1.0 = stable reference release**.

---

## ✅ v0.1 — Device enumeration & USB topology (Done)

- [x] `lsusb -v -d 0711:2211` — VID/PID, device class, configurations
- [x] Interface map: 3 interfaces (Mass Storage Bulk-Only, HID Boot Mouse, HID Boot Keyboard)
- [x] Endpoint map: EP1 IN / EP2 OUT (bulk 512 B), EP3 IN (int 8 B, 1 ms), EP4 IN (int 8 B, 4 ms)
- [x] Sysfs paths for block device (`/dev/srX`), SCSI generic (`/dev/sgX`), hidraw (`/dev/hidraw*`), input (`/dev/input/event*`)
- [x] Malformed `bmAttributes 0x60` (missing bit 7) documented

**Deliverables:** `docs/transport.md` §Device identity, §Interfaces

---

## ✅ v0.2 — SCSI / Mass Storage layer (Done)

- [x] INQUIRY → PDT=5 (cd/dvd), vendor `j5create`, product `WormholeSwitch`, rev `2.00`, version `0x00`
- [x] Supported opcodes: TEST UNIT READY, INQUIRY, REQUEST SENSE, READ CAPACITY(10), READ(10)
- [x] Rejected: LOG SENSE (0x4A), READ CAPACITY(16) (0x9E) → CHECK CONDITION / INVALID OPCODE
- [x] Capacity anomaly: device reports 3.1 MiB (1593 × 2048), kernel exposes 15.5 MiB (31744 × 512), ISO9660 mounts at 15.5 MiB
- [x] `sg_vpd` fails — no VPD pages

**Deliverables:** `docs/transport.md` §SCSI, `docs/capture-log.md` (CBW/CSW breakdown), `docs/reproduction.md` §2

---

## ✅ v0.3 — ISO payload & host software inventory (Done)

- [x] ISO9660 volume `WORMHOLE` (15.5 MiB) — full file listing with hashes
- [x] Windows: `autorun.inf` → `SKLoader.exe` (MFC, signed by Magic Control Technology), embedded UPX DLL resource, `Deployment/GSDD.lst` + `GSDD.zz` (unknown container)
- [x] macOS: `Wormhole.app` → `WormholeShell` (Mach-O universal) → extracts `Wormhole.tgz` → `GoBridgeDemon` + `KMKeyMouse` / `KMClipboard` / `OTiTransfer` / `FileChgEvent`
- [x] Manifest: KaiJet `Wormhole1107`, loader `1.0.1325.32`, ISO `1.0.1107.56`

**Deliverables:** `docs/iso-payload.md`, `docs/pe-analysis.md` (SKLoader + embedded DLL), `docs/mac-gobridge.md` (GoBridgeDemon function-level)

---

## 🔄 v0.4 — UPipe protocol (file / clipboard channel) — **CURRENT**

The HID injection path (`0xD9` CDB, types `'3'`/`'4'`/`'6'`) is decoded and verified end-to-end (`docs/transport.md`, `docs/live-capture-2026-11-06.md`). The **file/clipboard channel** uses the same SCSI Bulk-Only pipe with a different vendor CDB magic (not yet captured).

- [ ] Capture live peer-active session with file drag / clipboard copy (both ends running GoBridge/Wormhole)
- [ ] Identify UPipe CDB magic byte(s) — parser already flags `candidate_upipe` for any vendor-range CDB (`0xC0`–`0xFF`) with a data phase
- [ ] Decode UPipe framing: chunking, sequence, CRC, file metadata, clipboard MIME types
- [ ] Verify bidirectional symmetry (PC A → PC B vs PC B → PC A)
- [ ] Document in `docs/transport.md` (new section) + new `docs/upipe-protocol.md`

**Blocker:** Requires two machines with GoBridge running simultaneously and a filtered usbmon capture. Parser is ready (`tools/wormhole_parse.py` decodes `0xD9` HID + flags UPipe candidates).

---

## ⏳ v0.5 — Windows host software parity (Parallel)

macOS GoBridgeDemon is analysed to function level (`docs/mac-gobridge.md`). Windows path (`SKLoader.exe` → embedded DLL → `OTiTransfer`) is only mapped at import/resource level (`docs/pe-analysis.md`).

- [ ] Deep decompile embedded DLL (UPX unpacked, 1,849 functions) — trace `OTi_*` exports to SCSI/HID calls
- [ ] Map Windows HID injection: `SendInput` / `HID` API usage vs macOS `CGEvent` path
- [ ] Map Windows file/clipboard: `OTiTransfer` → `DeviceIoControl` / `IOCTL_SCSI_PASS_THROUGH` vs macOS `SCSITask`
- [ ] Document Windows-specific behaviours (driver signing, AutoRun deprecation, installer footprint)
- [ ] Cross-reference macOS/Windows packet formats for parity (same `0xD9` HID? same UPipe?)

**Deliverable:** `docs/windows-gobridge.md` (parallel to `mac-gobridge.md`)

---

## ⏳ v0.6 — Firmware mysteries (Internal cable logic)

Everything so far is **host-side observation**. The microcontroller inside the cable is a black box.

- [ ] Peer-to-peer data channel: how the cable forwards `0xD9` HID and UPipe packets between ends (not visible from one host)
- [ ] Capacity anomaly root cause: why `READ CAPACITY(10)` (3.1 MiB) ≠ kernel block device (15.5 MiB) — needs pre-enumeration kernel log or firmware dump
- [ ] `GSDD.zz` / `GSDD.lst` container format — encryption/compression, role in SKLoader deployment
- [ ] Multimedia HID type `'6'` wire payload layout (12 bytes) — not captured, decompiler only shows call signature
- [ ] Whether cable forwards type `'6'` at all, and which peer endpoint it synthesises (neither HID report descriptor declares Consumer page `05 0C`)
- [ ] Firmware extraction / analysis (if feasible — JTAG/SWD, DFU, or vendor update mechanism)

**Approach:** Two-end simultaneous capture (usbmon on both hosts) + host-software logging correlation. Firmware dump is stretch goal.

---

## 🎯 v1.0 — Stable reference release

- [ ] Complete protocol specification: USB/SCSI/HID/UPipe in one document (`docs/protocol-spec.md`)
- [ ] Parser (`tools/wormhole_parse.py`) covers all observed packet types with 100% test coverage
- [ ] Reproduction guide (`docs/reproduction.md`) validated on clean Linux/macOS/Windows hosts
- [ ] All captures in `captures/` are filtered, documented, and parseable by the reference parser
- [ ] Cross-platform host-software analysis parity (macOS + Windows)
- [ ] `README.md`, `CONTRIBUTING.md`, `ROADMAP.md`, `LICENSE` complete
- [ ] Architecture diagram (`architecture.html`) in repo root
- [ ] Tag `v1.0` — reference frozen for downstream implementers (emulators, KVM switches, protocol translators)

---

## Milestone status summary

| Version | Theme | Status | Target |
|---------|-------|--------|--------|
| v0.1 | Enumeration & topology | ✅ Done | — |
| v0.2 | SCSI / Mass Storage | ✅ Done | — |
| v0.3 | ISO payload & host inventory | ✅ Done | — |
| v0.4 | **UPipe protocol** | 🔄 **In progress** | Next capture |
| v0.5 | Windows host parity | ⏳ Parallel | After v0.4 |
| v0.6 | Firmware internals | ⏳ Research | Long-term |
| v1.0 | Stable reference release | 📋 Planned | When v0.4–0.6 converge |

---

## How to move v0.4 forward

1. Set up two machines (Linux + macOS, or Linux + Windows) with the Wormhole cable between them.
2. Run GoBridge / Wormhole software on both ends.
3. On the capture host: `sudo tcpdump -i usbmonN -w raw.pcap` (start **before** switching).
4. Drive a session: mouse moves, clicks, keystrokes, **file drag**, **clipboard copy/paste**.
5. Stop, filter (`tools/filter_usbmon.py`), parse (`tools/wormhole_parse.py --json`), inspect `candidate_upipe` entries.
6. Correlate with host-software logs (macOS `GoBridgeDemon` logs `key HID:`; Windows DLL exports may log similarly).
7. Document the UPipe CDB magic and framing.

Once UPipe is decoded, v0.4 closes and v0.5/v0.6 can proceed in parallel.