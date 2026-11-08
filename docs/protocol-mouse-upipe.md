# Wormhole Switch: Mouse Relative-Move Encoding & UPipe Framing

Synthesized from `docs/mac-gobridge.md` (GoBridgeDemon + OTiTransfer function-level analysis) and `tools/wormhole_parse.py` (vendor HID CDB decoder). All offsets and byte layouts are **host→cable direction** unless noted.

---

## 1. Mouse Relative-Move: `SendMouseEvent` → 0xD9 CDB (type `'3'`)

### 1.1 Call chain (macOS side)

```
CKMEvent::SendMouseEvent (0x3cd8, KMKeyMouse.dylib)
    → boundary detection: BoundaryDetectionInVirtualFrame / BoundaryDetectionInMainFrame
    → speed scaling via MouseInterface
    → [KMMainLoop sendMouseData:packet]
    → delegate: THMFileManager.postMouseHIDEventToRemote:
    → OTi_SendHIDPacket(type=1, packet)   // type 1 = mouse
    → OTiTransporter::sendHIDPacket(type, data)   // builds 16-byte CDB
    → SendSCSICommandSendData(CDB=packet, CDB_len=0x10, data=NULL)
```

### 1.2 16-byte CDB wire format (host → cable)

| Offset | Size | Value | Meaning |
|--------|------|-------|---------|
| 0      | 1    | `0xD9` | Vendor HID magic (SCSI opcode) |
| 1      | 1    | `'3'` (0x33) | Type: **mouse** (type 1 in ObjC → char `'3'`) |
| 2–13   | 12   | **HID payload** | 12 bytes: mouse report + padding |
| 14–15  | 2    | `'O' 'T'` (0x4F 0x54) | OTiTransfer footer |

The 14-byte `CFData` passed to `OTi_SendHIDPacket` is exactly bytes 0–13 above; `sendHIDPacket` appends the `'OT'` footer to make the 16-byte CDB.

### 1.3 12-byte HID payload layout (bytes 2–13)

From `OTiTransporter::sendHIDPacket` pseudocode and the parser's `decode_vendor_hid_cdb`:

```
Byte 2  : Button state (bit 0 = left, bit 1 = right, bit 2 = middle)
Byte 3  : Relative X  (signed int8, −128..+127)
Byte 4  : Relative Y  (signed int8, −128..+127)
Byte 5  : Wheel delta (signed int8, −128..+127)
Bytes 6–13 : Zero padding (always 0x00 in observed captures)
```

**This matches the boot-mouse interrupt report format** (EP3 IN, 4 bytes) decoded by `decode_hid_mouse_report` in `wormhole_parse.py` — the host→cable CDB payload *is* the same 4-byte report, zero-padded to 12 bytes.

### 1.4 Relative-move encoding rules (from `SendMouseEvent`)

- **Coordinates are relative deltas**, not absolute. `SendMouseEvent` accumulates deltas from the CGEvent tap (`kCGHIDEventTap`).
- **Boundary detection** (`BoundaryDetectionInVirtualFrame` / `BoundaryDetectionInMainFrame`) clamps or wraps when the virtual cursor hits the remote screen edge — this is how "seamless" cross-screen motion works.
- **Speed scaling** via `MouseInterface` applies a multiplier (configurable per-session) before the int8 clamp.
- **Clamping**: each axis is clamped to `int8_t` range (−128..+127). Large physical moves are split into multiple CDBs (observed burst of 0xD9 packets per drag).
- **Button state** is the *current* button mask at the time of the move event (down/drag/up all generate a CDB with the corresponding bit set).

### 1.5 Example CDB (mouse move right 10, down 5, left button held)

```
D9 33 01 0A FB 00 00 00 00 00 00 00 00 00 4F 54
│  │  │  │  │  └─ wheel = 0
│  │  │  │  └───── Y = −5 (0xFB = −5 signed)
│  │  │  └──────── X = +10 (0x0A)
│  │  └─────────── buttons = 0x01 (left down)
│  └────────────── type = '3' (mouse)
└───────────────── magic = 0xD9
```

---

## 2. Keyboard & Multimedia Types (for completeness)

| Type char | ObjC type | HID payload (bytes 2–13) | Parser constant |
|-----------|-----------|--------------------------|-----------------|
| `'3'` (0x33) | 1 (mouse) | 4-byte boot report + 8×0x00 | `VENDOR_HID_TYPES[0x33] = "mouse"` |
| `'4'` (0x34) | 2 (keyboard) | 8-byte boot report (mods + 6 keycodes) + 4×0x00 | `VENDOR_HID_TYPES[0x34] = "keyboard"` |
| `'6'` (0x36) | 3 (multimedia) | Usage ID at byte 2, rest 0 | `VENDOR_HID_TYPES[0x36] = "multimedia"` |

Keyboard payload matches the boot-keyboard interrupt report (EP4 IN, 8 bytes) decoded by `decode_hid_keyboard_report`.

---

## 3. UPipe / File-Transfer Framing: `GetData` / `PutData` Queues

### 3.1 What we know from static analysis

`OTiTransporter` (C++, ~70 methods) exposes:

- `GetData` / `PutData` — queue operations for bulk endpoints
- `RunLoopFunction` / `ReceiveData` / `SendData` — async I/O loop
- `processReceiveState` / `processTransferState` — state machines
- `rxQueues`, `txQueue` counters in `THMFileManager` (GoBridgeDemon)

The **same SCSI plumbing** (`SendSCSICommandSendData` / `SendSCSICommandReceiveData`) is used for file/clipboard transfer — the difference is:
- HID packets: **no data phase** (`CFData* data = NULL` in `SendSCSICommandSendData`)
- File/clipboard: **has a data phase** (CBW `data_len > 0`, bulk data follows)

### 3.2 Vendor CDB range flagged as UPipe candidates

`wormhole_parse.py` defines:

```python
VENDOR_RANGE = (0xC0, 0xFF)        # SPC vendor-specific opcodes
VENDOR_HID_MAGIC = 0xD9            # Only 0xD9 is fully decoded
```

Any CDB with opcode `0xC0–0xFF` **except 0xD9** is reported as:

```json
{
  "is_vendor": true,
  "is_vendor_hid": false,
  "name": "VENDOR CDB 0xNN (possible UPipe)",
  "candidate_upipe": true,
  "cdb_hex": "...",
  "cbw_data_len": <expected data phase length>
}
```

### 3.3 Observed UPipe candidate structure (from live captures needed)

| Field | Status |
|-------|--------|
| CDB opcode | Unknown (0xC0–0xFF, ≠0xD9) |
| CDB length | Likely 16 bytes (same SCSI transport) |
| Magic bytes | Unknown — **needs live peer-active capture** |
| Data phase | Present (CBW `data_len` > 0, bulk IN/OUT follows) |
| Direction | Both: host→cable (PutData/upload) and cable→host (GetData/download) |
| Queueing | `THMFileManager` maintains `rxQueues` / `txQueue` per session ID |

### 3.4 Clipboard rides UPipe, not HID

From `docs/mac-gobridge.md` (KMClipboard.dylib):

> Clipboard payloads ride **UPipe messages** (`marshallFromUPipeMsg`), i.e. the same peer channel as file commands — not HID packets.

So the UPipe channel multiplexes:
- File transfer (upload/download, directory ops)
- Clipboard sync
- Possibly hotkey/switch commands (`_NotifyUPipeMesssageUpToAppThread:`)

---

## 4. Cross-Reference: `tools/wormhole_parse.py` Decoder

### 4.1 Key constants (lines 145–158)

```python
VENDOR_HID_MAGIC = 0xD9
VENDOR_HID_TYPES = {
    0x33: "mouse",      # '3'
    0x34: "keyboard",   # '4'
    0x36: "multimedia", # '6'
}
VENDOR_HID_FOOTER = b"OT"
VENDOR_HID_LEN = 16
VENDOR_RANGE = (0xC0, 0xFF)
```

### 4.2 `decode_vendor_cdb(cdb)` (lines 487–546)

Returns a dict with:

| Key | Meaning |
|-----|---------|
| `is_vendor` | True for any opcode in `0xC0–0xFF` |
| `is_vendor_hid` | True only for `0xD9` |
| `hid_type` | `"mouse" \| "keyboard" \| "multimedia" \| "unknown"` |
| `payload_hex` | Bytes 2–13 (12 bytes) as hex |
| `payload` | List of 12 ints |
| `footer_ok` | True if bytes 14–15 == `b"OT"` |
| `valid_hid_framing` | All three checks pass (len==16, type known, footer OK) |
| `candidate_upipe` | True for vendor opcodes ≠ 0xD9 |

### 4.3 `build_vendor_hid_cdb(hid_type, payload)` (lines 549–558)

Test helper — builds a valid 16-byte CDB for `sg_raw` injection:

```python
build_vendor_hid_cdb("3", b"\x01\x0a\xfb\x00")  # mouse move example
# → b'\xd9\x33\x01\x0a\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4f\x54'
```

### 4.4 `decode_hid_mouse_report(payload)` (lines 604–623)

Decodes the **interrupt IN report** (EP3, 4 bytes) — same 4-byte layout as CDB payload bytes 2–5:

```python
{
  "buttons": 0x01,
  "left": True, "right": False, "middle": False,
  "x": +10, "y": -5, "wheel": 0
}
```

---

## 5. What Still Needs a Live Peer-Active Capture

| Unknown | Where to look |
|---------|---------------|
| UPipe CDB magic bytes (opcode + payload header) | Any vendor CDB ≠ 0xD9 in a file-transfer session |
| UPipe command/response encoding | `GetData`/`PutData` queue payloads (bulk data phase) |
| Clipboard UPipe message format | `marshallFromUPipeMsg` / `unmarshallFromUPipeMsg` in KMClipboard |
| Cable-side routing (microcontroller firmware) | Not in host binaries; needs two-end capture or firmware dump |

The parser already flags every non-0xD9 vendor CDB as `candidate_upipe` with raw hex — run it on a live transfer capture to characterise the magic.

---

## 6. Quick Reference: CDB Byte Map

```
Byte:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
      ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
HID   │D9 │'3'│Btn│ X │ Y │Whl│ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ O │ T │  ← mouse
      │D9 │'4'│Mod│Res│Kc1│Kc2│Kc3│Kc4│Kc5│Kc6│ 0 │ 0 │ 0 │ 0 │ O │ T │  ← keyboard
      │D9 │'6'│Use│ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ O │ T │  ← multimedia
      ├───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
UPipe │NN │?? │                    command-specific payload                    │  ← candidate_upipe
      └───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

- **HID path**: 0xD9 CDB, no bulk data phase, 16 bytes on the wire.
- **UPipe path**: Other vendor opcode, **has bulk data phase** (CBW `data_len` > 0), CDB length likely 16 but payload structure unknown.

---

## 7. Related Files

- `docs/mac-gobridge.md` — Full function-level RE trail (GoBridgeDemon, OTiTransfer, KMKeyMouse)
- `docs/pe-analysis.md` — Windows SKLoader + OTiArchive DLL analysis
- `tools/wormhole_parse.py` — Reference parser (`decode_vendor_cdb`, `build_vendor_hid_cdb`, `decode_hid_mouse_report`)
- `captures/wormhole_bus3_2026-11-06.pcap` — Idle capture (zero vendor HID traffic)
- `docs/reproduction.md` §6 — How to capture a peer-active session