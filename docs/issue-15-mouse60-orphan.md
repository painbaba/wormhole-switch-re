# Issue #15 — bus3 orphan `x=+60`: findings

**Verdict: (1) peer-side injection (cable forwarding).** The `+60`
report is not orphaned once the other end of the cable is looked at:
it is the cable's forwarding of the peer host's `SendMouseEvent`
`0xD9` CDB, delivered to the local host as an EP3 interrupt-IN
report. The local host sent **no** `0xD9` CDB in this run, so on a
single-end capture the report looks senderless — expected, because
the *received* direction never has a matching local CDB.

Scope note: `bus3_live2` itself (6202 raw packets, SHA-256
`285d8271…`, EP3 `x=+60` at raw frame 849) is **unpublished**, so it
is not directly parsed here. `captures/wormhole_bus3_live3_2026-11-06.pcap`
+ `captures/wormhole_bus1_live_2026-11-06.pcap` are the simultaneously
captured two-end run written up in `docs/live-capture-2026-11-06.md`
and exhibit the identical phenomenon with the peer side captured —
the sender is established there. `captures/wormhole_bus3_rerun_2026-11-06.pcap`
(parsed first, as tasked; ~2.9 h later) contains **no** `+60`
anywhere: 0 vendor-HID CDBs, 12 HID reports with mouse
`x ∈ {+1, −1, 0}` only. It is a synthetic control (see
`tools/peer_rerun_send.py`), not the source of the orphan.

## The orphan packet (parser-true, raw bytes verified)

Published file `captures/wormhole_bus3_live3_2026-11-06.pcap`
(frame numbers below are `wormhole_parse.py` numbers on the filtered
464-packet file; the same event is raw frame 617 of the unpublished
unfiltered local capture — see document line 87 of the live-capture
doc):

| Frame | Offset | What | Raw |
|---|---|---|---|
| 125 | 15.119 s | Routine 0x4A/REQUEST SENSE poll pair resumes (CBW submit) | `…030000001200…` |
| 128 | 15.119 s | Sense data, key 5 `ASC 0x20/0x00` (normal poll reject) | `7000050000…` |
| 130 | 15.119 s | CSW good — poll pair ends | — |
| **131** | **15.705 s** | **EP3 mouse IN COMPLETE, `x=+60`** | **`00 3c 00 00`** (buttons=0, X=+60, Y=0, wheel=0), EP 0x83, IN, 4 B, status 0, interval 1 |
| 132 | 15.705 s | EP3 re-submit 15 µs later (no data) | — |
| 133 | 17.131 s | Next 0x4A poll pair (~1.43 s later) | — |

No preceding mouse CDB exists on this bus: the only bus-3 `0xD9`
mouse CDBs in the whole capture are `X=+10` (f43), `X=+20` (f47),
`X=+30` (f63), click-down (f67), `X=0` (f83) — all 16-byte,
`CSW=good`. None carries `0x3c` in payload byte 1. Nothing else
interrupts between f130 and f133.

## Peer side, same wall-clock instant (bus1 capture)

Because both hosts were captured simultaneously, absolute pcap
timestamps can be compared (fit: `+1.2–1.7 ms` local-CDB→peer-EP
latency throughout, no drift — the two clocks agree to a few ms;
clocks were *not* NTP-locked to sub-ms, see caveat).

| Bus1 frame | Local-host time | Peer CDB | CSW / framing | On bus 3 |
|---|---|---|---|---|
| 99 | 15:56:48.2 | mouse `X=+40` `d9330028…4f54` | CHECK COND, **15-byte CDB** | rejected, not forwarded |
| 109 | 15:56:50.5 | mouse `X=+50` `d9330032…4f54` | CHECK COND, **15-byte** | rejected |
| **131** | **15:57:09.341** | **mouse `X=+60` `d933003c0000…4f54`** | **good, 16-byte** | **EP3 IN `003c0000` at 15:57:09.340 (−0.56 ms)** |
| 147 | 15:57:10.7 | click `0100…` | CHECK COND, 15-byte | rejected |
| 157 | 15:57:12.1 | `X=0` | CHECK COND, 15-byte | rejected |
| 179 | 15:57:13.5 | kbd `'b'` `000005…` | CHECK COND, 15-byte | rejected |
| 201 | 15:57:14.9 | kbd release | CHECK COND, 15-byte | rejected |
| 239 | 15:57:18.3 | wheel `00000001…` | CHECK COND, 15-byte | rejected |

Reverse direction in the same run, for symmetry: all 9 bus-3 CDBs
(16-byte, good) appear on bus 1 as 9/9 EP reports (`x=+10/+20/+30`,
click, `'a'`, `'c'`) 1.2–1.7 ms later.

Why **only** the `+60` is forwarded among the 8 peer sends: the
other 7 arrived as 15-byte CDBs (one `00` missing before the `OT`
footer — parser `footer_ok=None, framing=False`), and the device
rejects them with CHECK CONDITION, sense key 9, `ASC=0xFF/0xFF`
(firmware's vendor sense; the parser's "Copy Abort" label is an
alias). The re-run's P4 controls reproduce exactly this: 15-byte →
rejected → nothing forwarded. Short frames never produce a report.
So an orphan-`+60`-with-no-local-CDB is the *only possible*
signature of a lone well-framed peer send in this run — see
`docs/live-capture-2026-11-06.md` "Peer → local: mostly rejected /
truncated".

## Hypotheses

| # | Hypothesis | Verdict | Evidence |
|---|---|---|---|
| 1 | **Peer-side injection (cable forwarding)** | **Confirmed** | Bus1 f131 CDB `d933003c…4f54` (16 B, `CSW=good`) at the same instant as bus3 f131 EP3 `003c0000`; identical initial 4 payload bytes (boot-mouse layout); repro in rerun: 12/12 complete frames accepted + forwarded 1:1 in order. |
| 2 | Replay/rerun artifact | Rejected | Rerun (2.9 h later) has no `+60`, no vendor HID at all, only `±1/0` reports on a 2 s / 0.25 s schedule — a control, not a replay of live3 (live3's sends were 10/20/30/40/50/60, not ±1). |
| 3 | Boundary-detection edge-switch | Rejected | Sequence is monotonic `10,20,30` (local→peer) then `40,50,60` (peer→local): an accelerating rightward flick totalling +210 px. No clamp plateau at ±127, no negative wrap, no zero-stall — none of the `BoundaryDetectionInVirtualFrame`/`InMainFrame` signatures (`docs/protocol-mouse-upipe.md` §1.4). Also, boundary logic lives in the GoBridge host path (local `SendMouseEvent`); this event arrived via the cable-forwarded EP3 path and matches the peer CDB byte-for-byte. |
| 4 | Parser misattribution | Rejected | Raw record checked: SUBMIT/COMPLETE, interrupt, EP 0x83 (If 1 boot mouse per enumeration), IN, 4 bytes `00 3c 00 00`, status 0. Same 4-byte semantics as CDB payload bytes 0–3 (`protocol-mouse-upipe.md` §1.3). Cross-checked against the paired CDB bytes. |

## Caveats

- `bus3_live2` (the issue's file) is unpublished; for *that* run the
  sender remains unproven byte-for-byte — same mechanism inferred.
  If the raw file surfaces, the test is whether a one-end-only EP3
  report has a peer CDB; but no peer capture exists for that run.
- The −0.56 ms "EP-before-CDB-sub" needs no special pleading: the
  two pcap timestamps come from two different machines' kernels
  (offsets differ by 2.2 s of capture start; `usbmon` submit records
  are enqueue-time). Fit across the run is 1–4 ms (rerun note line
  110), so ±1 ms jitter is inside clock agreement.
- `x=+60` (0x3C) is within int8 range, so clamping plays no role.
- Frame 131 (parser, filtered file) == raw frame 617 (unfiltered
  raw local capture) == "frame 849" only for live2. Don't compare
  frame numbers across files.
- Open context unchanged: why the original peer sends went out
  15-byte short (typed commands not recorded).

## Comment-ready summary (paste for #15)

> **Verdict: (1) peer-side injection (cable forwarding).**
>
> Parsed `captures/wormhole_bus3_rerun_2026-11-06.pcap` first: no
> `+60` there (0 vendor-HID CDBs; 12 HID reports, mouse `x ∈
> {+1,−1,0}` — the rerun is a synthetic ±1 control). The instrumented
> equivalent of the unpublished `bus3_live2` is the simultaneous
> two-end run (`bus3_live3` + `bus1_live`):
>
> - Orphan: bus3 f131 (15.705 s offset), EP3 IN COMPLETE `00 3c 00
>   00` (`x=+60`), between a REQUEST SENSE pair (f125–130) and the
>   next 0x4A poll (f133). Bus3's only mouse CDBs are `x=+10/+20/+30/
>   0/0` — none is `0x3c`.
> - Peer side: bus1 f131, bulk-OUT CBW, `d933003c0000…4f54` (16 B,
>   `CSW=good`), abs 15:57:09.341 vs bus3 EP 15:57:09.340 (two
>   machines' clocks agree to ~1 ms — cf. 1.2–1.7 ms CDB→EP latency
>   for all 9 local→peer packets). Same event, other end of cable.
> - Only `+60` is forwarded because the other 7 peer CDBs (`X=+40`,
>   `+50`, click, `'b'`, wheel) arrived 15-byte short and were
>   rejected (CHECK CONDITION, key 9 `FF/FF`) — rerun P4 reproduces
>   the reject. A lone good frame → lone EP3 report with no local
>   CDB is exactly the expected signature.
>
> Hypotheses: (2) rerun artifact — no (rerun has no `+60`, ≠ replay).
> (3) boundary edge-switch — no (monotonic 10→60 flick, no clamp/wrap;
> boundary logic is host-side anyway). (4) parser misattribution —
> no (raw bytes, EP, direction, status all verified).
>
> Caveat: `bus3_live2` is unpublished, so for that file the sender
> stays mechanism-inferred; the paired live3/bus1 run proves the
> mechanism and identifies this `+60`'s sender as the peer host.
