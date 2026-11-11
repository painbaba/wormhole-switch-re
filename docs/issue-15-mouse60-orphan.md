# Issue #15 — bus3 orphan `x=+60`: findings

**Verdict: peer-side injection (cable forwarding) is the
best-supported explanation for `bus3_live2` frame 849, but it is
inferred, not observed.** No peer capture or record of the typed
commands exists for that run. Interference from other devices on the
local bus is ruled out, and a stale report is not supported.

The mechanism is established by the two-end `live3` + `bus1_live`
run: a report the local host receives is the cable's forwarding of
the peer host's `SendMouseEvent` `0xD9` CDB, delivered as an EP3
interrupt-IN report. The *received* direction never has a matching
local CDB, so on a single-end capture a forwarded report looks
senderless.

Scope note: `bus3_live2` itself (6202 raw packets, SHA-256
`285d8271…`, EP3 `x=+60` at raw frame 849) is **unpublished**, because
it holds other devices' traffic. It is analysed directly in the next
section. `captures/wormhole_bus3_live3_2026-11-06.pcap`
+ `captures/wormhole_bus1_live_2026-11-06.pcap` are the simultaneously
captured two-end run written up in `docs/live-capture-2026-11-06.md`
and exhibit the identical phenomenon with the peer side captured —
the sender is established there. `captures/wormhole_bus3_rerun_2026-11-06.pcap`
(parsed first, as tasked; ~2.9 h later) contains **no** `+60`
anywhere: 0 vendor-HID CDBs, 12 HID reports with mouse
`x ∈ {+1, −1, 0}` only. It is a synthetic control (see
`tools/peer_rerun_send.py`), not the source of the orphan.

## `bus3_live2` frame 849: raw capture analysis

Times are offsets from the capture's first packet.

| Check | Result |
|---|---|
| Frame 849 | Interrupt IN completion, device 3:15 endpoint `0x83`, status 0, 4 bytes `00 3c 00 00` (no buttons, `x=+60`, `y=0`, wheel 0), at t=13.676 s |
| EP3 URB | No submit before frame 849. Frame 850 resubmits the same URB 19 µs later, so the URB was armed before the capture started. EP4 has no traffic |
| Host→Wormhole commands | 70 CBWs: 35 `0x4A`, 35 REQUEST SENSE. Tags run `0x2c4` to `0x309` with no gap |
| `0xD9` on any device | None. The only other SCSI device, the IronKey at 3:14, carries only TEST UNIT READY, REQUEST SENSE and `0x4A` |
| Other traffic to the Wormhole | Three `GET_DESCRIPTOR` control reads in the first 4 ms. No other control transfers to the Wormhole or either hub, so no bus reset or reconfiguration request |
| Timing | 593 ms after the previous poll and 1.43 s before the next. Poll spacing stays 2.012 to 2.020 s for the whole run |
| Neighbouring packets | None on any device for 154 ms before or 46 ms after frame 849, apart from its own resubmit |

The tag check is what rules out a `0xD9` CDB that the capture missed:
in live3 the 9 local `0xD9` CDBs take consecutive tags in the same
sequence as the polls, so a missed CBW would show as a gap. The
capture file does not record tcpdump's drop count.

| Hypothesis | Conclusion | Strength |
|---|---|---|
| Peer-side `0xD9` send | Best-supported explanation | Strong inference, not observed |
| Cross-device interference | Ruled out on the local bus | Direct from this capture |
| Stale state | Not supported | Strong for the host side and a queued report, untestable for firmware that withholds a report |

**Peer-side injection.** What supports it:

- All 22 Wormhole reports in the five published 2026-11-06 captures
  have a known send behind them. In the two-end run, the 9 peer-side reports follow
  their local CBWs by 1.2 to 2.0 ms with matching payloads, and the
  1 local report is within 0.6 ms of the peer's accepted CBW. These
  are cross-host clocks, so read them only as "about the same moment".
  The re-run's 12 reports match `tools/peer_rerun_send.py`'s send
  order and spacing, but its peer send log is not in this repository.
- Mouse and keyboard sends don't echo to the sender: none of the 11
  local sends of those types (9 in live3, 1 in the synthetic run, 1 in
  `captures/wormhole_bus3_live_2026-11-08.pcap`) and none of the 8 peer
  sends produced a matching report on the sending side. So even a local
  send that escaped the capture would not explain frame 849.
- Frame 849 is byte-identical to live3's report from the peer's `+60`
  send. Seen from the local side, live3's peer sequence is 7 short
  frames rejected silently and one `+60` delivered. If the same
  sequence ran at 15:35, this is the expected result.

What limits it:

- The published peer capture starts 19 min 42 s after this run ends.
- A rejected peer send leaves no local trace, so the local capture
  can't show whether the peer was active at all.
- The typed commands weren't recorded, and the `+60` match is a
  single byte.
- The absence of unexplained reports on 2026-11-06 is weak on its
  own. About 220 s of capture that day plus `bus3_live`'s 48.5 s with
  zero reports (taken from the Files table in
  `docs/live-capture-2026-11-06.md`) gives a 95% upper bound near one
  spontaneous report per 90 s, which doesn't exclude one in a 70 s run.
- A later capture does hold a report with no known send behind it.
  `captures/wormhole_bus3_live_2026-11-08.pcap` has one EP3 report,
  `00000000`, between a local `'6'` probe's CBW and CSW. Its peer side
  wasn't captured, so its origin is unknown
  (`docs/protocol-mouse-upipe.md` §2.1.1). An idle report carries no
  movement, so it doesn't explain `x=+60`, but "every report has a
  known send" holds only for the 2026-11-06 captures.
- Even granting a peer send, no capture settles which actor issued it:
  an operator running `sg_raw`, or GoBridge forwarding real input.

**Cross-device interference.** Ruled out on the local bus. "EP3" alone
doesn't identify the Wormhole, because the Logitech receivers at 3:5
and 3:7 also declare interrupt endpoint `0x83`, so the attribution
rests on the device number usbmon stamps on each record. Frame 849 is
recorded against 3:15 and is the only completion with data on `0x83`
in this run. The Logitech receiver at 3:7 reports on its own endpoints
(`0x81` and `0x82`) with different lengths, 155 ms before and 145 ms
after frame 849. Devices on the peer host are not visible here. The
only host→cable HID path identified is `0xD9`, so any such device
would have to go through a program issuing those frames, which is the
first hypothesis.

**Stale state.** Not supported, by case:

- Host side: the completion carries status 0 and 4 data bytes from the
  device, so it isn't a buffer left over on the host.
- A report queued in the cable before the capture: the URB was armed
  throughout and the endpoint is polled every 125 µs (`bInterval 1`,
  high speed), so a waiting report would have been collected long
  before t=13.7 s.
- An earlier send held over: the only recorded `+60` send is live3's,
  20 minutes after this run. Adding the local→peer and peer→local
  report-minus-CBW times cancels the clock offset: across live3's 5
  mouse frames the two one-way delays sum to 0.67–0.75 ms. The
  peer→local direction is a single sample.
- Not testable: firmware that withholds a report and releases it later
  can't be excluded from USB traces. On what is known about the cable,
  it would still need a peer-side send as the report's origin, so it
  would change when the peer sent, not who did.

**What further work could settle.** A new run can't identify who sent
this historical frame. A long no-send soak captured at both ends
(`docs/reproduction.md` §6, `sudo` on the peer) would test something
the existing captures don't: whether reports ever appear without a
send. Direct evidence of this frame's sender could only come from the
peer's shell history or terminal log from about 15:35 that day, if any
survives.

To repeat the main checks against the raw file:

```sh
RAW=wormhole_bus3_live2_2026-11-06.pcap
python3 tools/wormhole_parse.py "$RAW" --hid | grep -E 'Vendor HID|f849'
tshark -r "$RAW" -Y 'usb.device_address==15 && usb.transfer_type==1' \
  -T fields -e frame.number -e usb.urb_type -e usb.endpoint_address
python3 tools/wormhole_parse.py "$RAW" --json | python3 -c 'import json,sys; t=[int(x["tag"],16) for x in json.load(sys.stdin)["transactions"]]; print(hex(t[0]),hex(t[-1]),t==list(range(t[0],t[-1]+1)))'
```

The last command filters its output deliberately. Raw `--json` output
includes every device's HID reports, even with `--device`, so don't
publish it.

To re-derive the delay sum from the published captures:

```sh
python3 - <<'PY'
import sys; sys.path.insert(0, "tools")
import wormhole_parse as wp
local = wp.read_pcap("captures/wormhole_bus3_live3_2026-11-06.pcap").packets
peer = wp.read_pcap("captures/wormhole_bus1_live_2026-11-06.pcap").packets
d9 = lambda pkts: [t for t in wp.parse_transactions(pkts) if t.is_vendor_hid]
out = [r["ts"] - t.cbw.ts for t, r in zip(d9(local), wp.parse_hid_reports(peer)) if r["ep_num"] == 3]
sent = next(t for t in d9(peer) if len(t.cbw.cdb) == 16)
back = wp.parse_hid_reports(local)[0]["ts"] - sent.cbw.ts
print("%.2f-%.2f ms over %d mouse frames" % ((min(out) + back) * 1e3, (max(out) + back) * 1e3, len(out)))
PY
```

## The matching `+60` report in `live3` (parser-true, raw bytes verified)

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
timestamps can be compared (fit: `+1.2–2.0 ms` local-CDB→peer-EP
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
click, `'a'`, `'c'`) 1.2–2.0 ms later.

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

## Hypotheses for the `live3` report

| # | Hypothesis | Verdict | Evidence |
|---|---|---|---|
| 1 | **Peer-side injection (cable forwarding)** | **Confirmed** | Bus1 f131 CDB `d933003c…4f54` (16 B, `CSW=good`) at the same instant as bus3 f131 EP3 `003c0000`; identical initial 4 payload bytes (boot-mouse layout); repro in rerun: 12/12 complete frames accepted + forwarded 1:1 in order. |
| 2 | Replay/rerun artifact | Rejected | Rerun (2.9 h later) has no `+60`, no vendor HID at all, only `±1/0` reports on a 2 s / 0.25 s schedule — a control, not a replay of live3 (live3's sends were 10/20/30/40/50/60, not ±1). |
| 3 | Boundary-detection edge-switch | Rejected | Sequence is monotonic `10,20,30` (local→peer) then `40,50,60` (peer→local): an accelerating rightward flick totalling +210 px. No clamp plateau at ±127, no negative wrap, no zero-stall — none of the `BoundaryDetectionInVirtualFrame`/`InMainFrame` signatures (`docs/protocol-mouse-upipe.md` §1.4). Also, boundary logic lives in the GoBridge host path (local `SendMouseEvent`); this event arrived via the cable-forwarded EP3 path and matches the peer CDB byte-for-byte. |
| 4 | Parser misattribution | Rejected | Raw record checked: SUBMIT/COMPLETE, interrupt, EP 0x83 (If 1 boot mouse per enumeration), IN, 4 bytes `00 3c 00 00`, status 0. Same 4-byte semantics as CDB payload bytes 0–3 (`protocol-mouse-upipe.md` §1.3). Cross-checked against the paired CDB bytes. |

## Caveats

- `bus3_live2` (the issue's file) is unpublished and has no peer
  capture, so for *that* run the sender is inferred from the mechanism
  shown here, not observed.
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
>   machines' clocks agree to ~1 ms — cf. 1.2–2.0 ms CDB→EP latency
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
