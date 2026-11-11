#!/usr/bin/env python3
"""Capacity anomaly analysis for the WormholeSwitch fake CD-ROM (issue #13).

Why does ``READ CAPACITY(10)`` advertise 1593 x 2048 B (3.1 MiB) while Linux
exposes ``/sys/block/srX/size`` = 31744 x 512 B (15.5 MiB)?

This tool replays the Linux ``drivers/scsi/sr.c`` ``get_sectorsize()`` math
against the evidence recorded in ``docs/capacity-anomaly.md`` (with the
supporting command captures in ``docs/transport.md``,
``docs/capture-log.md`` and ``docs/iso-payload.md``) and shows:

  * the recorded steady-state ``READ CAPACITY(10)`` response on its own
    yields 6372 sectors of 512 B -- not the observed 31744;
  * ``get_sectorsize()`` then applies ``cdrom_get_last_written()``: the
    firmware's TRACK INFORMATION track size and TOC lead-out both report
    7936 blocks, and ``max(1593, 7936) * 4 = 31744`` -- exactly the
    observed sysfs size;
  * the failure path is not a *4 conversion: ``get_sectorsize()`` sets
    ``cd->capacity = 0x1fffff`` with sector size 2048, and does not call
    ``set_capacity()``, so it cannot explain 31744;
  * READ CAPACITY(10) answers whose own value reaches 31744 include the
    sr.c-remapped block lengths 0, 2340 and 2352 as well as 2048 and 512.

Verdict: firmware inconsistency. READ CAPACITY reports 1593 blocks while
TRACK INFORMATION / TOC lead-out claim 7936; Linux ``sr`` uses
``max(READ CAPACITY, last_written)``, so the block device is 15.5 MiB
while the usable ISO9660 volume is 3.1 MiB (see docs/capacity-anomaly.md).

Run from the repo root (stdlib only):

    python3 tools/capacity_anomaly.py            # human-readable analysis
    python3 tools/capacity_anomaly.py --json     # machine-readable
    python3 tools/capacity_anomaly.py --rc10 0000063800000800
                                                 # evaluate any captured
                                                 # READ CAPACITY(10) data
                                                 # phase through the kernel
                                                 # path
"""

from __future__ import annotations

import argparse
import json
import sys

# ---------------------------------------------------------------------------
# Recorded evidence (all values appear verbatim in docs/)
# ---------------------------------------------------------------------------

# Steady-state READ CAPACITY(10) data phase (docs/transport.md,
# docs/capture-log.md: live sg_raw == sg_readcap == capture f1355).
RC10_RESPONSE = bytes.fromhex("0000063800000800")

# /sys/block/srX/size as observed on the capture host (docs/transport.md,
# docs/reproduction.md): 31744 sectors of 512 B = 16,252,928 B = 15.5 MiB.
SYSFS_SIZE_512B = 31744

# WORMHOLE ISO9660 volume / block-device size (docs/iso-payload.md).
ISO_BYTES = 16252928

# READ CAPACITY(16) (0x9E sa 0x10) sense: Illegal Request / Invalid opcode.
RC16_SENSE_KEY = 0x05
RC16_ASC = 0x20

# READ TRACK INFORMATION (0x52) track_size (docs/capacity-anomaly.md).
TRACK_INFO_TRACK_SIZE = 0x1F00  # 7936 blocks

# READ TOC lead-out MSF 01:47:61 (docs/capacity-anomaly.md).
TOC_LEADOUT_MSF = (1, 47, 61)


def msf_to_lba(msf: tuple[int, int, int]) -> int:
    """Convert a CD MSF address to an LBA (150-frame lead-in offset)."""
    minutes, seconds, frames = msf
    return ((minutes * 60) + seconds) * 75 + frames - 150


# cdrom_get_last_written() takes track_start + track_size from TRACK
# INFORMATION; the TOC lead-out agrees: 01:47:61 -> 7936.
LAST_WRITTEN_BLOCKS = 7936

# READ TOC/PMA/ATIP payload -- identical bytes returned for format 0 (LBA)
# and format 2 (MSF), a canned firmware response (capture f1385/f1391).
# This 12-byte allocation holds the track-1 descriptor, not the lead-out.
TOC_FMT0 = bytes.fromhex("001201010014010000000200")
TOC_FMT2 = bytes.fromhex("001201010014010000000200")
TOC_ALLOCATION_LENGTH = 12

# GET CONFIGURATION/Feature List payload, 32-byte allocation (capture f1399).
GET_CONFIG = bytes.fromhex(
    "000000840000000a0000030c0008000000090000000a01000001030400000002")

# drivers/scsi/sr.c get_sectorsize() failure path: READ CAPACITY error ->
# cd->capacity = 0x1fffff, sector_size = 2048; no *4 and no set_capacity()
# in that branch (Linux master, 2026).
SR_FALLBACK_CAPACITY_BLOCKS = 0x1FFFFF

VERDICT = ("firmware inconsistency: READ CAPACITY reports 1593 blocks, "
           "TRACK INFORMATION/TOC lead-out report 7936; Linux sr uses "
           "max(READ CAPACITY, last_written)")


# ---------------------------------------------------------------------------
# READ CAPACITY(10) decode + Linux sr.c replay
# ---------------------------------------------------------------------------

def parse_read_capacity(raw: bytes) -> dict:
    """Decode the 8-byte READ CAPACITY(10) data phase."""
    if len(raw) < 8:
        raise ValueError(
            "READ CAPACITY(10) data phase must be 8 bytes, got %d" % len(raw))
    last_lba = int.from_bytes(raw[0:4], "big")
    block_len = int.from_bytes(raw[4:8], "big")
    return {
        "last_lba": last_lba,
        "block_len": block_len,
        "blocks": last_lba + 1,
        "device_bytes": (last_lba + 1) * block_len,
    }


def sr_capacity_512b(last_lba: int, block_len: int,
                     last_written: int = LAST_WRITTEN_BLOCKS) -> int | None:
    """Replay drivers/scsi/sr.c get_sectorsize() for a successful READ
    CAPACITY(10) and return the gendisk capacity in 512 B units (what
    /sys/block/srX/size shows), or None for an unsupported sector size.

    Kernel logic (Linux master):

        cd->capacity = 1 + get_unaligned_be32(&buffer[0]);
        if (!cdrom_get_last_written(&cd->cdi, &last_written))
            cd->capacity = max(cd->capacity, last_written);
        switch (sector_size) {          # buffer[4..7] big-endian
        case 0: case 2340: case 2352:
            sector_size = 2048;         # fallthrough
        case 2048:
            cd->capacity *= 4;
            fallthrough;
        case 512:
            break;
        default:
            "unsupported sector size"; cd->capacity = 0;
        }
        set_capacity(cd->disk, cd->capacity);

    ``last_written`` defaults to the measured 7936 blocks (TRACK
    INFORMATION track_size / TOC lead-out).  Pass 0 to skip the
    correction and isolate READ CAPACITY's own value.
    """
    capacity = 1 + last_lba
    if last_written:
        capacity = max(capacity, last_written)
    if block_len in (0, 2340, 2352):
        block_len = 2048
    if block_len == 2048:
        capacity *= 4
    elif block_len != 512:
        return None
    return capacity


def sr_fallback_capacity_512b() -> int:
    """Capacity when READ CAPACITY(10) fails outright.

    get_sectorsize() sets ``cd->capacity = 0x1fffff`` and sector_size
    2048 but does not multiply by 4 and does not call ``set_capacity()``
    in that branch, so the effective capacity stays 0x1fffff sectors of
    512 B (the value set at probe time).  It is not 31744.
    """
    return SR_FALLBACK_CAPACITY_BLOCKS


def responses_producing_sysfs_size(
        sysfs_size: int = SYSFS_SIZE_512B) -> list[dict]:
    """READ CAPACITY(10) answers whose own value (before last_written)
    maps to exactly ``sysfs_size`` /sys sectors, with the raw data-phase
    bytes it would appear as on the wire.

    Block lengths 0, 2340 and 2352 are included because sr.c remaps them
    to 2048 before the *4 conversion; ``device_bytes`` therefore uses the
    post-remap block length (2048), not the raw wire value.  This list is
    not exhaustive once ``last_written`` is applied: any 2048-family answer
    with ``last_lba < LAST_WRITTEN_BLOCKS`` is also raised to 31744 by
    the ``max()`` (including the recorded steady-state response).
    """
    candidates = []
    for block_len in (512, 2048, 0, 2340, 2352):
        per_512 = 1 if block_len == 512 else 4
        if sysfs_size % per_512:
            continue
        blocks = sysfs_size // per_512
        last_lba = blocks - 1
        raw = (last_lba.to_bytes(4, "big") + block_len.to_bytes(4, "big"))
        effective = 2048 if block_len in (0, 2340, 2352) else block_len
        candidates.append({
            "last_lba": last_lba,
            "block_len": block_len,
            "blocks": blocks,
            "device_bytes": blocks * effective,
            "raw": raw.hex(),
        })
    return candidates


# ---------------------------------------------------------------------------
# Supporting canned-response decodes (quirk evidence)
# ---------------------------------------------------------------------------

def decode_toc(raw: bytes = TOC_FMT0) -> dict:
    """Decode the truncated 12-byte READ TOC/PMA/ATIP response.

    Header: TOC data length (2 B), first track, last track; then the first
    8-byte track descriptor (session, ADR/control, track, reserved,
    4-byte start address).  This allocation does not contain the
    lead-out; that was measured separately (TOC_LEADOUT_MSF).
    """
    desc = raw[4:12]
    return {
        "toc_length": int.from_bytes(raw[0:2], "big"),
        "first_track": raw[2],
        "last_track": raw[3],
        "track_desc": {
            "session": desc[0],
            "adr_control": desc[1],
            "track": desc[2],
            "start_lba": int.from_bytes(desc[4:8], "big"),
        },
    }


def decode_get_configuration(raw: bytes = GET_CONFIG) -> dict:
    """Decode the truncated GET CONFIGURATION/Feature List response.

    Header: list length (4 B), reserved (2 B), current profile (2 B);
    then the Profile List feature (0x0000) with its profile descriptors.
    """
    profiles = []
    pos = 12  # 8-byte header + 4-byte Profile List feature header
    while pos + 4 <= len(raw):
        profiles.append({
            "profile": int.from_bytes(raw[pos:pos + 2], "big"),
            "current": raw[pos + 2],
        })
        pos += 4
    return {
        "list_length": int.from_bytes(raw[0:4], "big"),
        "current_profile": int.from_bytes(raw[6:8], "big"),
        "profile_list_feature": int.from_bytes(raw[8:10], "big"),
        "profiles": profiles,
    }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse() -> dict:
    """Full anomaly analysis over the recorded evidence."""
    rc = parse_read_capacity(RC10_RESPONSE)
    rc_only_sectors = sr_capacity_512b(
        rc["last_lba"], rc["block_len"], last_written=0)
    kernel_sectors = sr_capacity_512b(rc["last_lba"], rc["block_len"])
    capacity_after_max = max(rc["blocks"], LAST_WRITTEN_BLOCKS)
    fallback_sectors = sr_fallback_capacity_512b()
    candidates = responses_producing_sysfs_size()
    toc = decode_toc()
    gc = decode_get_configuration()

    return {
        "device_view": {
            "source": "READ CAPACITY(10) response "
                      + RC10_RESPONSE.hex() + " (steady state)",
            "last_lba": rc["last_lba"],
            "block_len": rc["block_len"],
            "blocks": rc["blocks"],
            "bytes": rc["device_bytes"],
            "mib": round(rc["device_bytes"] / (1024 * 1024), 2),
        },
        "kernel_view": {
            "source": "/sys/block/srX/size (after sr.c capacity math)",
            "sysfs_512b_sectors": SYSFS_SIZE_512B,
            "bytes": SYSFS_SIZE_512B * 512,
            "mib": round(SYSFS_SIZE_512B * 512 / (1024 * 1024), 2),
            "matches_iso_bytes": SYSFS_SIZE_512B * 512 == ISO_BYTES,
        },
        "last_written": {
            "blocks": LAST_WRITTEN_BLOCKS,
            "toc_leadout_msf": "%02d:%02d:%02d" % TOC_LEADOUT_MSF,
            "toc_leadout_lba": msf_to_lba(TOC_LEADOUT_MSF),
            "track_info_track_size": TRACK_INFO_TRACK_SIZE,
            "sources_agree": (msf_to_lba(TOC_LEADOUT_MSF)
                              == TRACK_INFO_TRACK_SIZE
                              == LAST_WRITTEN_BLOCKS),
        },
        "kernel_from_recorded_response": {
            "read_capacity_sectors_512b": rc_only_sectors,
            "capacity_after_max_blocks": capacity_after_max,
            "sectors_512b": kernel_sectors,
            "bytes": kernel_sectors * 512,
            "matches_sysfs": kernel_sectors == SYSFS_SIZE_512B,
            "note": "sr.c get_sectorsize(): capacity = max(1 + last_lba, "
                    "last_written), then *4 for 2048 B sectors",
        },
        "fallback": {
            "sectors_512b": fallback_sectors,
            "bytes": fallback_sectors * 512,
            "matches_sysfs": fallback_sectors == SYSFS_SIZE_512B,
            "note": "sr.c failure path: capacity = 0x%x sectors, "
                    "sector_size 2048; no *4 and no set_capacity()"
                    % SR_FALLBACK_CAPACITY_BLOCKS,
        },
        "read_capacity_16": {
            "supported": False,
            "sense_key": RC16_SENSE_KEY,
            "asc": RC16_ASC,
            "note": "Illegal Request / Invalid command operation code",
        },
        "quirk_evidence": {
            "toc_format0_equals_format2": TOC_FMT0 == TOC_FMT2,
            "toc": toc,
            "get_configuration": gc,
        },
        "candidate_enumeration_responses": candidates,
        "verdict": VERDICT,
        "remaining_hardware_steps": [
            "none for the root cause: TRACK INFORMATION track_size "
            "0x1F00 and TOC lead-out 01:47:61 (both 7936 blocks) are "
            "already measured",
            "READ(10) beyond LBA 1983 is expected to fail (LBA out of "
            "range); 1593-1983 is zero padding",
        ],
    }


def print_report(a: dict) -> None:
    """Human-readable summary of analyse()."""
    print("Capacity anomaly: 3.1 MiB usable vs 15.5 MiB kernel block device")
    print()
    print("Device (steady state): %s" % a["device_view"]["source"])
    print("  last LBA %d, %d B blocks -> %d blocks = %d B (%s MiB)" % (
        a["device_view"]["last_lba"], a["device_view"]["block_len"],
        a["device_view"]["blocks"], a["device_view"]["bytes"],
        a["device_view"]["mib"]))
    print("Kernel: %s" % a["kernel_view"]["source"])
    print("  /sys/block/srX/size = %d x 512 B = %d B (%s MiB)" % (
        a["kernel_view"]["sysfs_512b_sectors"],
        a["kernel_view"]["bytes"], a["kernel_view"]["mib"]))
    print("  matches ISO volume size: %s" % (
        a["kernel_view"]["matches_iso_bytes"],))
    print()
    print("Kernel math on the recorded response (sr.c get_sectorsize()):")
    print("  READ CAPACITY only: (1 + %d) * 4 = %d sectors of 512 B -> %s"
          % (a["device_view"]["last_lba"],
             a["kernel_from_recorded_response"]
             ["read_capacity_sectors_512b"],
             "does NOT match sysfs 31744"))
    print("  cdrom_get_last_written: %d blocks -> max(%d, %d) * 4 = %d "
          "sectors of 512 B = %d B -> %s"
          % (a["last_written"]["blocks"], a["device_view"]["blocks"],
             a["last_written"]["blocks"],
             a["kernel_from_recorded_response"]["sectors_512b"],
             a["kernel_from_recorded_response"]["bytes"],
             "MATCHES sysfs" if a["kernel_from_recorded_response"]
             ["matches_sysfs"] else "does NOT match sysfs 31744"))
    print("Failure fallback (READ CAPACITY error path):")
    print("  0x%x sectors of 512 B (no *4, no set_capacity()) = %d B -> %s"
          % (SR_FALLBACK_CAPACITY_BLOCKS, a["fallback"]["bytes"],
             "MATCHES sysfs" if a["fallback"]["matches_sysfs"]
             else "does NOT match sysfs 31744"))
    print("READ CAPACITY(16): unsupported (%s)" %
          a["read_capacity_16"]["note"])
    print()
    print("READ CAPACITY answers whose own value yields sysfs 31744 "
          "(before last_written):")
    for c in a["candidate_enumeration_responses"]:
        print("  last LBA %d / %d B blocks -> raw %s" % (
            c["last_lba"], c["block_len"], c["raw"]))
    print()
    print("Canned-response evidence:")
    print("  READ TOC format 0 == format 2 bytes: %s (track-1 start LBA %d)"
          % (a["quirk_evidence"]["toc_format0_equals_format2"],
             a["quirk_evidence"]["toc"]["track_desc"]["start_lba"]))
    print("  GET CONFIGURATION current profile: 0x%04X (CD-ROM)" %
          a["quirk_evidence"]["get_configuration"]["current_profile"])
    print()
    print("Verdict: %s" % a["verdict"])
    print("Remaining hardware steps / limits:")
    for step in a["remaining_hardware_steps"]:
        print("  - %s" % step)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WormholeSwitch capacity anomaly analysis (issue #13)")
    parser.add_argument(
        "--rc10", metavar="HEX",
        help="evaluate a captured 8-byte READ CAPACITY(10) data phase "
             "through the sr.c kernel path")
    parser.add_argument(
        "--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.rc10:
        try:
            raw = bytes.fromhex(args.rc10.replace(" ", ""))
        except ValueError as exc:
            print("invalid --rc10 hex: %s" % exc, file=sys.stderr)
            return 2
        try:
            rc = parse_read_capacity(raw)
        except ValueError as exc:
            print("invalid --rc10 data phase: %s" % exc, file=sys.stderr)
            return 2
        rc_only = sr_capacity_512b(
            rc["last_lba"], rc["block_len"], last_written=0)
        sectors = sr_capacity_512b(rc["last_lba"], rc["block_len"])
        capacity_after_max = max(rc["blocks"], LAST_WRITTEN_BLOCKS)
        if args.json:
            json.dump({
                "response_hex": raw.hex(),
                "parse": rc,
                "read_capacity_only_sectors_512b": rc_only,
                "last_written_blocks": LAST_WRITTEN_BLOCKS,
                "capacity_after_max_blocks": capacity_after_max,
                "kernel_sectors_512b": sectors,
                "kernel_bytes": None if sectors is None else sectors * 512,
                "matches_sysfs_31744": sectors == SYSFS_SIZE_512B,
            }, sys.stdout, indent=2)
            print()
        else:
            print("READ CAPACITY(10) data phase: %s" % raw.hex())
            print("  last LBA %d / %d B blocks -> %d B device view" % (
                rc["last_lba"], rc["block_len"], rc["device_bytes"]))
            print("  READ CAPACITY only -> %s sectors of 512 B"
                  % rc_only)
            print("  last_written %d -> max(%d, %d) = %d blocks"
                  % (LAST_WRITTEN_BLOCKS, rc["blocks"],
                     LAST_WRITTEN_BLOCKS, capacity_after_max))
            if sectors is None:
                print("  kernel: unsupported sector size (capacity zeroed)")
            else:
                print("  kernel sr.c path -> %d sectors of 512 B (%s sysfs "
                      "31744)" % (sectors,
                                  "MATCHES" if sectors == SYSFS_SIZE_512B
                                  else "does not match"))
        return 0

    a = analyse()
    if args.json:
        json.dump(a, sys.stdout, indent=2)
        print()
    else:
        print_report(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
