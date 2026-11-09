# #13: Capacity anomaly (3.1 MiB vs 15.5 MiB) — resolved

Device: `0711:2211` WormholeSwitch, `/dev/sr0` ↔ `/dev/sg1`
(USB `3-1`, serial `C6629C6563582530`). Mount: `/media/rich/Wormhole`
(ISO9660 `WORMHOLE`).

## TL;DR

There is no partition table and no hidden volume. **Authoritative
usable size is 1593 × 2048 = 3,262,464 B (3.1 MiB).** The 15.5 MiB
exposed by `lsblk`/`fdisk`/`blockdev` (7936 × 2048 =
16,252,928 B = 31744 × 512) is a kernel overestimate. Linux
`sr` takes `max(READ CAPACITY, last_written)` — here the
firmware's TRACK INFORMATION / TOC lead-out reports 7936 blocks,
larger than READ CAPACITY and the ISO PVD (1593), so the kernel
uses 7936. The tail beyond 1593 holds no data: 1593–1983 are
all-zero reads, 1984+ fail with LBA out of range.

## Evidence

| Method | Value | Source |
|---|---|---|
| `sg_readcap` / raw `READ CAPACITY(10)` | Last LBA 1592, 1593 × 2048 = **3,262,464 B** (raw `00 00 06 38 00 00 08 00`) | Firmware |
| ISO PVD + Joliet SVD (sectors 16/17) Volume Space Size | **1593 blocks** | Firmware image |
| `blkid` FSSIZE | **3262464** | Filesystem |
| `df -B1` / `stat -f` Blocks | **3,262,464 B** (1593 × 2048) | Mounted FS |
| File bytes total | 3,165,663 B + 96,801 overhead = 3,262,464 B | Mounted FS |
| `lsblk` / `fdisk` / `blockdev --getsize64` / `/sys/block/sr0/size` | **16,252,928 B** (7936 × 2048 = 31744 × 512) | Kernel |
| `READ TRACK INFORMATION` track_size | **7936 (0x00001F00)** | Firmware |
| `READ TOC` lead-out MSF `01:47:61` | **7936** (`((1*60)+47)*75+61−150`) | Firmware |
| `READ(10)` readable limit (`dd`/`sg_raw`/`sg_read`) | LBA 0–1983 OK (zeros after 1593), **1984+ LBA out of range** (`IOERROR` / ASC `0x21`) | Firmware |
| Partition check (`fdisk -l`, `parted print`) | **No partitions**, "unrecognised disk label" / "unknown", whole-disk ISO | — |

Reproduction (bus numbers differ):

```sh
lsblk -o NAME,PATH,SIZE,TYPE /dev/sr0
blockdev --getsize64 /dev/sr0; cat /sys/block/sr0/size   # 16252928; 31744
sg_readcap /dev/sg1                                       # Last LBA=1592
df -B1 /media/rich/Wormhole                               # 3262464
sg_raw -r 32 /dev/sg1 52 00 00 00 00 00 00 00 20 00     # track_size 0x1F00
sg_raw -r 32 /dev/sg1 43 00 00 00 00 00 00 00 20 00     # lead-out MSF 1:47:61
dd if=/dev/sr0 bs=2048 skip=1593 count=1 status=none | wc -c   # 2048 (zeros)
dd if=/dev/sr0 bs=2048 skip=1984 count=1 status=none             # I/O error
```

Note: `sg_raw` READ(10) requires `-r <len>` matching the CDB
transfer length on this firmware (otherwise Invalid field in CDB).

## Root cause

Firmware inconsistency, surfaced by kernel policy — not a
partition table, not extra data:

1. **1593** — READ CAPACITY + ISO PVD/SVD + files → the real volume.
2. **7936** — TRACK INFORMATION track_size and TOC lead-out → claims
   a 16 MB volume.
3. **1984** — actual `READ(10)` limiter → only 1984 blocks return
   (zeros past 1593); 7936 is never fully readable.

Kernel `drivers/scsi/sr.c get_sectorsize()`:

```c
cd->capacity = 1 + read_capacity_last_lba;      // 1593
cdrom_get_last_written(&cdi, &last_written);    // DISC INFO + TRACK INFO
cd->capacity = max(cd->capacity, last_written); // max(1593, 7936) = 7936
if (sector_size == 2048) cd->capacity *= 4;     // 31744 (512 units)
```

`cdrom_get_last_written` (`drivers/cdrom/cdrom.c`) reads DISC
INFO (`0x51`, last track 1) + TRACK INFO (`0x52`: start 0,
size 7936) and, with `lra_v=0`, returns `track_start+track_size`
= 7936 (TOC MSF lead-out agrees: 7936). Hence `/sys/block/sr0/size`
= 31744. The ISO mount never touches the overstated tail
(filesystem ends at 1593), so mounting works despite the wrong
block-device size.

Drives/firmware class: `sg_get_config` reports ATAPI, logical
block size `0x800` (2048) — consistent with all of the above.

## Recommendation

Treat **3,262,464 B (1593 × 2048)** as the Wormhole volume size
for hashing, slicing, and `dd`/`xorriso` work. Do not treat
`lsblk`/`fdisk` 15.5 MiB as media size. Raw `dd` at/above LBA
1984 must be expected to fail; 1593–1983 is zero padding only.
Upstream fix would be firmware-side (make TRACK INFO/TOC lead-out
agree with READ CAPACITY/PVD at 1593); kernel-side, the `max()`
rule intentionally prefers `last_written` for UDF media and is
not to be changed for this device.
