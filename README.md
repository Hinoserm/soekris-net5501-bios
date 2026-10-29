# Soekris net5501 comBIOS 1.33x

Fixes for Soekris Engineering's last BIOS for the net5501, comBIOS 1.33c
(`b5501_133c.bin`, 2008-06-26), found by disassembling it:

- Large CompactFlash cards hang the BIOS during drive detection, or get a
  translated geometry with zero heads.
- A video card's VGA BIOS is never run.
- A VGA BIOS that is run is told the wrong PCI bus and device.
- A VGA BIOS runs before the BIOS timer is started.

The patched BIOS reports itself as `comBIOS ver. 1.33x 20261029`.

## Files

| File | What it is |
|---|---|
| `b5501_133x.bin` | The patched BIOS image. |
| `patch_b5501.py` | Builds it from the original `b5501_133c.bin`. |

SHA-256:

```
f14ef586478d2f198c9888a1fda46a091f0a1eb0eb2fc5435c5148598bef1bb0  b5501_133c.bin (original)
5e3258c1fd8265f92cf8a4be4f4afe9dd2871ea1827d9b340113c6cb9adcdcb4  b5501_133x.bin
```

The original is still available from the Internet Archive:
<https://web.archive.org/web/2020id_/http://www.soekris.com/media/software/b5501_133c.bin>

## The fixes

Offsets are in the main BIOS module, which starts at file offset `0xA800`.
Add `0xA800` to get a file offset.

| Fix | Where |
|---|---|
| Large CF cards no longer hang detection | `0x2973`, `0x2979` |
| Version and date | `0x002D`, file `0x187F5` |
| VGA option ROM is enabled and run | `0x2513`, `0x5776` |
| VGA ROM is told its own bus and device | `0x558C`, `0x5594` |
| The timer runs before the VGA ROM | `0x2553`, `0x0334`, `0x0354` |

### Large CompactFlash cards hang detection

If a drive's IDENTIFY geometry has 1024 cylinders or more, the BIOS builds a
translated geometry from the CHS product (`0x296D`):

1. It computes `q = (C*H*S - 1) / 64512`.
2. It derives a logical head count from `q` with an 8-step shift loop. That
   loop only works for `q < 256`, which is up to about 8.4 GB.
3. It divides the total by `heads * 63` to get the logical cylinder count
   (`div cx` at `0x29AF`).

Drives normally report at most 16383/16/63, but CF cards often report a
cylinder count closer to their real capacity. Once the CHS product passes
16384 x 16 x 63 sectors, `q` reaches 256 and the head count goes wrong:

- **With `q` from 256 to 511** (16 heads, 63 sectors: 16385 to 32768
  cylinders, about 8.5 to 16.9 GB), the head count comes out as 0. The divide
  is skipped, and the drive gets a translated geometry with no heads.
- **With `q` from 512 to 1535** (a CHS product of about 16.9 to 50.7 GB,
  which includes every 16-head, 63-sector geometry from 32769 cylinders up),
  the head count comes out as 1 to 4. The quotient no longer fits in 16 bits,
  and the CPU raises a divide error. The BIOS points INT 0 at a bare `iret`,
  which returns to the faulting `div`, so it runs again forever.
- **With `q` of 1536 or more**, the head count comes out as 5 or more. The
  divide fits, but the translated geometry is still wrong.

The fix caps the CHS product at `0xFC0000` sectors (16384 x 16 x 63) before
the head count is derived. Every larger geometry now gets the same 1024/255/63
translation as any disk over 8 GB. LBA access and the reported size come from
IDENTIFY words 60-61 and are unaffected.

### PCI option ROMs are never run

When POST finds a VGA card (`0x5573`, PCI class 0x0001, 0x0300 or 0x0301), it:

1. assigns the card's BARs;
2. sizes its expansion ROM;
3. maps the ROM at `0x98000000`;
4. checks the ROM's `55AA` and `PCIR` headers;
5. copies it to `C0000`;
6. calls `C000:0003`.

Step 3 writes the ROM BAR with `mov ecx,[0x15]`, but the ROM base is stored at
`[0x14]`. The dword it reads is one byte off: `0x??980000` instead of
`0x98000001`. The enable bit is never set, so the ROM never decodes, step 4
fails, and the BIOS writes 0 back to the ROM BAR. The card works under an OS,
but its video BIOS never runs and nothing appears on screen.

The fix puts an 11-byte helper in unused padding at `0x2513`. It loads
`[0x14]`, sets bit 0, and jumps to the BIOS's own PCI config-write routine.
The VGA path now calls it.

The generic loop for other cards' option ROMs (`0x5BD3`) has the same bug, and
is deliberately left as it is. Because of the bug, the loader that would run
those ROMs (`0x5C25`) has never run on any board. Enabling it makes an Intel
e1000 card's boot ROM send POST into an endless `PCI Error 9B08001C` loop, so
other cards keep working exactly as they did with the original BIOS: their
ROMs are not run.

Once the video BIOS runs, it takes over `INT 10h`. comBIOS prints everything
through `INT 10h`, so its messages move to the screen. Keyboard input stays on
the serial console, because the net5501 has no keyboard controller.

### A VGA ROM is told the wrong bus and device

By the PCI firmware specification, a ROM's init routine is entered with
AH = bus and AL = device/function. This BIOS restores the card's bus/devfn into
CX just before the call (`0x3CA5`), but that same routine sets BX to `0x0100`,
and the call does `mov ax,bx` (`0x5F00`). Every VGA ROM is therefore told it is
at bus 1, device 0, and the net5501 has no bus 1. A ROM that uses AX to find
its own configuration space and I/O ports reads a device that isn't there.

The fix uses dead code. The branch at `0x5596`, taken when no usable ROM was
found, always fails, since `0x3CF6` is `stc`/`ret`. It now jumps straight to
the existing failure exit at `0x55A6`, and the freed bytes hold `mov bx,cx`.

### A VGA BIOS runs before the timer

POST calls the VGA scan (`0x5573`) at `0x334`, but installs the `INT 08h`
timer handler and unmasks IRQ0 (`0x4EF7`) only at `0x354`. While the video
BIOS runs, the BIOS tick count at `40:6C` does not move, and `INT 1Ah AH=00`
keeps returning the same value. A video BIOS that times its delays with the
tick count waits forever.

The fix puts a 6-byte helper in unused padding at `0x2553`. It calls `0x4EF7`,
which loads the tick count from the RTC and starts the timer, and then jumps
to the VGA scan. POST at `0x334` calls the helper. The original call at
`0x354` is removed: it would point `INT 08h` and `INT 70h` back at the BIOS's
own handlers, dropping any hook the video BIOS installed, and step the tick
count back to the RTC's whole second.

## The image format and its checksum

The file is a chain of modules, which `flashupdate` walks:

1. the PXE option ROM for the onboard VIA Rhine Ethernet (`55AA`);
2. optional `FF` padding;
3. an optional type 5 module;
4. a type 1 or 2 module (the main BIOS);
5. optional `FF` padding;
6. an optional `-BCP` block;
7. a type 3 module (the boot block, which holds the reset vector);
8. the end of the file.

In this image the type 5 module is not separate: it sits inside the main
module, at file offset `0x15800`.

Each `SK_R` module starts with a 16-byte header:

| Offset | Contents |
|---|---|
| 0x00 | `SK_R` |
| 0x04 | length in 256-byte units (16-bit) |
| 0x06 | type |
| 0x08 | `0x55` |
| 0x09 | revision |
| 0x0E | checksum word |

The checksum word is chosen so that all the module's 16-bit little-endian words
sum to 0. To recompute it, zero the word, sum the module, and store the
negated sum. Nothing in this BIOS appears to check it: `flashupdate` checks
only the structure, the minimum revision and the total length. The patcher
sets it correctly anyway, and checks every module before writing the file.

## Flashing

From the comBIOS monitor (Ctrl-P during boot), on the serial console:

1. Run `download` and send the image with XMODEM/CRC. The BIOS expects 784
   blocks.
2. Optionally check the downloaded copy before flashing: `db 4a820` should show
   `comBIOS ver. 1.33x 20261029`.
3. Run `flashupdate`. It should end with `Done.`
4. Power-cycle the board. Until a cold boot, the old BIOS keeps running from
   its RAM copy. `db ffff0020` shows what is in the flash itself.

**There is no recovery path.** The boot block is rewritten on every flash and
contains only a jump to the main BIOS. A power cut or a bad image during
`flashupdate` leaves a board that only an external flash programmer can
revive. If a video card's own BIOS hangs during POST, removing the card brings
the board back.

## Building

```bash
python3 patch_b5501.py b5501_133c.bin b5501_133x.bin
```

The patcher:

- refuses any input other than the exact original, checking both its SHA-256
  and every byte it replaces;
- updates the checksums of the modules it touches;
- checks that every module sums to 0 and that the PXE ROM's own byte sum is
  intact.
- refuses to write over its own input.

## Other things found along the way

- Memory runs at DDR266. The GeodeLink PLL multiplier is fixed at 7 (`0x3D2E`).
- RAM is sized automatically, one or two ranks and up to 1 GB, by trying a table
  of controller configurations (`0x43C6`). No jumper is involved.
- A broken CF socket pin 47 (D08) shows up as every IDENTIFY word having bit 8
  clear: a garbled model string ("RanDhsj" for "SanDisk") and a wrong size.

## License

See [LICENSE](LICENSE). comBIOS is Soekris Engineering's, not ours.
