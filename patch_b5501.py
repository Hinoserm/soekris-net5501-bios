#!/usr/bin/env python3
"""Patch Soekris comBIOS 1.33c for the net5501 (b5501_133c.bin) into 1.33x.

Usage: patch_b5501.py IN OUT

IN must be the original b5501_133c.bin (checked by SHA-256).
"""
import hashlib, os, struct, sys

ORIG_SHA = "f14ef586478d2f198c9888a1fda46a091f0a1eb0eb2fc5435c5148598bef1bb0"
MAIN = 0xA800                      # SK_R type-2 module (main BIOS); BIOS offsets below are relative to it

# (file offset, old bytes, new bytes, what it does)
PATCH = [
    # Large CF cards: the CHS translation divided by heads*63 after a head count that only works up to
    # ~8.4 GB of CHS geometry, so DIV at 0x29AF overflowed and the divide-error handler (a bare iret)
    # re-ran it forever. Cap the CHS product at 0xFC0000 sectors (16384 x 16 x 63).
    (MAIN + 0x2973, bytes.fromhex("81faf00f"), bytes.fromhex("81fafc00"), "cmp dx,0xff0 -> cmp dx,0xfc"),
    (MAIN + 0x2979, bytes.fromhex("baf00f"),   bytes.fromhex("bafc00"),   "mov dx,0xff0 -> mov dx,0xfc"),
    # Version and date.
    (MAIN + 0x002D, b"1.33c 20080626", b"1.33x 20261029", "banner"),
    (0x187F5,       b"20080626",       b"20261029",       "date beside the reset vector"),
    # VGA option ROM: the ROM BAR was written from the dword at [0x15], a byte past the ROM base at
    # [0x14], so the enable bit was never set and the ROM never decoded. A helper in unused padding
    # after 0x2512 writes [0x14] | 1 and tail-jumps to the PCI config-write routine at 0x54F8.
    # The generic loop for other cards (0x5BD3) has the same bug; it calls the same helper.
    (MAIN + 0x2513, bytes(11), bytes.fromhex("668b0e1400" "80c901" "e9da2f"), "ROM BAR helper"),
    (MAIN + 0x5776, bytes.fromhex("668b0e1500e87afd"), bytes.fromhex("e89acd9090909090"), "VGA ROM BAR"),
    (MAIN + 0x5BD3, bytes.fromhex("668b0e1500e81df9"), bytes.fromhex("e83dc99090909090"), "other cards' ROM BARs"),
    # The loader that runs those other ROMs (0x5C25, when PCIROMS is set) has never run: no card's ROM
    # could validate. Two faults in it. It enables a card's ROM BAR from the dword at [0x398], a byte
    # past the window base at [0x397] -- the same slip -- so the copy reads nothing. A helper in unused
    # padding at 0x4C12 returns [0x397] | 1. And it runs the smallest ROM first, so the onboard Rhine
    # PXE ROM ran before a card's and the list was found overwritten after it. The selection routine
    # (0x5D80) is rewritten in place: card ROMs first, the board's built-in ROM last, each once.
    (MAIN + 0x4C12, bytes(9), bytes.fromhex("668b0e970380c901c3"), "loader ROM BAR helper"),
    (MAIN + 0x5E42, bytes.fromhex("668b0e9803"), bytes.fromhex("e8cded9090"), "loader calls it"),
    (MAIN + 0x5D80,
     bytes.fromhex("515257b2000fb60e9403837c18ff750c83c61a833cff7427fec2e2ee8bfe0fb60e94032aca83c71a833dff74128a45023844027e08837d18ff74028bf7e2e65f5a59c3"),
     bytes.fromhex("5057b001bf5400833dff7410837d18ff7405384503740b83c71aebebfec03c0372e289fe5f58c3")
     # In the 28 bytes the old routine leaves free: 0x5DA7 turns the ROM BAR of the device in BX off,
     # keeping all registers and flags; 0x5DBD runs a ROM (0x5EC0) and then does that. Nothing ever
     # turned a ROM BAR off after its ROM ran (0x5DC3 would, but nothing calls it and it clears the
     # wrong bit), so a VGA card and a card behind it both decoded their ROMs at 0x98000000.
     + bytes.fromhex("9c66506651576631c9bf3000e842f75f665966589dc3" "e80001ebe5") + b"\x90",
     "ROM selection: cards first, built-in last; ROM BAR off after a ROM runs"),
    (MAIN + 0x55A1, bytes.fromhex("e81c09"), bytes.fromhex("e81908"), "VGA ROM: run it, then its ROM BAR off"),
    (MAIN + 0x5E7B, bytes.fromhex("e84200"), bytes.fromhex("e83fff"), "other ROMs: the same"),
    # The VGA ROM was entered with AX = 0x0100 (bus 1, device 0) left in BX by 0x3CA5, instead of the
    # card's bus/devfn, which 0x3CA5 has just restored into CX. The no-usable-ROM branch (always a
    # failure: 0x3CF6 is stc/ret) goes straight to the failure exit at 0x55A6; the freed bytes hold mov bx,cx.
    (MAIN + 0x558C, bytes.fromhex("7408"), bytes.fromhex("7418"), "no usable ROM -> failure exit"),
    (MAIN + 0x5594, bytes.fromhex("eb05e85de7720b"), bytes.fromhex("8bd99090909090"), "VGA ROM gets its bus/devfn in AX"),
    # The VGA ROM ran before the timer: POST installed INT 08h and unmasked IRQ0 (0x4EF7, called at
    # 0x354) only after the VGA scan (0x5573, called at 0x334), so the tick count at 40:6C stood still and
    # a ROM that times its delays with it waited forever. A helper in unused padding at 0x2553 starts the
    # timer and then runs the VGA scan. The original call at 0x354 goes: it would re-point INT 08h and
    # INT 70h at the BIOS handlers, dropping any hook the VGA ROM installed, and step the tick count back.
    (MAIN + 0x2553, bytes(6), bytes.fromhex("e8a129" "e91a30"), "start the timer, then the VGA scan"),
    (MAIN + 0x0334, bytes.fromhex("e83c52"), bytes.fromhex("e81c22"), "POST calls the helper"),
    (MAIN + 0x0354, bytes.fromhex("e8a04b"), bytes.fromhex("909090"), "no second timer start"),
]

def sum16(b):
    return sum(struct.unpack_from("<%dH" % (len(b) // 2), b)) & 0xFFFF

def modules(d):
    """Walk the image the way flashupdate does; return the SK_R modules."""
    p, out = 0, []
    while d[p:p+2] == b"\x55\xaa":             # option ROMs
        p += d[p+2] * 512
    while p < len(d):
        if d[p:p+4] == b"\xff" * 4: p += 0x200; continue
        if d[p:p+4] == b"-BCP": p += 0x1000; continue
        if d[p:p+4] != b"SK_R": sys.exit(f"unexpected data at {p:#x}")
        ln, typ, magic, rev = struct.unpack_from("<HBxBB", d, p + 4)
        if magic != 0x55: sys.exit(f"module at {p:#x}: byte 8 is not 0x55")
        out.append((p, ln * 256)); p += ln * 256
    if p != len(d): sys.exit("modules do not end at the end of the file")
    return out

def main(argv):
    if len(argv) != 2: sys.exit(__doc__)
    src, dst = argv
    if os.path.realpath(src) == os.path.realpath(dst) or (os.path.exists(dst) and os.path.samefile(src, dst)):
        sys.exit("IN and OUT must differ")
    d = bytearray(open(src, "rb").read())
    if hashlib.sha256(d).hexdigest() != ORIG_SHA: sys.exit("not the expected b5501_133c.bin")
    for off, old, new, _ in PATCH:
        if d[off:off+len(old)] != old: sys.exit(f"unexpected bytes at {off:#x}")
        d[off:off+len(new)] = new
    # Each SK_R module carries a word at +0x0E that makes its 16-bit words sum to 0.
    for p, ln in modules(d):
        if any(p <= off < p + ln for off, _, _, _ in PATCH):
            d[p+0xE:p+0x10] = b"\0\0"
            d[p+0xE:p+0x10] = struct.pack("<H", (-sum16(d[p:p+ln])) & 0xFFFF)
    for p, ln in modules(d) + [(MAIN + 0xB000, 0x1000)]:    # a type-5 module sits inside the main one
        if sum16(d[p:p+ln]) != 0: sys.exit(f"module at {p:#x} does not sum to 0")
    if sum(d[:d[2] * 512]) & 0xFF != 0: sys.exit("the PXE option ROM's byte sum is broken")
    open(dst, "wb").write(d)
    print("wrote", dst, hashlib.sha256(d).hexdigest())

main(sys.argv[1:])
