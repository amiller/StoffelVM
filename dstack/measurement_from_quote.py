#!/usr/bin/env python3
"""Compute the stoffel admission measurement from a raw Intel TDX DCAP quote.

    measurement = blake3(mr_td || rtmr0 || rtmr1 || rtmr2)

RTMR3 is deliberately NOT included. It is the runtime-extended register, and its
contents are per-boot and per-deployment, so a digest over it is not stable
under a running committee — measured on a live pod, three different values
inside one hour while mr_td and RTMR0..2 stayed byte-identical. The app identity
RTMR3 carries is recovered instead by replaying the dstack event log onto the
quote's registers (see crates/stoffel-vm/src/net/dstack_event_log.rs), which is
both stable and more informative than pinning an opaque digest over it.

Offsets per Intel TDX DCAP spec: header = 48 bytes; TD report body:
tee_tcb_svn(16) mr_seam(48) mr_signer_seam(48) seam_attributes(8)
td_attributes(8) xfam(8) mr_td(48) mr_config_id(48) mr_owner(48)
mr_owner_config(48) rtmr0..3(4*48).

Usage: measurement_from_quote.py <hex-or-base64-quote-file-or-'-'>
"""
import sys, base64, binascii
import blake3

raw = sys.stdin.buffer.read() if sys.argv[1] == "-" else open(sys.argv[1], "rb").read()
s = raw.strip()
try:
    q = binascii.unhexlify(s)
except (binascii.Error, ValueError):
    q = base64.b64decode(s)

assert len(q) > 48 + 584, f"quote too short: {len(q)}"
body = q[48:]
mr_td = body[136:184]
rtmrs = [body[328 + i * 48 : 328 + (i + 1) * 48] for i in range(4)]

m = blake3.blake3(mr_td + b"".join(rtmrs[:3])).hexdigest()
print(f"mr_td:       {mr_td.hex()}")
for i in range(3):
    print(f"rtmr{i}:       {rtmrs[i].hex()}   (pinned)")
print(f"rtmr3:       {rtmrs[3].hex()}   (NOT pinned; verified via the event log)")
print(f"measurement: {m}")
