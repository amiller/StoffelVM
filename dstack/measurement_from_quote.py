#!/usr/bin/env python3
"""Compute the stoffel attestation measurement blake3(mr_td||rtmr0..3) from a
raw Intel TDX DCAP quote (v4/v5). Offsets per Intel TDX DCAP spec:
header = 48 bytes; TD report body: tee_tcb_svn(16) mr_seam(48) mr_signer_seam(48)
seam_attributes(8) td_attributes(8) xfam(8) mr_td(48) mr_config_id(48)
mr_owner(48) mr_owner_config(48) rtmr0..3(4*48).
Usage: measurement_from_quote.py <hex-or-base64-quote-file-or-'-'>"""
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
rtmrs = body[328:520]
assert len(rtmrs) == 192
m = blake3.blake3(mr_td + rtmrs).hexdigest()
print(f"mr_td:    {mr_td.hex()}")
for i in range(4):
    print(f"rtmr{i}:    {rtmrs[i*48:(i+1)*48].hex()}")
print(f"measurement: {m}")
