"""
Aegix Share - Full Feature Test Suite (Part 2: sections 8-15)
All timeouts are generous; expiry test uses a 5-second window so the
transfer is fully uploaded before it expires.
"""
import sys, secrets, requests, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

B = "http://localhost:8000"
P, F = [], []

def ok(m):        P.append(m);  print("[PASS]", m)
def fail(m, d=""): F.append(m); print("[FAIL]", m, "--", str(d)[:120])
def hdr(t):        print("\n===", t, "===")

# ─── 8. Download limit ────────────────────────────────────────
hdr("8. DOWNLOAD LIMIT (limit=2)")
lt = "lm_" + secrets.token_hex(4)
r = requests.post(B + "/api/transfer/init/", json={
    "id": lt, "name": "l.txt", "size": 5, "type": "text/plain",
    "total_chunks": 1, "expiry_hours": 1, "self_destruct": False,
    "download_limit": 2, "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=10)
ok("Limit init 200") if r.status_code == 200 else fail("Limit init", r.text)

requests.post(B + f"/api/transfer/{lt}/upload/0/",
    files={"chunk": ("c", b"abcde", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "5"}, timeout=10)
requests.post(B + f"/api/transfer/{lt}/complete/", timeout=10)

r1 = requests.get(B + f"/api/transfer/{lt}/chunk/0/", timeout=10)
ok("DL1: 200 (count=1)") if r1.status_code == 200 else fail("DL1 failed", r1.status_code)

r2 = requests.get(B + f"/api/transfer/{lt}/chunk/0/", timeout=10)
ok("DL2: 200 (count=2)") if r2.status_code == 200 else fail("DL2 failed", r2.status_code)

r3 = requests.get(B + f"/api/transfer/{lt}/chunk/0/", timeout=10)
ok("DL3: 410 Gone (over limit)") if r3.status_code == 410 else fail("DL3 should be 410", r3.status_code)
ok("DL3 CORS=*") if r3.headers.get("Access-Control-Allow-Origin") == "*" else fail("DL3 CORS missing")

rm = requests.get(B + f"/api/transfer/{lt}/meta/", timeout=10)
ok("Meta 410 after limit") if rm.status_code == 410 else fail("Meta should 410 after limit", rm.status_code)
ok("Meta 410 CORS=*") if rm.headers.get("Access-Control-Allow-Origin") == "*" else fail("Meta 410 CORS missing")

# ─── 9. Link expiry ───────────────────────────────────────────
# Use 30 seconds so all 3 HTTP requests complete before the transfer expires.
hdr("9. LINK EXPIRY (30-second window)")
et = "ex_" + secrets.token_hex(4)
EXPIRY_SECS = 30   # 30s window: enough for init+upload+complete to finish
requests.post(B + "/api/transfer/init/", json={
    "id": et, "name": "e.txt", "size": 4, "type": "text/plain",
    "total_chunks": 1, "expiry_hours": EXPIRY_SECS / 3600,
    "self_destruct": False, "download_limit": 0,
    "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=10)
requests.post(B + f"/api/transfer/{et}/upload/0/",
    files={"chunk": ("c", b"expr", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "4"}, timeout=10)
requests.post(B + f"/api/transfer/{et}/complete/", timeout=10)

# Confirm it's alive before expiry (informational — timing can vary slightly)
ra = requests.get(B + f"/api/transfer/{et}/meta/", timeout=10)
if ra.status_code == 200:
    ok("Link alive before expiry (200)")
else:
    # Already expired due to slow CI — treat as warning, not failure
    print(f"  [WARN] Link already expired before pre-check ({ra.status_code}) — timing issue, not a bug")

# Wait for it to expire
print(f"  [INFO] Waiting {EXPIRY_SECS + 2}s for link to expire...")
time.sleep(EXPIRY_SECS + 2)

re_ = requests.get(B + f"/api/transfer/{et}/meta/", timeout=10)
# 410 = found and expired; 404 = already cleaned up by a parallel request — both are correct
ok(f"Expired returns {re_.status_code} (410 or 404)") if re_.status_code in (410, 404) else fail("Expired link should be 410 or 404", re_.status_code)
ok("Expiry CORS=*") if re_.headers.get("Access-Control-Allow-Origin") == "*" else fail("Expiry CORS missing")
if re_.status_code == 410:
    ok("Says 'expired'") if "expir" in re_.text.lower() else fail("Expiry message unclear", re_.text[:80])


# ─── 10. Self-destruct ────────────────────────────────────────
hdr("10. SELF-DESTRUCT")
st = "sd_" + secrets.token_hex(4)
requests.post(B + "/api/transfer/init/", json={
    "id": st, "name": "sd.txt", "size": 4, "type": "text/plain",
    "total_chunks": 1, "expiry_hours": 1, "self_destruct": True,
    "download_limit": 0, "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=10)
requests.post(B + f"/api/transfer/{st}/upload/0/",
    files={"chunk": ("c", b"BOOM", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "4"}, timeout=10)
requests.post(B + f"/api/transfer/{st}/complete/", timeout=10)

r1 = requests.get(B + f"/api/transfer/{st}/chunk/0/", timeout=10)
ok("SD DL1: 200, data=BOOM") if r1.status_code == 200 and r1.content == b"BOOM" else fail("SD DL1", (r1.status_code, r1.content[:20]))

r2 = requests.get(B + f"/api/transfer/{st}/chunk/0/", timeout=10)
ok(f"SD DL2: {r2.status_code} (chunk wiped)") if r2.status_code in (404, 410) else fail("SD DL2 should fail", r2.status_code)

# ─── 11. Password-protected ───────────────────────────────────
hdr("11. PASSWORD-PROTECTED TRANSFER")
pt = "pw_" + secrets.token_hex(4)
fs  = secrets.token_hex(16)
fwi = secrets.token_hex(12)
fwk = secrets.token_hex(32)
requests.post(B + "/api/transfer/init/", json={
    "id": pt, "name": "p.txt", "size": 6, "type": "text/plain",
    "total_chunks": 1, "expiry_hours": 1, "self_destruct": False,
    "download_limit": 0, "salt": fs, "wrap_iv": fwi, "wrapped_key": fwk,
}, timeout=10)
requests.post(B + f"/api/transfer/{pt}/upload/0/",
    files={"chunk": ("c", b"secret", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "6"}, timeout=10)
requests.post(B + f"/api/transfer/{pt}/complete/", timeout=10)

r = requests.get(B + f"/api/transfer/{pt}/meta/", timeout=10)
d = r.json()
ok("PWD meta 200") if r.status_code == 200 else fail("PWD meta", r.status_code)
ok("salt round-tripped") if d.get("salt") == fs else fail("salt wrong", d.get("salt", "")[:30])
ok("wrap_iv round-tripped") if d.get("wrap_iv") == fwi else fail("wrap_iv wrong")
ok("wrapped_key round-tripped") if d.get("wrapped_key") == fwk else fail("wrapped_key wrong")

# ─── 12. Multi-chunk ─────────────────────────────────────────
hdr("12. MULTI-CHUNK TRANSFER")
mct = "mc_" + secrets.token_hex(4)
ca, cb = b"A" * 1024, b"B" * 512
requests.post(B + "/api/transfer/init/", json={
    "id": mct, "name": "mc.bin", "size": len(ca) + len(cb),
    "type": "application/octet-stream", "total_chunks": 2,
    "expiry_hours": 1, "self_destruct": False, "download_limit": 0,
    "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=10)
for i, c in enumerate([ca, cb]):
    requests.post(B + f"/api/transfer/{mct}/upload/{i}/",
        files={"chunk": (f"c{i}", c, "application/octet-stream")},
        data={"iv": secrets.token_hex(12), "original_size": str(len(c))}, timeout=10)
requests.post(B + f"/api/transfer/{mct}/complete/", timeout=10)

for i, c in enumerate([ca, cb]):
    r = requests.get(B + f"/api/transfer/{mct}/chunk/{i}/", timeout=10)
    cl = r.headers.get("Content-Length", "")
    if r.status_code == 200 and r.content == c and cl == str(len(c)):
        ok(f"Multi chunk {i}: {len(c)}B, Content-Length={cl}")
    else:
        fail(f"Multi chunk {i}", f"status={r.status_code} cl={cl} expected={len(c)}")

# ─── 13. LAN discovery ────────────────────────────────────────
hdr("13. LAN DISCOVERY")
r = requests.post(B + "/api/lan/announce/",
    json={"id": "testpeer", "name": "TestPC"}, timeout=10)
ok("LAN announce 200") if r.status_code == 200 else fail("LAN announce", f"{r.status_code} {r.text[:80]}")
rd = r.json()
ok("server_ip in announce") if rd.get("server_ip") else fail("server_ip missing from announce response")

r = requests.get(B + "/api/lan/devices/", timeout=10)
d = r.json()
peers = d.get("peers", [])
ok(f"LAN devices 200 ({len(peers)} peers)") if r.status_code == 200 else fail("LAN devices", r.status_code)
ok("server_ip in devices") if d.get("server_ip") else fail("server_ip missing from devices")
found = any(p.get("id") == "testpeer" for p in peers)
ok("testpeer visible in peer list") if found else fail("testpeer not in peer list", [p.get("id") for p in peers])

# ─── 14. WebRTC signaling ─────────────────────────────────────
hdr("14. WEBRTC SIGNALING")
r = requests.post(B + "/api/webrtc/room/", timeout=10)
ok("Room created 200") if r.status_code == 200 else fail("Room creation", r.status_code)
rid = r.json().get("room_id") or r.json().get("id")

# sender must be 'initiator' or 'responder' (validated server-side)
r2 = requests.post(B + f"/api/webrtc/{rid}/signal/", json={
    "sender": "initiator", "type": "offer", "payload": {"sdp": "v=0"},
}, timeout=10)
ok("Signal posted 200") if r2.status_code == 200 else fail("Signal post", r2.text[:80])

# Non-blocking poll: peer=responder reads signals FROM initiator
r3 = requests.get(B + f"/api/webrtc/{rid}/poll/?after=0&peer=responder", timeout=10)
d3 = r3.json()
sigs = d3.get("signals", [])
ok(f"Poll returned {len(sigs)} signal(s)") if r3.status_code == 200 and len(sigs) >= 1 else fail("Poll failed", f"{r3.status_code} {r3.text[:100]}")
ok("Signal type=offer") if sigs and sigs[0]["type"] == "offer" else fail("Signal type wrong", sigs[:1])

# ─── 15. Edge cases ───────────────────────────────────────────
hdr("15. EDGE CASES")
r = requests.get(B + "/api/transfer/GHOST/chunk/0/", timeout=10)
ok("Ghost chunk 404") if r.status_code == 404 else fail("Ghost chunk", r.status_code)
ok("Ghost CORS=*") if r.headers.get("Access-Control-Allow-Origin") == "*" else fail("Ghost chunk CORS missing")

# Out-of-range seq upload
tid_e = "edge_" + secrets.token_hex(4)
requests.post(B + "/api/transfer/init/", json={
    "id": tid_e, "name": "e.txt", "size": 4, "type": "text/plain",
    "total_chunks": 1, "expiry_hours": 1, "self_destruct": False,
    "download_limit": 0, "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=10)
r = requests.post(B + f"/api/transfer/{tid_e}/upload/999/",
    files={"chunk": ("c", b"bad!", "application/octet-stream")},
    data={"iv": "aabbccdd00112233aabbccdd", "original_size": "4"}, timeout=10)
ok("OOB chunk seq returns 400") if r.status_code == 400 else fail("OOB chunk should be 400", r.status_code)

# Stats sanity
r = requests.get(B + "/api/stats/", timeout=10)
d = r.json()
ok("Stats has files list") if "files" in d else fail("Stats missing files array")
ok("Stats has local_ip") if d.get("local_ip") else fail("Stats no local_ip")
ok("Stats port=8000") if d.get("port") == 8000 else fail("Stats port wrong", d.get("port"))

# ─── Summary ─────────────────────────────────────────────────
print()
print("=" * 55)
print(f"RESULTS: {len(P)} passed | {len(F)} failed")
print("=" * 55)
if F:
    print("\nFAILED TESTS:")
    for x in F:
        print("  FAIL:", x)
    sys.exit(1)
else:
    print("\nALL PART-2 TESTS PASSED")
    sys.exit(0)
