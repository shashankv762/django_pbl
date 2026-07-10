"""Full Aegix feature test - runs synchronously, no blocking SSE calls."""
import sys, secrets, requests, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

B = "http://localhost:8000"
L = "http://192.168.31.192:8000"
P, F = [], []

def ok(m):  P.append(m);  print("  [PASS]", m)
def fail(m, d=""): F.append(m); print("  [FAIL]", m, ("-- " + str(d)) if d else "")
def hdr(t): print(f"\n=== {t} ===")

# 1. Health
hdr("1. HEALTH")
r = requests.get(B + "/", timeout=5)
ok("Frontend 200") if r.status_code == 200 else fail("Frontend", r.status_code)
ok("Has Aegix content") if "Aegix" in r.text else fail("No Aegix in HTML")

r = requests.get(B + "/api/stats/", timeout=5)
d = r.json()
ok(f"Stats OK, LAN IP={d['local_ip']}") if r.status_code == 200 else fail("Stats", r.status_code)
ok("Real LAN IP") if d["local_ip"] not in ("127.0.0.1", "localhost", "") else fail("Still loopback IP", d["local_ip"])

# 2. Full transfer lifecycle
hdr("2. TRANSFER LIFECYCLE")
tid = "lifecycle_" + secrets.token_hex(4)
data = b"Hello Aegix full test!"

r = requests.post(B + "/api/transfer/init/", json={
    "id": tid, "name": "test.txt", "size": len(data), "type": "text/plain",
    "total_chunks": 1, "expiry_hours": 1, "self_destruct": False,
    "download_limit": 0, "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=5)
ok("Init 200") if r.status_code == 200 else fail("Init", r.text)

r = requests.post(
    B + f"/api/transfer/{tid}/upload/0/",
    files={"chunk": ("chunk_0", data, "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": str(len(data))},
    timeout=5,
)
ok("Upload chunk 200") if r.status_code == 200 else fail("Upload", r.text)

r = requests.post(B + f"/api/transfer/{tid}/complete/", timeout=5)
ok("Complete 200") if r.status_code == 200 else fail("Complete", r.text)

r = requests.get(B + f"/api/transfer/{tid}/meta/", timeout=5)
d = r.json()
ok("Meta 200") if r.status_code == 200 else fail("Meta", r.status_code)
ok("is_complete=true") if d.get("is_complete") else fail("Not marked complete")
ok("CORS on meta = *") if r.headers.get("Access-Control-Allow-Origin") == "*" else fail("Meta CORS missing", r.headers.get("Access-Control-Allow-Origin"))
ok("1 chunk in meta") if len(d.get("chunks", [])) == 1 else fail("Chunk count wrong", d.get("chunks"))

# 3. Chunk download
hdr("3. CHUNK DOWNLOAD")
r = requests.get(B + f"/api/transfer/{tid}/chunk/0/", timeout=5)
ok("Chunk 200") if r.status_code == 200 else fail("Chunk dl", r.status_code)
ok("Bytes match exactly") if r.content == data else fail("Data mismatch", r.content[:50])
cl = r.headers.get("Content-Length", "")
ok(f"Content-Length={cl} exact (no chunked TE)") if cl == str(len(data)) else fail("Content-Length wrong", cl)
ok("No Transfer-Encoding: chunked") if "chunked" not in r.headers.get("Transfer-Encoding", "").lower() else fail("Has chunked TE - will break mobile AES-GCM")
ok("CORS on chunk = *") if r.headers.get("Access-Control-Allow-Origin") == "*" else fail("Chunk CORS missing")
ok("Cache-Control: no-store") if "no-store" in r.headers.get("Cache-Control", "") else fail("Cache-Control missing")
ok("X-Chunk-Seq header present") if r.headers.get("X-Chunk-Seq") else fail("X-Chunk-Seq missing")

# 4. LAN IP access
hdr("4. LAN IP ACCESS")
r = requests.get(L + f"/api/transfer/{tid}/chunk/0/", timeout=5)
ok(f"LAN chunk 200 ({L})") if r.status_code == 200 and r.content == data else fail("LAN chunk", r.status_code)
r = requests.get(L + f"/api/transfer/{tid}/meta/", timeout=5)
ok("LAN meta 200") if r.status_code == 200 else fail("LAN meta", r.status_code)
ok("LAN meta CORS = *") if r.headers.get("Access-Control-Allow-Origin") == "*" else fail("LAN meta CORS missing")

# 5. Error CORS
hdr("5. CORS ON ALL ERROR RESPONSES")
for path, label in [
    (f"/api/transfer/NOTEXIST/meta/", "not-found meta"),
    (f"/api/transfer/NOTEXIST/chunk/0/", "not-found chunk"),
]:
    r = requests.get(B + path, timeout=5)
    ok(f"{label}: {r.status_code} + CORS=*") if r.headers.get("Access-Control-Allow-Origin") == "*" else fail(f"{label} CORS missing", r.headers.get("Access-Control-Allow-Origin"))

# 6. Duplicate init rejected
hdr("6. DUPLICATE TRANSFER INIT REJECTED")
r2 = requests.post(B + "/api/transfer/init/", json={
    "id": tid, "name": "dup.txt", "size": 1, "type": "text/plain",
    "total_chunks": 1, "expiry_hours": 1, "self_destruct": False,
    "download_limit": 0, "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=5)
ok("Duplicate init rejected") if r2.status_code in (400, 409) else fail("Duplicate init should fail", r2.status_code)

# 7. Download limit
hdr("7. DOWNLOAD LIMIT (limit=2)")
lt = "limit_" + secrets.token_hex(4)
requests.post(B + "/api/transfer/init/", json={
    "id": lt, "name": "lim.txt", "size": 5, "type": "text/plain", "total_chunks": 1,
    "expiry_hours": 1, "self_destruct": False, "download_limit": 2,
    "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=5)
requests.post(B + f"/api/transfer/{lt}/upload/0/",
    files={"chunk": ("c", b"abcde", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "5"}, timeout=5)
requests.post(B + f"/api/transfer/{lt}/complete/", timeout=5)

r1 = requests.get(B + f"/api/transfer/{lt}/chunk/0/", timeout=5)
ok("DL1: 200 (count->1)") if r1.status_code == 200 else fail("DL1 failed", r1.status_code)
r2 = requests.get(B + f"/api/transfer/{lt}/chunk/0/", timeout=5)
ok("DL2: 200 (count->2)") if r2.status_code == 200 else fail("DL2 failed", r2.status_code)
r3 = requests.get(B + f"/api/transfer/{lt}/chunk/0/", timeout=5)
ok("DL3: 410 Gone (over limit)") if r3.status_code == 410 else fail("DL3 should be 410", r3.status_code)
ok("410 CORS = *") if r3.headers.get("Access-Control-Allow-Origin") == "*" else fail("410 CORS missing")
rm = requests.get(B + f"/api/transfer/{lt}/meta/", timeout=5)
ok("Meta 410 after limit") if rm.status_code == 410 else fail("Meta after limit should 410", rm.status_code)

# 8. Expiry
hdr("8. LINK EXPIRY")
et = "exp_" + secrets.token_hex(4)
requests.post(B + "/api/transfer/init/", json={
    "id": et, "name": "e.txt", "size": 4, "type": "text/plain", "total_chunks": 1,
    "expiry_hours": 0.000001, "self_destruct": False, "download_limit": 0,
    "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=5)
requests.post(B + f"/api/transfer/{et}/upload/0/",
    files={"chunk": ("c", b"expr", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "4"}, timeout=5)
requests.post(B + f"/api/transfer/{et}/complete/", timeout=5)
time.sleep(0.5)
re_ = requests.get(B + f"/api/transfer/{et}/meta/", timeout=5)
ok("Expired meta returns 410") if re_.status_code == 410 else fail("Expired meta should 410", re_.status_code)
ok("410 CORS = *") if re_.headers.get("Access-Control-Allow-Origin") == "*" else fail("Expiry CORS missing")
ok("Error says 'expired'") if "expir" in re_.text.lower() else fail("Expiry message unclear", re_.text)

# 9. Self-destruct
hdr("9. SELF-DESTRUCT")
st = "sd_" + secrets.token_hex(4)
requests.post(B + "/api/transfer/init/", json={
    "id": st, "name": "sd.txt", "size": 4, "type": "text/plain", "total_chunks": 1,
    "expiry_hours": 1, "self_destruct": True, "download_limit": 0,
    "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=5)
requests.post(B + f"/api/transfer/{st}/upload/0/",
    files={"chunk": ("c", b"BOOM", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "4"}, timeout=5)
requests.post(B + f"/api/transfer/{st}/complete/", timeout=5)
r1 = requests.get(B + f"/api/transfer/{st}/chunk/0/", timeout=5)
ok("SD DL1: 200, data=BOOM") if r1.status_code == 200 and r1.content == b"BOOM" else fail("SD DL1 wrong", (r1.status_code, r1.content[:20]))
r2 = requests.get(B + f"/api/transfer/{st}/chunk/0/", timeout=5)
ok(f"SD DL2: {r2.status_code} (wiped)") if r2.status_code in (404, 410) else fail("SD DL2 should fail", r2.status_code)

# 10. Password transfer
hdr("10. PASSWORD-PROTECTED TRANSFER")
pt = "pwd_" + secrets.token_hex(4)
fs, fwi, fwk = secrets.token_hex(16), secrets.token_hex(12), secrets.token_hex(32)
requests.post(B + "/api/transfer/init/", json={
    "id": pt, "name": "p.txt", "size": 6, "type": "text/plain", "total_chunks": 1,
    "expiry_hours": 1, "self_destruct": False, "download_limit": 0,
    "salt": fs, "wrap_iv": fwi, "wrapped_key": fwk,
}, timeout=5)
requests.post(B + f"/api/transfer/{pt}/upload/0/",
    files={"chunk": ("c", b"secret", "application/octet-stream")},
    data={"iv": secrets.token_hex(12), "original_size": "6"}, timeout=5)
requests.post(B + f"/api/transfer/{pt}/complete/", timeout=5)
r = requests.get(B + f"/api/transfer/{pt}/meta/", timeout=5)
d = r.json()
ok("PWD meta 200") if r.status_code == 200 else fail("PWD meta", r.status_code)
ok("salt round-tripped") if d.get("salt") == fs else fail("salt wrong", d.get("salt"))
ok("wrap_iv round-tripped") if d.get("wrap_iv") == fwi else fail("wrap_iv wrong")
ok("wrapped_key round-tripped") if d.get("wrapped_key") == fwk else fail("wrapped_key wrong")

# 11. Multi-chunk
hdr("11. MULTI-CHUNK TRANSFER")
mct = "mc_" + secrets.token_hex(4)
ca, cb = b"A" * 1024, b"B" * 512
requests.post(B + "/api/transfer/init/", json={
    "id": mct, "name": "mc.bin", "size": len(ca) + len(cb), "type": "application/octet-stream",
    "total_chunks": 2, "expiry_hours": 1, "self_destruct": False, "download_limit": 0,
    "salt": "", "wrap_iv": "", "wrapped_key": "",
}, timeout=5)
for i, c in enumerate([ca, cb]):
    requests.post(B + f"/api/transfer/{mct}/upload/{i}/",
        files={"chunk": (f"c{i}", c, "application/octet-stream")},
        data={"iv": secrets.token_hex(12), "original_size": str(len(c))}, timeout=5)
requests.post(B + f"/api/transfer/{mct}/complete/", timeout=5)
for i, c in enumerate([ca, cb]):
    r = requests.get(B + f"/api/transfer/{mct}/chunk/{i}/", timeout=5)
    cl = r.headers.get("Content-Length", "")
    if r.status_code == 200 and r.content == c and cl == str(len(c)):
        ok(f"Multi chunk {i}: {len(c)}B, CL={cl} correct")
    else:
        fail(f"Multi chunk {i}", f"status={r.status_code} cl={cl} expected={len(c)}")

# 12. LAN discovery
hdr("12. LAN DISCOVERY")
# Note: frontend sends 'id' not 'peer_id' — our fix accepts both
r = requests.post(B + "/api/lan/announce/", json={"id": "testpeer", "name": "TestPC", "ip": "192.168.1.99"}, timeout=5)
ok("LAN announce 200") if r.status_code == 200 else fail("LAN announce", f"{r.status_code} {r.text}")
r = requests.get(B + "/api/lan/devices/", timeout=5)
d = r.json()
ok(f"LAN devices 200 ({len(d.get('peers', []))} peers)") if r.status_code == 200 else fail("LAN devices", r.status_code)
ok("server_ip in LAN devices") if d.get("server_ip") else fail("server_ip missing")

# 13. WebRTC
# 13. WEBRTC SIGNALING
hdr("13. WEBRTC SIGNALING")
r = requests.post(B + "/api/webrtc/room/", timeout=5)
ok("WebRTC room created") if r.status_code == 200 else fail("WebRTC room", r.status_code)
rd = r.json()
rid = rd.get("room_id") or rd.get("id")
# Signal must use 'initiator' or 'responder' as sender (validated by the view)
r2 = requests.post(B + f"/api/webrtc/{rid}/signal/", json={
    "sender": "initiator", "type": "offer", "payload": {"sdp": "v=0"}}, timeout=5)
ok("Signal posted") if r2.status_code == 200 else fail("Signal post", r2.text)
# Non-blocking poll — peer='responder' reads signals from 'initiator'
r3 = requests.get(B + f"/api/webrtc/{rid}/poll/?after=0&peer=responder", timeout=5)
d3 = r3.json()
sigs = d3.get("signals", [])
ok(f"Signal polled back ({len(sigs)} signal(s))") if r3.status_code == 200 and len(sigs) >= 1 else fail("Poll", (r3.status_code, r3.text[:200]))

# 14. Library / stats
hdr("14. LIBRARY / STATS")
r = requests.get(B + "/api/stats/", timeout=5)
d = r.json()
ok(f"Stats: {d.get('files_encrypted_count')} files, {d.get('total_encrypted_bytes')} bytes") if r.status_code == 200 else fail("Stats", r.status_code)
ok("files array present") if "files" in d else fail("files missing from stats")

# 15. Out-of-range chunk rejected
hdr("15. VALIDATION / EDGE CASES")
r = requests.post(B + f"/api/transfer/{tid}/upload/999/",
    files={"chunk": ("c", b"bad", "application/octet-stream")},
    data={"iv": "aabb", "original_size": "3"}, timeout=5)
ok("OOB chunk seq rejected 400") if r.status_code == 400 else fail("OOB chunk should be 400", r.status_code)

# Check chunk on non-existent transfer
r = requests.get(B + "/api/transfer/GHOST/chunk/0/", timeout=5)
ok("Ghost chunk 404") if r.status_code == 404 else fail("Ghost chunk should be 404", r.status_code)
ok("Ghost chunk CORS") if r.headers.get("Access-Control-Allow-Origin") == "*" else fail("Ghost chunk CORS missing")

# SUMMARY
total = len(P) + len(F)
print(f"\n{'='*55}")
print(f"  RESULTS: {len(P)}/{total} passed  |  {len(F)} failed")
print("=" * 55)
if F:
    print("\nFAILED TESTS:")
    for x in F:
        print("  FAIL:", x)
    sys.exit(1)
else:
    print("\nALL TESTS PASSED")
    sys.exit(0)
