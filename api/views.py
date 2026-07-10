"""
Aegix Share — API Views
Implements Wormhole-style chunked streaming:
  • Sender uploads file in 512 KB encrypted chunks one at a time
  • Server stores each chunk as it arrives
  • Receiver opens SSE stream and downloads/decrypts each chunk in real-time
  • Transfer is a streaming pipe — receiver can start before sender finishes
"""
import os
import json
import time
import socket
import threading
from datetime import datetime, timedelta as dt_timedelta

from django.db.models import Sum, F
from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta

from .models import Transfer, TransferChunk, WebRTCRoom, WebRTCSignal


# ─── LAN Peer Registry ────────────────────────────────────────────────────────
# Thread-safe in-memory registry. Each device POSTs to /api/lan/announce/
# every 3 s; entries older than 12 s are pruned automatically.
_lan_lock  = threading.Lock()
_lan_peers: dict = {}   # peer_id → {id, name, ip, last_seen: datetime}


def _score_ip(ip: str) -> int:
    """
    Score a candidate LAN IP for suitability as the host's public address.
    Higher score = more likely to be a real physical-adapter IP.

    Rules:
      - Loopback / link-local → excluded (score -999)
      - Private ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x) → preferred
      - IPs ending in .1 are typically virtual gateway addresses assigned by
        VMware Host-Only / NAT adapters — score them lower so that a real
        DHCP-assigned IP (e.g. .192) wins.
    """
    if ip.startswith('127.') or ip.startswith('169.254.'):
        return -999
    score = 0
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
        score += 10
    if ip.endswith('.1'):
        score -= 5
    return score


def _get_local_ip() -> str:
    """
    Return the best LAN IP for this machine.

    Strategy (most-reliable first):
      1. Collect all IPs bound to this hostname via gethostbyname_ex.
      2. Score each IP (prefer non-.1 private addresses).
      3. Fall back to the UDP-route trick for machines where gethostbyname_ex
         only returns 127.0.0.1 (some minimal Docker/CI environments).
      4. Last resort: 127.0.0.1.
    """
    candidates: list[tuple[int, str]] = []   # (score, ip)

    # Strategy 1 — enumerate all IPs bound to this hostname
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        for addr in addrs:
            s = _score_ip(addr)
            if s > -900:   # exclude loopback / link-local
                candidates.append((s, addr))
    except Exception:
        pass

    # Strategy 2 — UDP route trick (picks the OS default-route interface)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0)
        sock.connect(('8.8.8.8', 80))
        route_ip = sock.getsockname()[0]
        sock.close()
        s = _score_ip(route_ip)
        if s > -900:
            candidates.append((s, route_ip))
    except Exception:
        pass

    if candidates:
        candidates.sort(key=lambda x: (-x[0], x[1]))
        return candidates[0][1]

    return '127.0.0.1'


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _json_error(message, status=400):
    resp = JsonResponse({'error': message}, status=status)
    resp['Access-Control-Allow-Origin'] = '*'
    return resp


def _cleanup_transfer(transfer):
    """Delete all chunk files on disk + DB records, then delete transfer."""
    for chunk in transfer.chunks.all():
        try:
            if chunk.data and chunk.data.name:
                path = chunk.data.path
                if os.path.exists(path):
                    os.remove(path)
        except Exception:
            pass
        chunk.delete()
    transfer.delete()


def _get_active_transfer(transfer_id, check_limit=True):
    """
    Fetch a transfer by id; auto-expire and return None if expired.
    Returns (transfer, error_response) — one of them is always None.
    When check_limit=False, skips the download limit check (used during
    chunk uploads and initial chunk downloads — the gate is enforced
    atomically at seq==0 in download_chunk).
    """
    try:
        t = Transfer.objects.get(id=transfer_id)
    except Transfer.DoesNotExist:
        return None, _json_error('Transfer not found', 404)

    if t.is_expired():
        _cleanup_transfer(t)
        return None, _json_error('Transfer link has expired', 410)

    # Only block (but don't delete) if limit already exceeded before download starts
    if check_limit and t.download_limit > 0 and t.download_count >= t.download_limit:
        return None, _json_error('Download limit reached', 410)

    return t, None


# ─── 1. Init Transfer ─────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST', 'OPTIONS'])
def init_transfer(request):
    """
    Sender calls this once to register a transfer session before uploading chunks.
    Body (JSON or form): id, name, size, type, total_chunks,
                         expiry_hours, self_destruct, download_limit,
                         salt, wrap_iv, wrapped_key (optional, password-protected)
    """
    if request.method == 'OPTIONS':
        return HttpResponse(status=200)

    try:
        # Accept both JSON and form-data
        if request.content_type and 'application/json' in request.content_type:
            body = json.loads(request.body)
            get = body.get
        else:
            get = request.POST.get

        transfer_id  = get('id')
        name         = get('name', 'unnamed')
        size         = int(get('size', 0))
        file_type    = get('type', '')
        total_chunks = int(get('total_chunks', 1))
        expiry_hours = float(get('expiry_hours', 24))
        self_destruct  = str(get('self_destruct', 'false')).lower() == 'true'
        download_limit = int(get('download_limit', 0))   # 0 = unlimited by default
        salt        = get('salt', '') or ''
        wrap_iv     = get('wrap_iv', '') or ''
        wrapped_key = get('wrapped_key', '') or ''

        if not transfer_id:
            return _json_error('Missing id')
        if Transfer.objects.filter(id=transfer_id).exists():
            return _json_error('Transfer ID already exists', 409)

        expires_at = timezone.now() + timedelta(hours=expiry_hours)

        transfer = Transfer.objects.create(
            id=transfer_id,
            name=name,
            size=size,
            type=file_type,
            total_chunks=total_chunks,
            uploaded_chunks=0,
            is_complete=False,
            salt=salt or None,
            wrap_iv=wrap_iv or None,
            wrapped_key=wrapped_key or None,
            expires_at=expires_at,
            self_destruct=self_destruct,
            download_limit=download_limit,
        )

        return JsonResponse({
            'status': 'ok',
            'id': transfer.id,
            'total_chunks': total_chunks,
            'expires_at': expires_at.isoformat(),
        })

    except (ValueError, KeyError) as e:
        return _json_error(f'Invalid field: {e}')
    except Exception as e:
        return _json_error(str(e), 500)


# ─── 2. Upload Chunk ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST', 'OPTIONS'])
def upload_chunk(request, transfer_id, seq):
    """
    Sender uploads one encrypted chunk.
    Form fields: chunk (file), iv (hex string), original_size (int)

    NOTE: check_limit=False — the download limit applies to *receivers*, not
    the sender. A sender should never be blocked from uploading their own file.
    """
    if request.method == 'OPTIONS':
        return HttpResponse(status=200)

    # Pass check_limit=False: download limit must not block the uploader
    transfer, err = _get_active_transfer(transfer_id, check_limit=False)
    if err:
        return err

    if transfer.is_complete:
        return _json_error('Transfer already marked complete', 400)

    seq = int(seq)
    if seq < 0 or seq >= transfer.total_chunks:
        return _json_error(f'Chunk seq {seq} out of range [0, {transfer.total_chunks})')

    if TransferChunk.objects.filter(transfer=transfer, seq=seq).exists():
        return _json_error(f'Chunk {seq} already uploaded', 409)

    chunk_file = request.FILES.get('chunk')
    iv = request.POST.get('iv', '')
    original_size = int(request.POST.get('original_size', 0))

    if not chunk_file:
        return _json_error('Missing chunk file')
    if not iv:
        return _json_error('Missing chunk IV')

    TransferChunk.objects.create(
        transfer=transfer,
        seq=seq,
        iv=iv,
        data=chunk_file,
        original_size=original_size,
    )

    # Atomically increment uploaded_chunks to avoid race conditions
    # when multiple chunks are uploaded concurrently.
    Transfer.objects.filter(id=transfer_id).update(
        uploaded_chunks=F('uploaded_chunks') + 1
    )
    transfer.refresh_from_db(fields=['uploaded_chunks'])

    return JsonResponse({
        'status': 'ok',
        'seq': seq,
        'uploaded_chunks': transfer.uploaded_chunks,
        'total_chunks': transfer.total_chunks,
    })


# ─── 3. Complete Transfer ─────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST', 'OPTIONS'])
def complete_transfer(request, transfer_id):
    """Sender calls this when all chunks have been uploaded."""
    if request.method == 'OPTIONS':
        return HttpResponse(status=200)

    transfer, err = _get_active_transfer(transfer_id, check_limit=False)
    if err:
        return err

    transfer.is_complete = True
    transfer.save(update_fields=['is_complete'])

    return JsonResponse({
        'status': 'ok',
        'total_chunks': transfer.total_chunks,
        'uploaded_chunks': transfer.uploaded_chunks,
    })


# ─── 4. Transfer Metadata ─────────────────────────────────────────────────────

def transfer_meta(request, transfer_id):
    """
    Returns transfer metadata including which chunk IVs are available.
    Receiver polls this (or uses SSE) to discover ready chunks.
    Uses check_limit=False so that metadata remains readable even after the
    download limit is reached — receivers see file info and get a clear error
    only when they attempt the actual chunk download (enforced at seq==0).
    """
    # check_limit=False: the download limit is enforced atomically in download_chunk
    # at seq==0.  Metadata must remain readable even after the limit is reached
    # so receivers can see file info (name, size, expiry) and get a clear error
    # message when they attempt the actual chunk download.
    transfer, err = _get_active_transfer(transfer_id, check_limit=False)
    if err:
        return err

    chunks = list(transfer.chunks.values('seq', 'iv', 'original_size'))

    response = JsonResponse({
        'id': transfer.id,
        'name': transfer.name,
        'size': transfer.size,
        'type': transfer.type,
        'total_chunks': transfer.total_chunks,
        'uploaded_chunks': transfer.uploaded_chunks,
        'is_complete': transfer.is_complete,
        'chunks': chunks,   # [{seq, iv, original_size}, ...]
        'salt': transfer.salt or '',
        'wrap_iv': transfer.wrap_iv or '',
        'wrapped_key': transfer.wrapped_key or '',
        'self_destruct': transfer.self_destruct,
        'download_limit': transfer.download_limit,
        'download_count': transfer.download_count,
        'expires_at': transfer.expires_at.isoformat(),
    })
    response['Access-Control-Allow-Origin'] = '*'
    return response


# ─── 5. Download Chunk ────────────────────────────────────────────────────────

def download_chunk(request, transfer_id, seq):
    """
    Serve one encrypted chunk to the receiver as a plain in-memory response.

    IMPORTANT: we use HttpResponse (not FileResponse / StreamingHttpResponse)
    because Django's dev-server sends FileResponse with chunked transfer
    encoding when Content-Length is unknown, and many mobile browsers
    (Safari iOS, Chrome Android) fail to reassemble the chunks before passing
    the body to fetch().arrayBuffer() — resulting in a truncated ArrayBuffer
    that fails AES-GCM decryption silently.  Reading the whole chunk file into
    memory first guarantees a single-shot, Content-Length-bearing response that
    every browser handles correctly.
    """
    # check_limit=False: new-download gate is enforced at seq==0 below;
    # chunks 1..N of an in-progress download must never be blocked mid-stream.
    transfer, err = _get_active_transfer(transfer_id, check_limit=False)
    if err:
        return err

    seq = int(seq)
    try:
        chunk = TransferChunk.objects.get(transfer=transfer, seq=seq)
    except TransferChunk.DoesNotExist:
        resp = HttpResponse(f'Chunk {seq} not yet available', status=404)
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    file_path = chunk.data.path
    if not os.path.exists(file_path):
        chunk.delete()
        resp = HttpResponse('Chunk file missing from storage', status=404)
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    is_first_chunk = (seq == 0)
    is_last_chunk  = (seq == transfer.total_chunks - 1)

    # ── Download-limit gate (atomic, enforced at the first chunk only) ─────────
    if is_first_chunk:
        if transfer.download_limit > 0:
            updated = Transfer.objects.filter(
                id=transfer_id,
                download_count__lt=transfer.download_limit,
            ).update(download_count=F('download_count') + 1)
            if updated == 0:
                # Limit already reached — deny without touching any files
                return _json_error('Download limit reached', 410)
        else:
            Transfer.objects.filter(id=transfer_id).update(
                download_count=F('download_count') + 1,
            )
        transfer.refresh_from_db()

    # ── Read chunk into memory ─────────────────────────────────────────────────
    with open(file_path, 'rb') as fh:
        data = fh.read()

    # ── Self-destruct: wipe transfer after last chunk is safely in memory ──────
    if transfer.self_destruct and is_last_chunk:
        try:
            _cleanup_transfer(transfer)
        except Exception:
            pass   # never fail the response because of cleanup

    resp = HttpResponse(data, content_type='application/octet-stream')
    resp['Content-Length']              = str(len(data))
    resp['X-Chunk-Seq']                 = str(seq)
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Cache-Control']               = 'no-store, no-cache, must-revalidate'
    resp['Pragma']                      = 'no-cache'
    return resp


# ─── 6. SSE — Real-time chunk notification stream ─────────────────────────────

def chunk_stream(request, transfer_id):
    """
    Server-Sent Events endpoint.
    Receiver connects here; server pushes a 'chunk_ready' event each time
    a new chunk is uploaded. Also pushes 'complete' when sender finishes.
    Receiver immediately fetches each chunk from download_chunk on that event.

    This is the core of the Wormhole-style pipe: receiver is always
    downloading the previous chunk while the sender uploads the next one.
    """
    try:
        transfer = Transfer.objects.get(id=transfer_id)
    except Transfer.DoesNotExist:
        def _err():
            yield f"data: {json.dumps({'type': 'error', 'message': 'Transfer not found'})}\n\n"
        return StreamingHttpResponse(_err(), content_type='text/event-stream')

    def _event_generator():
        notified_seqs = set()
        max_wait = 600   # stop after 10 minutes of inactivity
        waited = 0

        # Send transfer metadata first so receiver can show file info immediately
        yield f"data: {json.dumps({'type': 'meta', 'name': transfer.name, 'size': transfer.size, 'total_chunks': transfer.total_chunks})}\n\n"

        while waited < max_wait:
            # Re-query available chunks
            available = list(
                TransferChunk.objects.filter(transfer=transfer)
                .values('seq', 'iv', 'original_size')
                .order_by('seq')
            )

            new_chunks = [c for c in available if c['seq'] not in notified_seqs]

            for chunk in new_chunks:
                notified_seqs.add(chunk['seq'])
                yield f"data: {json.dumps({'type': 'chunk_ready', 'seq': chunk['seq'], 'iv': chunk['iv'], 'original_size': chunk['original_size']})}\n\n"
                waited = 0   # reset inactivity timer when we see activity

            # Refresh transfer state
            try:
                transfer.refresh_from_db()
            except Exception:
                break

            if transfer.is_complete and len(notified_seqs) >= transfer.total_chunks:
                yield f"data: {json.dumps({'type': 'complete', 'total_chunks': transfer.total_chunks})}\n\n"
                break

            if transfer.is_expired():
                yield f"data: {json.dumps({'type': 'expired'})}\n\n"
                break

            time.sleep(0.75)
            waited += 0.75

        yield f"data: {json.dumps({'type': 'end'})}\n\n"

    response = StreamingHttpResponse(_event_generator(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'       # disable nginx buffering
    response['Access-Control-Allow-Origin'] = '*'
    return response


# ─── 7. Stats ─────────────────────────────────────────────────────────────────

def get_stats(request):
    """
    Library view stats — also triggers cleanup of expired transfers.
    Uses DB aggregation (not Python loops) for O(1) byte count.
    """
    # Bulk-delete all expired transfers in one query instead of row-by-row Python loop
    expired_ids = list(
        Transfer.objects.filter(expires_at__lt=timezone.now()).values_list('id', flat=True)
    )
    for t_id in expired_ids:
        try:
            t = Transfer.objects.get(id=t_id)
            _cleanup_transfer(t)
        except Transfer.DoesNotExist:
            pass

    queryset = Transfer.objects.all()
    total = queryset.count()

    # Use DB aggregation — avoids loading every transfer into Python memory
    agg = queryset.aggregate(total_bytes=Sum('size'))
    total_bytes = agg['total_bytes'] or 0

    files_list = list(queryset.values(
        'id', 'name', 'size', 'type', 'is_complete',
        'total_chunks', 'uploaded_chunks', 'expires_at',
        'download_count', 'download_limit',
    ))
    # Convert expires_at datetime to ISO string for JSON serialisation
    for f in files_list:
        if hasattr(f['expires_at'], 'isoformat'):
            f['expires_at'] = f['expires_at'].isoformat()

    local_ip = _get_local_ip()

    resp = JsonResponse({
        'files_encrypted_count': total,
        'active_links_count': total,
        'total_encrypted_bytes': total_bytes,
        'files': files_list,
        'local_ip': local_ip,
        'port': 8000,
    })
    resp['Access-Control-Allow-Origin'] = '*'
    return resp


# ─── 7a. Dedicated LAN IP endpoint ───────────────────────────────────────────

def get_lan_ip(request):
    """
    GET /api/lan/ip/

    Returns all candidate LAN IPs ranked best-first. The frontend calls this
    to build QR-code URLs that are reachable from phones on the same WiFi.

    Response:
        {
          "best": "192.168.31.192",          # top-ranked (non-virtual) IP
          "all":  ["192.168.31.192", ...],   # full ranked list
          "port": 8000
        }

    Scoring: private non-.1 addresses rank highest; virtual-gateway .1 addresses
    rank lowest. See _score_ip() for the exact logic.
    """
    candidates: list[tuple[int, str]] = []

    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        for addr in addrs:
            s = _score_ip(addr)
            if s > -900:
                candidates.append((s, addr))
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0)
        sock.connect(('8.8.8.8', 80))
        route_ip = sock.getsockname()[0]
        sock.close()
        s = _score_ip(route_ip)
        if s > -900 and route_ip not in [ip for _, ip in candidates]:
            candidates.append((s, route_ip))
    except Exception:
        pass

    candidates.sort(key=lambda x: (-x[0], x[1]))
    ranked = [ip for _, ip in candidates]
    best = ranked[0] if ranked else '127.0.0.1'

    resp = JsonResponse({'best': best, 'all': ranked, 'port': 8000})
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Cache-Control'] = 'no-store'
    return resp


# ─── 7b. LAN Peer Discovery ───────────────────────────────────────────────────

@csrf_exempt
def lan_announce(request):
    """
    POST  /api/lan/announce/  — register / heartbeat this device.
    DELETE /api/lan/announce/ — deregister this device.
    Body JSON: {peer_id, name}
    Response: {ok: true, ip: "<client LAN IP>", server_ip: "<server LAN IP>"}
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, Exception):
            return _json_error('Invalid JSON body')

        # Accept both 'peer_id' (canonical) and 'id' (what the frontend sends)
        peer_id = str(data.get('peer_id') or data.get('id', '')).strip()[:64]
        name    = str(data.get('name', 'Unknown')).strip()[:100]
        if not peer_id:
            return _json_error('peer_id or id required')

        # Prefer X-Forwarded-For when behind a proxy, else use REMOTE_ADDR
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        client_ip = forwarded.split(',')[0].strip() if forwarded else \
                    request.META.get('REMOTE_ADDR', '127.0.0.1')
        # Filter out loopback — use server LAN IP as fallback for same-machine tabs
        if client_ip in ('127.0.0.1', '::1', ''):
            client_ip = _get_local_ip()

        now = datetime.now()
        with _lan_lock:
            _lan_peers[peer_id] = {
                'id': peer_id, 'name': name,
                'ip': client_ip, 'last_seen': now,
            }
            # Prune stale entries (older than 12 s) while we hold the lock
            cutoff = now - dt_timedelta(seconds=12)
            stale  = [k for k, v in _lan_peers.items() if v['last_seen'] < cutoff]
            for k in stale:
                del _lan_peers[k]

        resp = JsonResponse({'ok': True, 'ip': client_ip, 'server_ip': _get_local_ip()})
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    elif request.method == 'DELETE':
        try:
            data = json.loads(request.body)
            peer_id = str(data.get('peer_id', '')).strip()[:64]
        except Exception:
            return JsonResponse({'ok': True})
        with _lan_lock:
            _lan_peers.pop(peer_id, None)
        resp = JsonResponse({'ok': True})
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    elif request.method == 'OPTIONS':
        resp = HttpResponse(status=200)
        resp['Access-Control-Allow-Origin'] = '*'
        resp['Access-Control-Allow-Methods'] = 'POST, DELETE, OPTIONS'
        resp['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    return _json_error('Method not allowed', 405)


@csrf_exempt
def lan_devices(request):
    """
    GET /api/lan/devices/  — list all active LAN peers (seen in last 10 s).
    Response: {peers: [{id, name, ip}], server_ip}
    """
    if request.method == 'OPTIONS':
        resp = HttpResponse(status=200)
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    if request.method != 'GET':
        return _json_error('Method not allowed', 405)

    cutoff = datetime.now() - dt_timedelta(seconds=10)
    with _lan_lock:
        peers = [
            {'id': v['id'], 'name': v['name'], 'ip': v['ip']}
            for v in _lan_peers.values()
            if v['last_seen'] > cutoff
        ]

    resp = JsonResponse({'peers': peers, 'server_ip': _get_local_ip()})
    resp['Access-Control-Allow-Origin'] = '*'
    return resp


# ─── 8. WebRTC Signaling ──────────────────────────────────────────────────────

def _get_webrtc_room(room_id):
    """Fetch a WebRTC room, auto-expire if past expiry."""
    try:
        r = WebRTCRoom.objects.get(id=room_id)
    except WebRTCRoom.DoesNotExist:
        return None, _json_error('Room not found', 404)
    if r.is_expired():
        r.delete()
        return None, _json_error('Room has expired', 410)
    return r, None


@csrf_exempt
@require_http_methods(['POST', 'OPTIONS'])
def create_webrtc_room(request):
    """
    Create a new WebRTC signaling room.
    Returns: {room_id, expires_at}
    Automatically cleans up any expired rooms.
    """
    if request.method == 'OPTIONS':
        return HttpResponse(status=200)

    # Cleanup stale rooms opportunistically
    WebRTCRoom.objects.filter(expires_at__lt=timezone.now()).delete()

    room_id = os.urandom(8).hex()   # 16-char hex, cryptographically random
    expires_at = timezone.now() + timedelta(minutes=10)
    WebRTCRoom.objects.create(id=room_id, expires_at=expires_at)

    resp = JsonResponse({'room_id': room_id, 'expires_at': expires_at.isoformat()})
    resp['Access-Control-Allow-Origin'] = '*'
    return resp


@csrf_exempt
@require_http_methods(['POST', 'OPTIONS'])
def post_webrtc_signal(request, room_id):
    """
    Post a signaling message (offer/answer/ice-candidate/bye) to the room.
    Body JSON: {sender: 'initiator'|'responder', type: str, payload: any}
    """
    if request.method == 'OPTIONS':
        return HttpResponse(status=200)

    room, err = _get_webrtc_room(room_id)
    if err:
        return err

    try:
        body = json.loads(request.body)
        sender = body['sender']      # 'initiator' | 'responder'
        signal_type = body['type']   # 'offer' | 'answer' | 'ice-candidate' | 'bye'
        payload = body['payload']    # SDP dict or ICE candidate dict
    except (KeyError, json.JSONDecodeError) as exc:
        return _json_error(f'Invalid signal body: {exc}')

    if sender not in ('initiator', 'responder'):
        return _json_error("sender must be 'initiator' or 'responder'")
    if signal_type not in ('offer', 'answer', 'ice-candidate', 'bye'):
        return _json_error(f"Unknown signal type: {signal_type}")

    signal = WebRTCSignal.objects.create(
        room=room, sender=sender, type=signal_type, payload=payload,
    )
    resp = JsonResponse({'status': 'ok', 'signal_id': signal.id})
    resp['Access-Control-Allow-Origin'] = '*'
    return resp


def webrtc_signal_poll(request, room_id):
    """
    Non-blocking REST poll for WebRTC signals.
    GET /api/webrtc/<room>/poll/?after=<signal_id>&peer=<initiator|responder>
    Returns immediately with all signals newer than `after` — no long-polling.
    Used by mobile clients that cannot maintain SSE connections, and for testing.
    """
    my_peer    = request.GET.get('peer', 'responder')
    other_peer = 'initiator' if my_peer == 'responder' else 'responder'
    after_id   = int(request.GET.get('after', 0))

    room, err = _get_webrtc_room(room_id)
    if err:
        return err

    signals = list(
        WebRTCSignal.objects
        .filter(room_id=room_id, sender=other_peer, id__gt=after_id)
        .order_by('id')
        .values('id', 'sender', 'type', 'payload')
    )

    resp = JsonResponse({'signals': signals, 'room_id': room_id})
    resp['Access-Control-Allow-Origin'] = '*'
    return resp


def webrtc_signal_stream(request, room_id):
    """
    SSE stream for WebRTC signaling.
    ?peer=initiator  → pushes signals FROM 'responder'
    ?peer=responder  → pushes signals FROM 'initiator'
    ?after=<signal_id>  → resume from this signal ID (default 0)

    Mirrors the chunk_stream pattern used for file transfers.
    """
    my_peer   = request.GET.get('peer',  'responder')  # who am I
    other_peer = 'initiator' if my_peer == 'responder' else 'responder'
    last_id   = int(request.GET.get('after', 0))

    def _generator():
        nonlocal last_id
        waited   = 0
        max_wait = 600   # 10 minutes

        while waited < max_wait:
            try:
                room = WebRTCRoom.objects.get(id=room_id)
                if room.is_expired():
                    yield f"data: {json.dumps({'type': 'expired'})}\n\n"
                    break
            except WebRTCRoom.DoesNotExist:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Room not found'})}\n\n"
                break

            new_signals = WebRTCSignal.objects.filter(
                room_id=room_id,
                sender=other_peer,
                id__gt=last_id,
            ).order_by('id')

            for sig in new_signals:
                last_id = sig.id
                waited  = 0   # reset inactivity timer on activity
                yield f"data: {json.dumps({'type': sig.type, 'payload': sig.payload, 'signal_id': sig.id})}\n\n"
                if sig.type == 'bye':
                    yield f"data: {json.dumps({'type': 'end'})}\n\n"
                    return

            time.sleep(0.5)
            waited += 0.5

        yield f"data: {json.dumps({'type': 'end'})}\n\n"

    response = StreamingHttpResponse(_generator(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    response['Access-Control-Allow-Origin'] = '*'
    return response
