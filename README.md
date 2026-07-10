# Aegix Share

> Zero-knowledge, end-to-end encrypted file sharing over LAN, WebRTC P2P, and Web Bluetooth. No cloud. No accounts.

---

## What It Does

Aegix Share encrypts every file in the browser using **AES-256-GCM** before it leaves your machine. The decryption key is embedded in the URL fragment (`#key=...`) — the server only ever stores ciphertext. Files can be shared over a local network via QR code, streamed directly device-to-device over WebRTC, or delivered via Bluetooth GATT, all without an internet connection.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Vite 6 |
| Backend | Django 6 + SQLite |
| Encryption (HTTPS) | Web Crypto API — AES-256-GCM + PBKDF2-SHA-256 |
| Encryption (HTTP LAN) | `@noble/ciphers` + `@noble/hashes` — lazy-loaded fallback |
| Real-time | Server-Sent Events, WebRTC DataChannels |
| Bluetooth | Web Bluetooth API (GATT) |
| Styling | Tailwind CSS v3 |

---

## Feature Overview

| Feature | Detail |
|---------|--------|
| **Send / Receive** | Chunked upload with per-chunk AES-256-GCM encryption. Configurable expiry, download limit, self-destruct, and password protection. |
| **LAN / QR Share** | Scan a QR from any device on the same WiFi. Works fully offline. |
| **WebRTC P2P** | Direct streaming via DataChannels — file never touches the server. |
| **Web Bluetooth** | Delivers download URLs via GATT characteristic `0xae92`. |
| **File Library** | Browse, re-share, or track all active transfers. |
| **Settings** | 7-section panel — transfer defaults, appearance, security, network, notifications, data management, about. All settings persist in `localStorage`. |
| **HTTP LAN Compat** | `@noble/ciphers` fallback kicks in when `window.crypto.subtle` is unavailable (plain-HTTP LAN IP). Bit-identical output to Web Crypto API. |

---

## Settings Reference

### Transfer Defaults
| Setting | Default | Wired To |
|---------|---------|---------|
| Default link expiry | 24 h | `linkExpiry` state |
| Default download limit | Unlimited | `downloadLimit` state |
| Chunk size | 512 KB | Upload encryption loop |
| Self-destruct | Off | `selfDestruct` state |
| Require password | Off | `requirePassword` state |
| Auto-show QR on upload | Off | Opens QR modal on complete |

### Appearance
| Setting | Default | Effect |
|---------|---------|--------|
| Accent color | Indigo | CSS `hue-rotate()` on `#aegix-app-root` — shifts all saturated colors |
| Display density | Normal | `font-size` on `<html>` — compact 14 px / normal 16 px / comfortable 18 px |
| Reduce motion | Off | Injects CSS disabling all animations and transitions |

### Security & Privacy
| Setting | Default | Effect |
|---------|---------|--------|
| History retention | Forever | Prune old transfers at 7 / 30 / 90 days |
| Show key in history | Off | Reveals AES key in transfer cards |
| Close modal on copy | Off | Auto-dismisses link modal on copy |

### Network
| Setting | Default | Effect |
|---------|---------|--------|
| LAN discoverable | On | Heartbeat to `/api/lan/announce/` |
| Device display name | `Aegix·<ID>` | Name shown in LAN peer list |

### Notifications
| Setting | Default | Effect |
|---------|---------|--------|
| Upload complete alert | On | Toast after upload |
| Download ready alert | On | Toast after decryption |
| LAN device found alert | On | Toast on new BroadcastChannel peer |
| Sound effects | Off | AudioContext beep on complete |

### Data Management
Export / import settings as JSON, clear transfer history, reset all settings to defaults.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/transfer/init/` | Register transfer |
| `POST` | `/api/transfer/<id>/upload/<seq>/` | Upload encrypted chunk |
| `POST` | `/api/transfer/<id>/complete/` | Finalize upload |
| `GET` | `/api/transfer/<id>/meta/` | Metadata (enforces limits + expiry) |
| `GET` | `/api/transfer/<id>/chunk/<seq>/` | Download chunk |
| `GET` | `/api/stats/` | Library stats + LAN IP |
| `GET` | `/api/lan/ip/` | Best LAN IP detection |
| `POST` | `/api/lan/announce/` | LAN peer heartbeat |
| `GET` | `/api/lan/devices/` | Active LAN peers |
| `POST` | `/api/webrtc/room/` | Create P2P signaling room |
| `GET` | `/api/webrtc/<room>/stream/` | SSE signal stream |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Phone gets "Connection refused" | Start Django with `0.0.0.0:8000`, not `8000` |
| Phone page times out | Run `setup_firewall.bat` as Administrator |
| QR shows `localhost` | Check `/api/lan/ip/` returns a real `192.168.x.x` address |
| Mobile download does nothing | Ensure you have the latest build — `npm run build` (`@noble` fallback is included) |
| Link unavailable | Link expired, hit download limit, or is malformed. Create a new one. |
| Bluetooth greyed out | Requires `https://` or `http://localhost`. Not available on plain LAN IP. |

---

## Step-by-Step: Full Setup and Run

Execute each command in order in a terminal (PowerShell on Windows, Bash on macOS/Linux).

### 1. Clone the repository

```powershell
git clone https://github.com/shashankv762/django_pbl.git
cd django_pbl
```

### 2. Create a Python virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv .venv
call .venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Apply database migrations

```bash
python manage.py migrate
```

### 5. Install Node.js packages

```bash
npm install
```

### 6. Build the frontend

```bash
npm run build
```

> This compiles the React app into `dist/` which Django serves directly. Required for LAN sharing.

### 7. Open the firewall on Windows (one-time, run as Administrator)

**Option A — provided script:**
Right-click `setup_firewall.bat` in the project root → **Run as administrator**.

**Option B — PowerShell (elevated):**
```powershell
netsh advfirewall firewall add rule name="Aegix Port 8000" protocol=TCP dir=in localport=8000 action=allow
```

### 8. Find your LAN IP address

**Windows:**
```powershell
(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "192.168.*" }).IPAddress
```

**macOS / Linux:**
```bash
ip route get 1 | awk '{print $7; exit}'
```

Note this address — e.g. `192.168.1.42`. Other devices on your network will use it.

### 9. Start the Django server

```bash
python manage.py runserver 0.0.0.0:8000
```

The server binds to all network interfaces so any device on the same WiFi can reach it.

### 10. Verify LAN IP detection

```powershell
Invoke-RestMethod http://localhost:8000/api/lan/ip/
```

The `best` field must show your real LAN IP, not `127.0.0.1`.

### 11. Send a file to another device

1. On the PC, open `http://localhost:8000`
2. Go to **Nearby → LAN / QR Share**
3. Select a file and click **Send files**
4. A QR code appears containing `http://<LAN-IP>:8000/#/download?id=...&key=...`
5. Scan the QR with the phone camera
6. Tap **Decrypt & Download** on the phone
7. Tap the green **Save File** button when decryption completes

### 12. Use WebRTC P2P (no server storage)

1. Open `http://localhost:8000` on the sender
2. Go to **Nearby → WiFi / P2P**
3. Select files and click **Start P2P Send**
4. Share the link or QR with the receiver
5. Receiver opens the link — direct WebRTC connection is established
6. Files stream encrypted, peer-to-peer

### 13. Use Web Bluetooth (same PC only, requires localhost)

> Requires Chrome or Edge. Must be on `http://localhost:8000` — not the LAN IP.

1. Go to **Nearby → Bluetooth LE**
2. Click **Scan** — OS Bluetooth picker appears
3. Select a paired BLE device
4. If the device exposes the Aegix GATT service, the download URL is written directly to it

### 14. Configure settings

Open the **Settings** tab (gear icon) to:
- Change the default chunk size, expiry, and download limits
- Switch accent color, display density, or enable reduced motion
- Toggle toast notifications and sound effects
- Export or import your settings as JSON
- View the active crypto engine (Web Crypto or `@noble` fallback)

---

## Development Mode (hot reload)

```powershell
# Terminal 1 — Django backend
.venv\Scripts\python.exe manage.py runserver 0.0.0.0:8000

# Terminal 2 — Vite dev server (proxies /api/* to Django)
npm run dev
```

Open `http://localhost:5173`.  
**Note:** LAN/QR sharing requires the production build (`npm run build`). The Vite dev server is not reachable from other devices.

---

## License

MIT — see [LICENSE](LICENSE) for details.
