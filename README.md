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
| Phone gets "Connection refused" | Start Django with `0.0.0.0:8000` or `0.0.0.0:8443`, not `localhost` |
| Phone page times out | Run `setup_firewall.bat` as Administrator |
| QR shows `localhost` | Check `/api/lan/ip/` returns a real `192.168.x.x` address |
| Mobile says "File can't be downloaded securely" | Run the server in HTTPS mode (using `start_https.bat` or `python manage.py runssl`) and accept the self-signed certificate |
| Mobile camera scanner doesn't open / permission denied | Camera API (`getUserMedia`) requires a secure context (HTTPS). Run the server in HTTPS mode |
| Link unavailable | Link expired, hit download limit, or is malformed. Create a new one. |
| Bluetooth greyed out | Requires `https://` or `http://localhost`. Not available on plain LAN IP. |

---

## Running the Project: HTTP vs HTTPS Modes

Aegix Share can be run in two network modes. **HTTPS mode is highly recommended** for cross-device LAN file sharing because modern mobile browsers enforce strict security constraints on file downloads and device APIs.

### 1. HTTP Mode (Port 8000)
- **Startup Script**: Double-click `start.bat`
- **Manual Command**: `python manage.py runserver 0.0.0.0:8000`
- **Use Case**: Quick local testing on the same PC.
- **Limitation**: When accessing via a mobile device on LAN, mobile browsers will block file downloads due to insecure HTTP context, and the QR camera scanner will not open.

### 2. HTTPS Mode (Port 8443) — RECOMMENDED
- **Startup Script**: Double-click `start_https.bat`
- **Manual Command**: `python manage.py runssl 0.0.0.0:8443`
- **Use Case**: Secure cross-device sharing, mobile downloads, and mobile camera scanning.
- **How it works**: The backend auto-generates a self-signed TLS certificate (`cert.pem` and `key.pem`) containing the server's LAN IP. The web app automatically detects this secure server and generates `https://` URLs for QR codes.

---

## Step-by-Step Guidance: Run and Access via LAN

Follow these instructions to set up the project and share files securely with other devices on your local network (WiFi).

### Step 1: Install Prerequisites
Ensure you have the following installed:
- [Python 3.10+ ](https://www.python.org/downloads/)
- [Node.js 18+ ](https://nodejs.org/)

### Step 2: Clone and Setup Virtual Environment
Open a terminal in the project directory:
```powershell
# Create Python virtual environment
python -m venv .venv

# Activate it (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Install Python packages
pip install -r requirements.txt
```

### Step 3: Install Frontend Dependencies & Build
Compile the frontend static assets so they can be served by Django:
```bash
# Install Node modules
npm install

# Build production frontend assets
npm run build

# Collect static files into Django static directory
python manage.py collectstatic --noinput --clear
```

### Step 4: Apply Database Migrations
Initialize the SQLite database schema:
```bash
python manage.py migrate
```

### Step 5: Configure Firewall (Windows)
To allow other devices (like your phone) to connect to your PC, open the inbound firewall ports:
- Right-click `setup_firewall.bat` in the project root → **Run as administrator**.
- Alternatively, run this in an elevated PowerShell:
  ```powershell
  netsh advfirewall firewall add rule name="Aegix HTTP 8000" protocol=TCP dir=in localport=8000 action=allow
  netsh advfirewall firewall add rule name="Aegix HTTPS 8443" protocol=TCP dir=in localport=8443 action=allow
  ```

### Step 6: Start the HTTPS Server
Run the HTTPS startup script:
- Double-click **`start_https.bat`** (or run `python manage.py runssl 0.0.0.0:8443` in your terminal).
- This will print your access URLs:
  - **Local**: `https://localhost:8443`
  - **LAN**: `https://192.168.x.x:8443`

### Step 7: Connect Mobile Devices via LAN
1. On your phone, connect to the **same WiFi network** as your PC.
2. Open your phone's browser and go to your PC's LAN URL (e.g. `https://192.168.1.50:8443`).
3. **Important (One-time bypass)**: Because the server uses a self-signed developer certificate, your browser will display a security warning:
   - **Chrome / Android**: Tap **Advanced** → **Proceed to <ip_address> (unsafe)**.
   - **Safari / iOS**: Tap **Show Details** → **Visit this website** → Confirm with your passcode/FaceID.
4. The Aegix Share interface will load. Both file downloads and the QR camera scanner are now fully authorized to work.

### Step 8: Share a File
1. On your PC, open `https://localhost:8443` (or `https://192.168.x.x:8443`).
2. Select a file to upload in the **Send** tab.
3. Once ready, click the **LAN QR** button or look at the auto-generated QR code.
4. On your mobile, tap **Open camera scanner** in the Receive tab (or use the system camera) and scan the QR code.
5. The mobile browser will open the decryption link, download the chunks securely, and decrypt the file.

---

## Development Mode (Hot Reload)

To make changes to the code with instant browser reloading:

```powershell
# Terminal 1 — Django backend
.venv\Scripts\python.exe manage.py runserver 0.0.0.0:8000

# Terminal 2 — Vite dev server (proxies /api/* to Django)
npm run dev
```

Open `http://localhost:5173`.  
*Note: Vite dev server does not support SSL out of the box and is not reachable from other network devices. Use `npm run build` for testing LAN transfers.*

---

## License
MIT — see [LICENSE](LICENSE) for details.
