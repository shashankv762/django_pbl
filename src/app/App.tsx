/**
 * Aegix Share — Frontend
 * Wormhole-style chunked encrypted file sharing via Django backend.
 * Each 512 KB chunk is independently AES-256-GCM encrypted.
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  generateAesKey, importAesKey, exportAesKey,
  aesGcmEncrypt, aesGcmDecrypt,
  pbkdf2Key, wrapAesKey, unwrapAesKey,
  type AesKey,
} from '../lib/crypto-compat';
import {
  Shield, Upload, File, QrCode, History, Copy, Check, Lock,
  Camera, Download, X, User, LogOut, Eye, EyeOff, Bluetooth,
  Scan, Globe, Settings, Wifi, VideoOff, Database, RefreshCw,
  Clock, ArrowRight, AlertTriangle, CheckCircle, Zap, Link2,
  ChevronRight, Send, Radio, Signal, Smartphone, Monitor,
  Plus, Minus, FolderOpen, HardDrive, Info,
  Palette, SlidersHorizontal, Bell, Trash2, RotateCcw,
  ChevronDown, HardDriveDownload, Network, ShieldCheck, Cpu,
  Layers, Volume2, VolumeX, FileJson, FlaskConical,
} from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import jsQR from 'jsqr';

// ─── API base ──────────────────────────────────────────────────────────────────
const API =
  window.location.port === '5173' || window.location.port === '5174'
    ? `http://${window.location.hostname}:8000`
    : '';

// ─── Constants ─────────────────────────────────────────────────────────────────
const CHUNK_SIZE = 512 * 1024;

const EXPIRY_OPTIONS = [
  { label: '5 minutes',  value: 5 / 60 },
  { label: '10 minutes', value: 10 / 60 },
  { label: '15 minutes', value: 15 / 60 },
  { label: '30 minutes', value: 30 / 60 },
  { label: '1 hour',     value: 1 },
  { label: '2 hours',    value: 2 },
  { label: '3 hours',    value: 3 },
  { label: '5 hours',    value: 5 },
  { label: '10 hours',   value: 10 },
  { label: '24 hours',   value: 24 },
  { label: '1 week',     value: 168 },
];

const DOWNLOAD_LIMIT_OPTIONS = [
  { label: '1 download (one-time link)', value: 1 },
  { label: '2 downloads',               value: 2 },
  { label: '3 downloads',               value: 3 },
  { label: '5 downloads',               value: 5 },
  { label: '10 downloads',              value: 10 },
  { label: '15 downloads',              value: 15 },
  { label: '25 downloads',              value: 25 },
  { label: '50 downloads',              value: 50 },
  { label: 'Unlimited',                 value: 0 },
];

// ─── Types ─────────────────────────────────────────────────────────────────────
type Tab = 'send' | 'nearby' | 'history' | 'library' | 'settings' | 'profile';
type AuthPage = 'login' | 'register';
type SendSubTab = 'send' | 'receive';
type NearbySubTab = 'lan' | 'wifi' | 'ble';

interface TransferRecord {
  id: string; name: string; size: number; type: string;
  downloadUrl: string; downloadLanUrl: string;  // localhost vs LAN-IP URL
  uploadedChunks: number; totalChunks: number;
  status: 'uploading' | 'done' | 'failed';
  selfDestruct: boolean; requirePassword: boolean;
  downloadLimit: number; linkExpiry: number;
}

interface Toast { id: string; text: string; kind: 'ok' | 'err' | 'info'; }
interface ChunkMeta { seq: number; iv: string; original_size: number; }
interface RecvMeta {
  id: string; name: string; size: number; type: string;
  total_chunks: number; is_complete: boolean;
  chunks: ChunkMeta[];
  salt: string; wrap_iv: string; wrapped_key: string;
  self_destruct: boolean; download_limit: number; download_count: number;
  expires_at: string;
}

interface LanDevice {
  id: string; name: string; url: string; lastSeen: number;
}

// Full GATT metadata for a connected BLE device
interface BleDeviceInfo {
  id: string;
  name: string;
  status: 'pairing' | 'gatt-connecting' | 'connected' | 'error' | 'disconnected';
  manufacturer?: string;
  battery?: number;         // 0-100, undefined if service not available
  hasAegixService: boolean; // Custom Aegix URL delivery characteristic present
  servicesCount: number;
  errorMsg?: string;
  lastActivity: number;
}


// ─── Helpers ───────────────────────────────────────────────────────────────────
const bufToHex = (b: ArrayBuffer) =>
  [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');

const hexToBuf = (h: string): ArrayBuffer => {
  const arr = new Uint8Array(h.length / 2);
  for (let i = 0; i < h.length; i += 2) arr[i / 2] = parseInt(h.slice(i, i + 2), 16);
  return arr.buffer;
};

const fmtBytes = (b: number) => {
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
};

const uid = () => Math.random().toString(36).slice(2, 12);
const deviceId = (() => {
  const k = 'aegix-device-id';
  let id = localStorage.getItem(k);
  if (!id) { id = Math.random().toString(36).slice(2, 10).toUpperCase(); localStorage.setItem(k, id); }
  return id;
})();
const deviceName = `Aegix·${deviceId.slice(0, 6)}`;

// ─── Crypto ────────────────────────────────────────────────────────────────────
// All operations below use crypto-compat.ts which transparently falls back to
// @noble/ciphers when window.crypto.subtle is unavailable (plain-HTTP LAN IP).

/** Generate a fresh AES-256-GCM key. */
const makeKey = (): Promise<AesKey> => generateAesKey();

/** Derive an AES-256-GCM key from a password via PBKDF2-SHA-256 (100k rounds). */
const deriveKeyFromPassword = (pwd: string, salt: Uint8Array): Promise<AesKey> =>
  pbkdf2Key(pwd, salt, 100_000);

/** Encrypt one file chunk. Returns the ciphertext and the hex-encoded IV. */
const encryptChunk = async (data: ArrayBuffer, key: AesKey): Promise<{ cipher: ArrayBuffer; iv: string }> => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await aesGcmEncrypt(data, key, iv);
  return { cipher, iv: bufToHex(iv.buffer) };
};

/** Decrypt one file chunk. */
const decryptChunk = async (cipher: ArrayBuffer, key: AesKey, ivHex: string): Promise<ArrayBuffer> =>
  aesGcmDecrypt(cipher, key, new Uint8Array(hexToBuf(ivHex)));

// ─── Toggle Component ──────────────────────────────────────────────────────────
const Toggle = ({ val, onChange, label }: { val: boolean; onChange: () => void; label?: string }) => (
  <button
    type="button"
    role="switch"
    aria-checked={val}
    aria-label={label}
    onClick={onChange}
    className="toggle-track"
    data-on={String(val)}
  >
    <span className="toggle-thumb" />
  </button>
);

// ─── AppSettings — full persistent settings for the app ────────────────────────
interface AppSettings {
  // Transfer defaults
  defaultExpiryHours: number;   // maps to EXPIRY_OPTIONS values
  defaultDownloadLimit: number; // 0 = unlimited
  defaultSelfDestruct: boolean;
  defaultRequirePassword: boolean;
  defaultChunkKB: number;       // 256 | 512 | 1024 | 2048
  showQrOnUpload: boolean;

  // Appearance
  accentHue: number;            // 0–360, indigo ≈ 235
  density: 'compact' | 'normal' | 'comfortable';
  reducedMotion: boolean;

  // Security & Privacy
  historyRetentionDays: number; // 0 = keep forever
  showTransferKeys: boolean;    // show decryption key in history cards
  autoCloseModalOnCopy: boolean;

  // Network
  lanDiscoverable: boolean;
  deviceDisplayName: string;

  // Notifications
  notifyOnUpload: boolean;
  notifyOnLanPeer: boolean;
  notifyOnDownload: boolean;
  soundEffects: boolean;

  // Meta
  schemaVersion: number; // increment when shape changes to auto-migrate
}

const APP_SETTINGS_KEY = 'aegix-settings-v1';

const DEFAULT_SETTINGS: AppSettings = {
  defaultExpiryHours:     24,
  defaultDownloadLimit:   0,
  defaultSelfDestruct:    false,
  defaultRequirePassword: false,
  defaultChunkKB:         512,
  showQrOnUpload:         false,
  accentHue:              235,
  density:                'normal',
  reducedMotion:          false,
  historyRetentionDays:   0,
  showTransferKeys:       false,
  autoCloseModalOnCopy:   false,
  lanDiscoverable:        true,
  deviceDisplayName:      deviceName,
  notifyOnUpload:         true,
  notifyOnLanPeer:        true,
  notifyOnDownload:       true,
  soundEffects:           false,
  schemaVersion:          1,
};

function loadSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(APP_SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<AppSettings>;
    // Deep-merge: parsed values override defaults; any new default fields are preserved
    return { ...DEFAULT_SETTINGS, ...parsed, schemaVersion: DEFAULT_SETTINGS.schemaVersion };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function saveSettings(s: AppSettings): void {
  try { localStorage.setItem(APP_SETTINGS_KEY, JSON.stringify(s)); } catch { /* quota exceeded — ignore */ }
}

// Helper: export any object as a downloadable JSON file
function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Accent hue: inject a <style> that hue-rotates the entire app shell.
// Tailwind's indigo baseline is ~235°, so a delta of (hue-235)° shifts
// all saturated colors (indigo toggles, buttons, badges) to the chosen hue.
// Desaturated slate/gray colors barely shift because their saturation is ~5%.
function applyAccentHue(hue: number): void {
  const deg = hue - 235; // delta from indigo baseline
  const id  = 'aegix-accent-style';
  let el = document.getElementById(id) as HTMLStyleElement | null;
  if (!el) { el = document.createElement('style'); el.id = id; document.head.appendChild(el); }
  // Target the entire app shell — not just [data-accent] elements
  el.textContent = `#aegix-app-root { filter: hue-rotate(${deg}deg); }`;
}

// Density: change the <html> font-size so all rem-based Tailwind classes scale.
// compact=14px / normal=16px / comfortable=18px
function applyDensity(density: AppSettings['density']): void {
  const id = 'aegix-density-style';
  let el = document.getElementById(id) as HTMLStyleElement | null;
  if (!el) { el = document.createElement('style'); el.id = id; document.head.appendChild(el); }
  const size = density === 'compact' ? '14px' : density === 'comfortable' ? '18px' : '16px';
  el.textContent = `html { font-size: ${size}; }`;
  // Also keep the data attribute for any future CSS selectors
  document.documentElement.setAttribute('data-density', density);
}

// Reduced motion: disable animations + transitions via injected CSS.
function applyReducedMotion(reduced: boolean): void {
  const id = 'aegix-motion-style';
  let el = document.getElementById(id) as HTMLStyleElement | null;
  if (!el) { el = document.createElement('style'); el.id = id; document.head.appendChild(el); }
  el.textContent = reduced
    ? `*, *::before, *::after {
         animation-duration: 0.01ms !important;
         animation-iteration-count: 1 !important;
         transition-duration: 0.01ms !important;
         scroll-behavior: auto !important;
       }`
    : '';
  document.documentElement.setAttribute('data-motion', reduced ? 'reduce' : 'full');
}

// ─── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  // ── Auth ──
  const isDownloadLink = window.location.hash.startsWith('#/download');
  const isP2pLink      = window.location.hash.startsWith('#/p2p');
  const [isLoggedIn, setIsLoggedIn] = useState(isDownloadLink || isP2pLink);
  const [isGuest,    setIsGuest]    = useState(isDownloadLink || isP2pLink);
  const [authPage, setAuthPage] = useState<AuthPage>('login');
  const [authName, setAuthName] = useState('');
  const [authEmail, setAuthEmail] = useState('');
  const [authPwd, setAuthPwd] = useState('');
  const [showPwd, setShowPwd] = useState(false);

  // ── Navigation ──
  const [tab, setTab] = useState<Tab>('send');
  const [sendSubTab, setSendSubTab] = useState<SendSubTab>('send');
  const [nearbySubTab, setNearbySubTab] = useState<NearbySubTab>('lan');

  // ── Profile ──
const [profileName,  setProfileName]  = useState(() => { try { return JSON.parse(localStorage.getItem('aegix_profile') || '{}').name || 'User'; } catch { return 'User'; } });
const [profileEmail, setProfileEmail] = useState(() => { try { return JSON.parse(localStorage.getItem('aegix_profile') || '{}').email || 'user@example.com'; } catch { return 'user@example.com'; } });
const [deviceName,   setDeviceName]   = useState(() => { try { const p = JSON.parse(localStorage.getItem('aegix_profile') || '{}'); return p.device || 'My Device'; } catch { return 'My Device'; } });

  // ── App Settings (persistent, localStorage) ──
  const [settings, setSettings] = useState<AppSettings>(() => {
    const s = loadSettings();
    // Apply CSS effects synchronously before first render
    applyAccentHue(s.accentHue);
    applyDensity(s.density);
    applyReducedMotion(s.reducedMotion);
    return s;
  });

  // Helper: update one setting key, persist, and apply side-effects
  const updateSetting = useCallback(<K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setSettings(prev => {
      const next = { ...prev, [key]: value };
      saveSettings(next);
      // Apply CSS side-effects immediately
      if (key === 'accentHue')    applyAccentHue(value as number);
      if (key === 'density')      applyDensity(value as AppSettings['density']);
      if (key === 'reducedMotion') applyReducedMotion(value as boolean);
      return next;
    });
  }, []);

  // Ref to hold current chunk size so upload closures always get the latest value
  const chunkSizeRef = useRef<number>(settings.defaultChunkKB * 1024);
  useEffect(() => { chunkSizeRef.current = settings.defaultChunkKB * 1024; }, [settings.defaultChunkKB]);

  // ── Toasts ──
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toast = useCallback((text: string, kind: Toast['kind'] = 'info') => {
    const id = uid();
    setToasts(p => [...p, { id, text, kind }]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 4500);
  }, []);

  // ── Send — defaults loaded from settings ──
  const [uploadQueue,     setUploadQueue]     = useState<File[]>([]);
  const [isDragging,      setIsDragging]      = useState(false);
  const [linkExpiry,      setLinkExpiry]      = useState(settings.defaultExpiryHours);
  const [selfDestruct,    setSelfDestruct]    = useState(settings.defaultSelfDestruct);
  const [downloadLimit,   setDownloadLimit]   = useState(settings.defaultDownloadLimit);
  const [requirePassword, setRequirePassword] = useState(settings.defaultRequirePassword);
  const [password,        setPassword]        = useState('');
  const [showSendPwd,     setShowSendPwd]     = useState(false);
  const [transfers,       setTransfers]       = useState<TransferRecord[]>([]);
  const [isUploading,     setIsUploading]     = useState(false);

  // Sync settings → send-tab defaults + LAN state whenever they change
  useEffect(() => {
    setLinkExpiry(settings.defaultExpiryHours);
    setSelfDestruct(settings.defaultSelfDestruct);
    setDownloadLimit(settings.defaultDownloadLimit);
    setRequirePassword(settings.defaultRequirePassword);
    setLanDiscoverable(settings.lanDiscoverable);
    setLocalName(settings.deviceDisplayName);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.defaultExpiryHours, settings.defaultSelfDestruct, settings.defaultDownloadLimit,
      settings.defaultRequirePassword, settings.lanDiscoverable, settings.deviceDisplayName]);

  // Apply history-retention pruning when settings or transfers change
  useEffect(() => {
    if (settings.historyRetentionDays === 0) return; // keep forever
    const cutoff = Date.now() - settings.historyRetentionDays * 86_400_000;
    setTransfers(prev => prev.filter(t => {
      // Prune only records that are old (we use uploadedAt from record id as proxy: uid is Date.now().toString(36))
      // Since we don't store timestamps, we skip pruning done records older than cutoff
      // This is a best-effort prune using the transfer id's embedded time approximation
      return true; // conservative: do not delete without explicit timestamp
    }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.historyRetentionDays]);

  // Sound effect helper
  const playSfx = useCallback((type: 'done' | 'error') => {
    if (!settings.soundEffects) return;
    try {
      const ctx = new AudioContext();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      if (type === 'done') {
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.setValueAtTime(1174, ctx.currentTime + 0.12);
      } else {
        osc.frequency.setValueAtTime(200, ctx.currentTime);
        osc.frequency.setValueAtTime(150, ctx.currentTime + 0.1);
      }
      gain.gain.setValueAtTime(0.18, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.35);
      osc.start(); osc.stop(ctx.currentTime + 0.35);
    } catch { /* AudioContext not available */ }
  }, [settings.soundEffects]);

  // ── Link Modal ──
  const [showLinkModal, setShowLinkModal] = useState(false);
  const [showShareSheet, setShowShareSheet] = useState(false);
  const [lastTransfer, setLastTransfer] = useState<TransferRecord | null>(null);
  const [linkCopied, setLinkCopied] = useState(false);

  // ── Receive ──
  const [receiverMode, setReceiverMode] = useState(false);
  const [recvId, setRecvId] = useState<string | null>(null);
  const [recvKeyHex, setRecvKeyHex] = useState<string | null>(null);
  const [recvMeta, setRecvMeta] = useState<RecvMeta | null>(null);
  const [recvPassword, setRecvPassword] = useState('');
  const [showRecvPwd, setShowRecvPwd] = useState(false);
  const [recvStatus, setRecvStatus] = useState<'idle' | 'connecting' | 'downloading' | 'done' | 'error'>('idle');
  const [recvProgress, setRecvProgress] = useState(0);
  const [recvChunksGot, setRecvChunksGot] = useState(0);
  const [recvLink, setRecvLink] = useState('');
  // Holds blob URL + filename once decryption is complete.
  // The user taps the Save File anchor (a real user gesture) to trigger download.
  const [recvDownloadReady, setRecvDownloadReady] = useState<{ blobUrl: string; filename: string } | null>(null);

  // ── Library ──
  const [libStats, setLibStats] = useState({ count: 0, bytes: 0, files: [] as any[] });

  // ── Network IP ──
  const [serverIp,   setServerIp]   = useState<string>('');
  /**
   * HTTPS port reported by the backend (null = HTTPS server not running).
   * When non-null, ALL LAN QR / share links are built with https:// + this port
   * regardless of whether the current page was opened via HTTP or HTTPS.
   * This fixes the "can't download securely" block on mobile Chrome/Safari.
   */
  const [httpsPort,  setHttpsPort]  = useState<number | null>(null);

  const getBaseUrl = useCallback(() => {
    // Always preserve the hostname the browser is currently using.
    // Replacing localhost with the LAN IP breaks copy-paste on the same machine
    // (the LAN IP may be firewalled or unreachable even locally).
    // Users who need LAN-IP links for cross-device sharing can use the QR code,
    // which already encodes the full URL shown in the QR modal.
    const hostname = window.location.hostname;
    return `${window.location.protocol}//${hostname}${window.location.port ? ':' + window.location.port : ''}${window.location.pathname}`;
  }, []);

  // ── QR ──
  const [showQR, setShowQR] = useState(false);
  const [qrContent, setQrContent] = useState('');
  const [qrTitle, setQrTitle] = useState('');
  const [showScanner, setShowScanner] = useState(false);
  const [scannerTitle, setScannerTitle] = useState('');
  const [scanCallback, setScanCallback] = useState<((v: string) => void) | null>(null);
  const [cameraActive, setCameraActive] = useState(false);
  const [cameraError, setCameraError] = useState('');
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const scanTimerRef = useRef<number | null>(null);
  const streamRef = useRef<MediaStream | null>(null);

  // ── Nearby / LAN ──
  const [bleSupported,    setBleSupported]    = useState(false);
  const [bleStatus,       setBleStatus]       = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [bleDevices,      setBleDevices]      = useState<{ name: string; id: string }[]>([]);
  // Rich per-device GATT state (displayed in UI)
  const [bleDeviceInfos,  setBleDeviceInfos]  = useState<BleDeviceInfo[]>([]);
  // Stable refs to actual Web Bluetooth objects (not serialisable to React state)
  const bleDeviceRefs  = useRef<Map<string, any>>(new Map()); // id → BluetoothDevice
  const gattServerRefs = useRef<Map<string, any>>(new Map()); // id → BluetoothRemoteGATTServer
  // Web Serial API (Bluetooth Classic COM ports on Windows)
  const [serialSupported, setSerialSupported] = useState(false);

  useEffect(() => { setBleSupported('bluetooth' in navigator); }, []);
  useEffect(() => { setSerialSupported('serial' in navigator); }, []);

  const [lanDevices, setLanDevices] = useState<LanDevice[]>([]);
  const [lanDiscoverable, setLanDiscoverable] = useState(true);
  const [editDeviceName, setEditDeviceName] = useState(false);
  const [localName, setLocalName] = useState(deviceName);
  // Nearby file selection
  const [nearbyFiles, setNearbyFiles] = useState<File[]>([]);
  const [nearbyTarget, setNearbyTarget] = useState<LanDevice | null>(null);
  const [nearbyStatus, setNearbyStatus] = useState<'idle' | 'uploading' | 'done' | 'error'>('idle');
  const [nearbyProgress, setNearbyProgress] = useState(0);
  const [nearbyLink,    setNearbyLink]    = useState('');   // localhost URL
  const [nearbyLanLink, setNearbyLanLink] = useState('');   // LAN-IP URL for QR
  const lanBcRef = useRef<BroadcastChannel | null>(null);

  // ── WebRTC P2P state ──
  type P2PStatus = 'idle'|'creating'|'waiting'|'connecting'|'transferring'|'done'|'error';
  const [p2pStatus,       setP2pStatus]       = useState<P2PStatus>('idle');
  const [p2pRoomId,       setP2pRoomId]       = useState<string|null>(null);
  const [p2pKeyHex,       setP2pKeyHex]       = useState<string|null>(null);
  const [p2pLink,         setP2pLink]         = useState('');   // localhost URL (copy-paste)
  const [p2pLanLink,      setP2pLanLink]      = useState('');   // LAN-IP URL (QR for other device)
  const [p2pProgress,     setP2pProgress]     = useState(0);
  const [p2pChunksDone,   setP2pChunksDone]   = useState(0);
  const [p2pTotalChunks,  setP2pTotalChunks]  = useState(0);
  const [p2pFileName,     setP2pFileName]     = useState('');
  const [p2pFileSize,     setP2pFileSize]     = useState(0);
  const [p2pFile,         setP2pFile]         = useState<File|null>(null);
  const [p2pError,        setP2pError]        = useState('');
  const [p2pMode,         setP2pMode]         = useState<'send'|'receive'|null>(null);
  const p2pPcRef    = useRef<RTCPeerConnection|null>(null);
  const p2pEsRef    = useRef<EventSource|null>(null);
  const p2pAbortRef = useRef(false);

  // ── Stats ──
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/stats/`);
      if (res.ok) {
        const d = await res.json();
        setLibStats({ count: d.files_encrypted_count, bytes: d.total_encrypted_bytes, files: d.files });
        if (d.local_ip) setServerIp(d.local_ip);
        // Capture HTTPS port — backend probes whether port 8443 is bound
        if (typeof d.https_port === 'number') setHttpsPort(d.https_port);
        else if (d.https_port === null)        setHttpsPort(null);
      }
    } catch { /* offline */ }
  }, []);

  useEffect(() => {
    fetchStats();
    const t = setInterval(fetchStats, 8000);
    return () => clearInterval(t);
  }, [fetchStats]);

  // ── LAN peer discovery: server-side polling (works across all devices on the network) ──
  useEffect(() => {
    if (!lanDiscoverable) return;

    // Derive the server port from current page URL (e.g. 8000)
    const svrPort = window.location.port || '8000';

    const doAnnounce = async () => {
      try {
        const res = await fetch(`${API}/api/lan/announce/`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ peer_id: deviceId, name: localName }),
        });
        if (res.ok) {
          const data = await res.json();
          // Update serverIp from the announce response (most reliable source)
          if (data.server_ip && data.server_ip !== '127.0.0.1') {
            setServerIp(data.server_ip);
          }
        }
      } catch { /* network error — server unreachable */ }
    };

    const doFetchPeers = async () => {
      try {
        const res = await fetch(`${API}/api/lan/devices/`);
        if (!res.ok) return;
        const data = await res.json();
        const now = Date.now();
        setLanDevices(
          (data.peers as { id: string; name: string; ip: string }[])
            .filter(p => p.id !== deviceId)
            .map(p => ({
              id: p.id,
              name: p.name,
              // Build clickable URL using the peer's LAN IP + our server port
              url: `http://${p.ip}:${svrPort}`,
              lastSeen: now,
            }))
        );
      } catch { /* ignore */ }
    };

    // Initial burst then steady heartbeat
    doAnnounce();
    doFetchPeers();
    const announceT = setInterval(doAnnounce,    3000);
    const peersT    = setInterval(doFetchPeers,  4000);

    // Also keep same-device BroadcastChannel as a fast-path for same-machine tabs
    const bc = new BroadcastChannel('aegix-lan-discovery');
    lanBcRef.current = bc;
    bc.postMessage({ type: 'announce', id: deviceId, name: localName, url: window.location.origin });
    const bcT = setInterval(() => bc.postMessage({ type: 'announce', id: deviceId, name: localName, url: window.location.origin }), 3000);
    bc.onmessage = (e) => {
      const { type, id, name, url } = e.data;
      if (type === 'announce' && id !== deviceId) {
        setLanDevices(prev => {
          const existing = prev.find(d => d.id === id);
          // Fire notification only for brand-new devices (not heartbeats)
          if (!existing && settings.notifyOnLanPeer) toast(`📶 ${name} joined the network`, 'info');
          if (existing) return prev.map(d => d.id === id ? { ...d, name, url, lastSeen: Date.now() } : d);
          return [...prev, { id, name, url, lastSeen: Date.now() }];
        });
      }
    };

    return () => {
      clearInterval(announceT);
      clearInterval(peersT);
      clearInterval(bcT);
      bc.close();
      lanBcRef.current = null;
      // Deregister cleanly
      fetch(`${API}/api/lan/announce/`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ peer_id: deviceId }),
      }).catch(() => {});
    };
  }, [lanDiscoverable, localName]);

  // ── URL hash parsing ──
  const parseHash = useCallback(async () => {
    const hash = window.location.hash;

    // ── P2P WebRTC receive link: #/p2p?room=...&key=... ──
    if (hash.startsWith('#/p2p')) {
      setReceiverMode(false); setRecvId(null); setRecvMeta(null); setRecvStatus('idle');
      const qs = new URLSearchParams(hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '');
      const room = qs.get('room');
      const key  = qs.get('key');
      if (room && key) {
        setP2pRoomId(room); setP2pKeyHex(key); setP2pMode('receive'); setP2pStatus('connecting');
      }
      return;
    }

    // ── Server-based download link: #/download?id=...&key=... ──
    if (!hash.startsWith('#/download')) {
      setReceiverMode(false); setRecvId(null); setRecvMeta(null); setRecvStatus('idle');
      setP2pMode(null); setP2pStatus('idle'); return;
    }
    setReceiverMode(true);
    const qs = new URLSearchParams(hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '');
    const id = qs.get('id');
    const key = qs.get('key');
    if (!id) return;
    setRecvId(id); setRecvKeyHex(key); setRecvStatus('connecting');
    try {
      const res = await fetch(`${API}/api/transfer/${id}/meta/`);
      if (res.ok) { setRecvMeta(await res.json()); setRecvStatus('idle'); }
      else {
        setRecvStatus('error');
        let message = 'File link invalid or expired.';
        try { const body = await res.json(); if (body?.error) message = body.error; } catch { /* non-JSON error body, keep default */ }
        toast(message, 'err');
      }
    } catch { setRecvStatus('error'); toast('Could not reach the server. Check your connection.', 'err'); }
  }, [toast]);

  useEffect(() => {
    parseHash();
    window.addEventListener('hashchange', parseHash);
    return () => window.removeEventListener('hashchange', parseHash);
  }, [parseHash]);

  // ── Cleanup P2P resources on unmount ──
  useEffect(() => {
    return () => {
      p2pAbortRef.current = true;
      p2pEsRef.current?.close();
      p2pPcRef.current?.close();
    };
  }, []);

  // ─── Crypto Utilities ────────────────────────────────────────────────────
  const getDecryptionKey = async (meta: RecvMeta, pwd?: string): Promise<AesKey | null> => {
    const hasWrapped = meta.wrapped_key?.length > 0;
    const hasSalt    = meta.salt?.length > 0;
    const hasWrapIv  = meta.wrap_iv?.length > 0;
    if (hasWrapped && hasSalt && hasWrapIv) {
      if (!pwd) { toast('Password required to decrypt this file.', 'err'); return null; }
      const saltBuf = new Uint8Array(hexToBuf(meta.salt));
      const pwdKey = await deriveKeyFromPassword(pwd, saltBuf);
      try {
        return await unwrapAesKey(
          hexToBuf(meta.wrapped_key),
          pwdKey,
          new Uint8Array(hexToBuf(meta.wrap_iv)),
        );
      } catch { toast('Wrong password — could not decrypt.', 'err'); return null; }
    }
    if (recvKeyHex?.length) return importAesKey(hexToBuf(recvKeyHex), ['decrypt']);
    toast('No decryption key available.', 'err'); return null;
  };

  // ─── SEND — chunked upload ────────────────────────────────────────────────
  const startUpload = async () => {
    if (!uploadQueue.length) { toast('Select a file first.', 'err'); return; }
    const file = uploadQueue[0];
    if (file.size > 1_073_741_824) { toast('File exceeds 1 GB limit.', 'err'); return; }
    if (requirePassword && !password.trim()) { toast('Enter a password.', 'err'); return; }
    setIsUploading(true);
    const id = uid();
    // Use the settings-driven chunk size (via ref for freshest value)
    const cs = chunkSizeRef.current;
    const totalChunks = Math.ceil(file.size / cs) || 1;
    const fileKey = await makeKey();
    const rawKeyBuf = await exportAesKey(fileKey);
    let keyHex = bufToHex(rawKeyBuf);
    let saltStr = '', wrapIvStr = '', wrappedKeyStr = '';
    if (requirePassword && password) {
      const salt   = crypto.getRandomValues(new Uint8Array(16));
      const wrapIV = crypto.getRandomValues(new Uint8Array(12));
      const pwdKey = await deriveKeyFromPassword(password, salt);
      const wrapped = await wrapAesKey(fileKey, pwdKey, wrapIV);
      saltStr = bufToHex(salt.buffer); wrapIvStr = bufToHex(wrapIV.buffer); wrappedKeyStr = bufToHex(wrapped);
      keyHex = '';
    }
    const base    = getBaseUrl();
    const urlKey  = keyHex ? `&key=${keyHex}` : '';
    const fragment      = `#/download?id=${id}${urlKey}`;
    const downloadUrl    = `${base}${fragment}`;
    const downloadLanUrl = await buildLanUrlAsync(fragment);
    const rec: TransferRecord = {
      id, name: file.name, size: file.size, type: file.type || 'bin',
      downloadUrl, downloadLanUrl, uploadedChunks: 0, totalChunks, status: 'uploading',
      selfDestruct, requirePassword, downloadLimit, linkExpiry,
    };
    setTransfers(p => [rec, ...p]);
    try {
      const initRes = await fetch(`${API}/api/transfer/init/`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id, name: file.name, size: file.size, type: rec.type, total_chunks: totalChunks,
          expiry_hours: linkExpiry, self_destruct: selfDestruct, download_limit: downloadLimit,
          salt: saltStr, wrap_iv: wrapIvStr, wrapped_key: wrappedKeyStr,
        }),
      });
      if (!initRes.ok) throw new Error(`Init failed: ${initRes.status}`);
      for (let seq = 0; seq < totalChunks; seq++) {
        const start = seq * cs;
        const end = Math.min(start + cs, file.size);
        const plain = await file.slice(start, end).arrayBuffer();
        const { cipher, iv } = await encryptChunk(plain, fileKey);
        const fd = new FormData();
        fd.append('chunk', new Blob([cipher], { type: 'application/octet-stream' }), `chunk_${seq}`);
        fd.append('iv', iv); fd.append('original_size', String(end - start));
        const chunkRes = await fetch(`${API}/api/transfer/${id}/upload/${seq}/`, { method: 'POST', body: fd });
        if (!chunkRes.ok) throw new Error(`Chunk ${seq} failed: ${chunkRes.status}`);
        setTransfers(p => p.map(t => t.id === id ? { ...t, uploadedChunks: seq + 1 } : t));
      }
      await fetch(`${API}/api/transfer/${id}/complete/`, { method: 'POST' });
      const finalRec = { ...rec, uploadedChunks: totalChunks, status: 'done' as const };
      setTransfers(p => p.map(t => t.id === id ? finalRec : t));
      setLastTransfer(finalRec); setShowLinkModal(true); setLinkCopied(false); setUploadQueue([]); fetchStats();
      if (settings.notifyOnUpload) toast(`"${file.name}" encrypted & uploaded ✓`, 'ok');
      playSfx('done');
      // Auto-open QR if the setting is enabled
      if (settings.showQrOnUpload) {
        setQrContent(finalRec.downloadLanUrl || finalRec.downloadUrl);
        setQrTitle(`QR — ${file.name}`);
        setShowQR(true);
      }
    } catch (err: any) {
      setTransfers(p => p.map(t => t.id === id ? { ...t, status: 'failed' } : t));
      toast(`Upload failed: ${err?.message || 'unknown error'}`, 'err');
      playSfx('error');
    } finally { setIsUploading(false); }
  };

  // ─── RECEIVE — download ────────────────────────────────────────────────────
  const startDownload = async () => {
    if (!recvId || !recvMeta) return;
    let fileKey: AesKey | null = null;
    try {
      fileKey = await getDecryptionKey(recvMeta, recvPassword || undefined);
    } catch (e: any) {
      toast(`Decryption setup failed: ${e?.message || 'unknown error'}`, 'err');
      setRecvStatus('error');
      return;
    }
    if (!fileKey) return;
    setRecvStatus('downloading'); setRecvProgress(0); setRecvChunksGot(0);
    setRecvDownloadReady(null);  // clear any previous download blob
    const totalChunks = recvMeta.total_chunks;
    const slots: (ArrayBuffer | null)[] = new Array(totalChunks).fill(null);
    let received = 0;

    // ── Assemble decrypted slots into final file ───────────────────────────────
    // IMPORTANT: We do NOT auto-trigger a.click() here.
    // Mobile Chrome (Android) and iOS Safari require a direct user gesture to
    // initiate a blob download.  After multiple await calls the original button-
    // click gesture is gone, so programmatic a.click() is silently blocked.
    // Instead we store the blob URL in state and render a visible "Save File"
    // anchor that the user taps — that tap IS a user gesture and always works.
    const assembleAndSave = () => {
      if (received !== totalChunks || slots.some(s => s === null)) {
        const missing = slots.reduce((acc, s, i) => s === null ? [...acc, i] : acc, [] as number[]);
        toast(`Download incomplete — missing chunks: ${missing.join(', ')}`, 'err');
        setRecvStatus('error');
        return;
      }
      const mimeType = recvMeta!.type || 'application/octet-stream';
      const blob = new Blob((slots as ArrayBuffer[]).map(c => new Uint8Array(c)), { type: mimeType });
      const blobUrl = URL.createObjectURL(blob);
      // Store for the Save File button rendered in the UI
      setRecvDownloadReady({ blobUrl, filename: recvMeta!.name });
      setRecvStatus('done');
      if (settings.notifyOnDownload) toast(`"${recvMeta!.name}" decrypted — tap Save File!`, 'ok');
      playSfx('done');
      // Auto-revoke after 10 min to free memory
      setTimeout(() => URL.revokeObjectURL(blobUrl), 600_000);
    };

    // ── Download a single encrypted chunk and decrypt it ──────────────────────
    const downloadOneChunk = async (seq: number, ivHex: string): Promise<boolean> => {
      if (slots[seq] !== null) return true;   // already in cache
      for (let attempt = 0; attempt < 4; attempt++) {
        try {
          const res = await fetch(`${API}/api/transfer/${recvId}/chunk/${seq}/`);
          if (!res.ok) {
            if (res.status === 404) {
              // Chunk not yet on server — wait and retry
              await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
              continue;
            }
            if (res.status === 410) {
              // 410 Gone: self-destruct or limit exceeded — abort
              toast(`Chunk ${seq} is gone (limit or self-destruct).`, 'err');
              return false;
            }
            await new Promise(r => setTimeout(r, 500));
            continue;
          }
          const cipher = await res.arrayBuffer();
          const plain  = await decryptChunk(cipher, fileKey, ivHex);
          slots[seq]   = plain;
          received++;
          setRecvChunksGot(received);
          setRecvProgress(Math.round((received / totalChunks) * 100));
          return true;
        } catch (e) {
          if (attempt < 3) await new Promise(r => setTimeout(r, 600 * (attempt + 1)));
        }
      }
      return false;
    };

    // ── Path A: transfer is already complete (normal case after sender finishes) ─
    if (recvMeta.is_complete) {
      let chunkInfos = recvMeta.chunks?.length ? recvMeta.chunks : [];

      // Fetch fresh metadata if chunks list was empty (edge case on first open)
      if (!chunkInfos.length) {
        try {
          const fresh = await fetch(`${API}/api/transfer/${recvId}/meta/`);
          if (fresh.ok) {
            const fm = await fresh.json();
            chunkInfos = fm.chunks ?? [];
          }
        } catch { /* network error */ }
      }

      if (!chunkInfos.length) {
        setRecvStatus('error');
        toast('Could not retrieve chunk list from server.', 'err');
        return;
      }

      // Download chunks sequentially (safer on mobile — avoids saturating connection)
      // Up to 3 concurrent downloads: compromise between speed and reliability
      const CONCURRENCY = 3;
      for (let i = 0; i < chunkInfos.length; i += CONCURRENCY) {
        const batch = chunkInfos.slice(i, i + CONCURRENCY);
        const results = await Promise.all(batch.map(c => downloadOneChunk(c.seq, c.iv)));
        if (results.some(ok => !ok)) {
          // Retry failed chunks once serially
          for (const c of batch) {
            if (slots[c.seq] === null) await downloadOneChunk(c.seq, c.iv);
          }
        }
      }

      if (received === totalChunks) {
        assembleAndSave();
      } else {
        setRecvStatus('error');
        toast(`Only ${received}/${totalChunks} chunks received. Try again.`, 'err');
      }
      return;
    }

    // ── Path B: sender is still uploading — subscribe to SSE stream ──────────
    const es = new EventSource(`${API}/api/transfer/${recvId}/stream/`);
    const jobs: Promise<boolean>[] = [];
    await new Promise<void>((resolve) => {
      let ended = false;
      const onFinish = async () => {
        if (ended) return; ended = true; es.close();
        await Promise.allSettled(jobs);
        // Fetch any chunks that SSE might have missed
        if (received < totalChunks) {
          try {
            const r = await fetch(`${API}/api/transfer/${recvId}/meta/`);
            if (r.ok) {
              const fm = await r.json();
              const miss = (fm.chunks as ChunkMeta[]).filter(c => slots[c.seq] === null);
              await Promise.all(miss.map(c => downloadOneChunk(c.seq, c.iv)));
            }
          } catch { /* ignore */ }
        }
        resolve();
      };
      es.onmessage = (ev) => {
        let data: any; try { data = JSON.parse(ev.data); } catch { return; }
        if (data.type === 'chunk_ready') jobs.push(downloadOneChunk(data.seq, data.iv));
        if (data.type === 'complete' || data.type === 'end') onFinish();
        if (data.type === 'error' || data.type === 'expired') {
          es.close(); ended = true; setRecvStatus('error');
          toast(data.message || 'Transfer expired.', 'err'); resolve();
        }
      };
      es.onerror = () => onFinish();
    });

    if (received === totalChunks) assembleAndSave();
    else if (recvStatus !== 'error') {
      setRecvStatus('error');
      toast(`Only ${received}/${totalChunks} chunks received. Try again.`, 'err');
    }
  };


  // ─── Nearby LAN file send via upload to server then share link ──────────────
  const sendNearbyFiles = async (target?: LanDevice) => {
    if (!nearbyFiles.length) { toast('Select files to send first.', 'err'); return; }
    const file = nearbyFiles[0];
    setNearbyStatus('uploading'); setNearbyProgress(0);
    const id = uid();
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
    const fileKey = await makeKey();
    const rawKeyBuf = await exportAesKey(fileKey);
    const keyHex  = bufToHex(rawKeyBuf);
    const fragment = `#/download?id=${id}&key=${keyHex}`;
    // localhost URL — for copy/paste on the same machine
    const localBase = getBaseUrl();
    const downloadUrl    = `${localBase}${fragment}`;
    // LAN-IP URL — always uses a freshly fetched IP so the QR is correct
    // even if the user sends before the first stats poll completes.
    const downloadLanUrl = await buildLanUrlAsync(fragment);
    try {
      await fetch(`${API}/api/transfer/init/`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id, name: file.name, size: file.size, type: file.type || 'bin',
          total_chunks: totalChunks, expiry_hours: 1,
          self_destruct: false, download_limit: 0,
          salt: '', wrap_iv: '', wrapped_key: '',
        }),
      });
      for (let seq = 0; seq < totalChunks; seq++) {
        const start = seq * CHUNK_SIZE;
        const end   = Math.min(start + CHUNK_SIZE, file.size);
        const plain = await file.slice(start, end).arrayBuffer();
        const { cipher, iv } = await encryptChunk(plain, fileKey);
        const fd = new FormData();
        fd.append('chunk', new Blob([cipher]), `chunk_${seq}`);
        fd.append('iv', iv);
        fd.append('original_size', String(end - start));
        await fetch(`${API}/api/transfer/${id}/upload/${seq}/`, { method: 'POST', body: fd });
        setNearbyProgress(Math.round(((seq + 1) / totalChunks) * 100));
      }
      await fetch(`${API}/api/transfer/${id}/complete/`, { method: 'POST' });
      setNearbyLink(downloadUrl);
      setNearbyLanLink(downloadLanUrl);
      setNearbyStatus('done');
      // Announce link via BroadcastChannel so same-device tabs pick it up instantly
      lanBcRef.current?.postMessage({ type: 'file-ready', url: downloadLanUrl, name: file.name, fromId: deviceId });
      toast(`"${file.name}" ready — share the QR or copy the link!`, 'ok');
    } catch (err: any) { setNearbyStatus('error'); toast(`Send failed: ${err.message}`, 'err'); }
  };

  // ─── WebRTC P2P helpers ───────────────────────────────────────────────────────
  const P2P_CHUNK  = 16384;  // 16 KB — safe across all browsers (Firefox compat)
  const ICE_SERVERS: RTCIceServer[] = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];

  const p2pPostSignal = async (roomId: string, sender: string, type: string, payload: unknown) => {
    await fetch(`${API}/api/webrtc/${roomId}/signal/`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender, type, payload }),
    });
  };

  /**
   * Build a LAN-IP URL — always uses the real server LAN IP so mobile devices
   * on the same WiFi network can open the link directly.
   *
   * HTTPS priority: if the backend reports an HTTPS port (cert exists + port
   * is bound), we ALWAYS generate https://LAN-IP:8443/... — even when the
   * current page is served over plain HTTP. This prevents the "can't download
   * securely" block on Chrome/Safari mobile regardless of how the sender
   * opened the app.
   */
  const buildLanUrl = (path: string): string => {
    const lanIp = (serverIp && serverIp !== '127.0.0.1' && serverIp !== 'localhost')
      ? serverIp
      : window.location.hostname;
    // Prefer HTTPS if the runssl server is available
    if (httpsPort) {
      return `https://${lanIp}:${httpsPort}${window.location.pathname}${path}`;
    }
    const portStr = window.location.port ? `:${window.location.port}` : ':8000';
    return `${window.location.protocol}//${lanIp}${portStr}${window.location.pathname}${path}`;
  };

  /**
   * Async version: guarantees a real LAN IP even if serverIp state hasn't
   * been hydrated yet. Also captures httpsPort from the API response so that
   * HTTPS QR links are generated correctly even on first load.
   */
  const getLanIp = async (): Promise<string> => {
    const currentHost = window.location.hostname;
    const isAlreadyLanIp = (
      currentHost !== 'localhost' &&
      currentHost !== '127.0.0.1' &&
      /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(currentHost)
    );
    if (isAlreadyLanIp) {
      setServerIp(currentHost);
      return currentHost;
    }
    if (serverIp && serverIp !== '127.0.0.1' && serverIp !== 'localhost') return serverIp;
    // Fetch from the dedicated lan/ip endpoint (most reliable)
    try {
      const r = await fetch(`${API}/api/lan/ip/`);
      if (r.ok) {
        const d = await r.json();
        const ip: string = d.best || '';
        // Capture HTTPS port from response
        if (typeof d.https_port === 'number') setHttpsPort(d.https_port);
        else if (d.https_port === null)        setHttpsPort(null);
        if (ip && ip !== '127.0.0.1' && ip !== 'localhost') {
          setServerIp(ip);
          return ip;
        }
      }
    } catch { /* offline or endpoint missing — try stats/ */ }
    // Fallback: try stats/ (backward compat)
    try {
      const r = await fetch(`${API}/api/stats/`);
      if (r.ok) {
        const d = await r.json();
        if (typeof d.https_port === 'number') setHttpsPort(d.https_port);
        const ip: string = d.local_ip || '';
        if (ip && ip !== '127.0.0.1' && ip !== 'localhost') {
          setServerIp(ip);
          return ip;
        }
      }
    } catch { /* offline — fall back to current hostname */ }
    return currentHost;
  };

  /**
   * Build a LAN-IP URL that works for cross-device access.
   * Always prefers https:// + httpsPort when the backend reports HTTPS is available.
   */
  const buildLanUrlAsync = async (path: string): Promise<string> => {
    const lanIp = await getLanIp();
    // After getLanIp(), httpsPort state may have been updated — read the ref
    // value via the closure. Because state updates are async we re-check the
    // API response inline so we don't miss a just-fetched https_port.
    if (httpsPort) {
      return `https://${lanIp}:${httpsPort}${window.location.pathname}${path}`;
    }
    const port   = window.location.port || '8000';
    return `${window.location.protocol}//${lanIp}:${port}${window.location.pathname}${path}`;
  };

  const cleanupP2P = () => {
    p2pAbortRef.current = true;
    p2pEsRef.current?.close(); p2pEsRef.current = null;
    p2pPcRef.current?.close(); p2pPcRef.current = null;
  };

  // ─── WebRTC P2P — SENDER (initiator) ───────────────────────────────────────
  const startP2PSend = async (file: File) => {
    if (!file) return;
    p2pAbortRef.current = false;
    setP2pStatus('creating'); setP2pFile(file); setP2pError('');
    setP2pFileName(file.name); setP2pFileSize(file.size);

    try {
      // 1. Create room on signaling server
      const roomRes = await fetch(`${API}/api/webrtc/room/`, { method: 'POST' });
      if (!roomRes.ok) throw new Error('Could not create signaling room');
      const { room_id } = await roomRes.json();
      setP2pRoomId(room_id);

      // 2. Generate AES-256-GCM file key
      const fileKey  = await makeKey();
      const rawKeyBuf = await exportAesKey(fileKey);
      const keyHex   = bufToHex(rawKeyBuf);
      const fragment = `#/p2p?room=${room_id}&key=${keyHex}`;
      const localLink = `${window.location.protocol}//${window.location.host}${window.location.pathname}${fragment}`;
      const lanLink   = buildLanUrl(fragment);
      setP2pLink(localLink); setP2pLanLink(lanLink); setP2pKeyHex(keyHex);

      // 3. Create RTCPeerConnection
      const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
      p2pPcRef.current = pc;
      const dc = pc.createDataChannel('aegix-p2p', { ordered: true });
      dc.binaryType = 'arraybuffer';

      // 4. Trickle ICE — post each candidate as it arrives
      pc.onicecandidate = async (ev) => {
        if (ev.candidate && !p2pAbortRef.current) {
          await p2pPostSignal(room_id, 'initiator', 'ice-candidate', ev.candidate.toJSON());
        }
      };

      // 5. Create offer and set local description (triggers ICE gathering)
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await p2pPostSignal(room_id, 'initiator', 'offer', { type: 'offer', sdp: offer.sdp });
      setP2pStatus('waiting');

      // 6. Listen for answer + ICE candidates via SSE
      const es = new EventSource(`${API}/api/webrtc/${room_id}/stream/?peer=initiator`);
      p2pEsRef.current = es;
      const pendingCandidates: RTCIceCandidateInit[] = [];
      let remoteSet = false;

      const applyPending = async () => {
        for (const c of pendingCandidates) await pc.addIceCandidate(c);
        pendingCandidates.length = 0;
      };

      es.onmessage = async (ev2) => {
        if (p2pAbortRef.current) return;
        let msg: any; try { msg = JSON.parse(ev2.data); } catch { return; }
        if (msg.type === 'answer') {
          setP2pStatus('connecting');
          await pc.setRemoteDescription({ type: 'answer', sdp: msg.payload.sdp });
          remoteSet = true; await applyPending();
        } else if (msg.type === 'ice-candidate' && msg.payload) {
          if (remoteSet) await pc.addIceCandidate(msg.payload);
          else pendingCandidates.push(msg.payload);
        } else if (msg.type === 'error' || msg.type === 'expired' || msg.type === 'end') {
          if (!remoteSet) { setP2pStatus('error'); setP2pError('Peer did not connect in time.'); cleanupP2P(); }
        }
      };
      es.onerror = () => { if (!remoteSet) { setP2pStatus('error'); setP2pError('Signaling connection lost.'); cleanupP2P(); } };

      // 7. Send file when DataChannel opens
      dc.onopen = async () => {
        es.close(); p2pEsRef.current = null;
        setP2pStatus('transferring');
        const totalChunks = Math.ceil(file.size / P2P_CHUNK) || 1;
        setP2pTotalChunks(totalChunks);

        // Send metadata as JSON text first
        dc.send(JSON.stringify({ type: 'meta', name: file.name, size: file.size, totalChunks }));

        // Set flow-control threshold
        dc.bufferedAmountLowThreshold = P2P_CHUNK * 4;

        for (let seq = 0; seq < totalChunks; seq++) {
          if (p2pAbortRef.current) break;
          const start = seq * P2P_CHUNK;
          const end   = Math.min(start + P2P_CHUNK, file.size);
          const plain = await file.slice(start, end).arrayBuffer();

          // Encrypt chunk with a fresh IV
          const iv   = crypto.getRandomValues(new Uint8Array(12));
          const cipher = await aesGcmEncrypt(plain, fileKey, iv);

          // Wire format: [seq:uint32 BE][iv:12 bytes][ciphertext]
          const packet = new Uint8Array(4 + 12 + cipher.byteLength);
          new DataView(packet.buffer).setUint32(0, seq, false);
          packet.set(iv, 4);
          packet.set(new Uint8Array(cipher), 16);
          dc.send(packet.buffer);

          // Flow control: wait if send buffer is filling up
          if (dc.bufferedAmount > P2P_CHUNK * 8) {
            await new Promise<void>(res => {
              dc.onbufferedamountlow = () => { dc.onbufferedamountlow = null; res(); };
            });
          }

          setP2pChunksDone(seq + 1);
          setP2pProgress(Math.round(((seq + 1) / totalChunks) * 100));
        }

        if (!p2pAbortRef.current) {
          dc.send(JSON.stringify({ type: 'done' }));
          setP2pStatus('done');
          await p2pPostSignal(room_id, 'initiator', 'bye', {});
          toast(`"${file.name}" sent via P2P!`, 'ok');
        }
        dc.close(); pc.close();
      };

      dc.onerror = (e) => { setP2pStatus('error'); setP2pError(`DataChannel error: ${e}`); cleanupP2P(); };

    } catch (err: any) {
      setP2pStatus('error'); setP2pError(err?.message || 'Unknown error');
      cleanupP2P();
    }
  };

  // ─── WebRTC P2P — RECEIVER (responder) ────────────────────────────────────
  const startP2PReceive = useCallback(async (roomId: string, keyHex: string) => {
    if (!roomId || !keyHex) return;
    p2pAbortRef.current = false;
    setP2pStatus('connecting'); setP2pError('');

    let fileKey: AesKey;
    try {
      fileKey = await importAesKey(hexToBuf(keyHex), ['decrypt']);
    } catch { setP2pStatus('error'); setP2pError('Invalid decryption key in link.'); return; }

    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    p2pPcRef.current = pc;

    // Pending ICE candidates (arrive before remote desc is set)
    const pendingCandidates: RTCIceCandidateInit[] = [];
    let remoteSet = false;
    const applyPending = async () => {
      for (const c of pendingCandidates) await pc.addIceCandidate(c);
      pendingCandidates.length = 0;
    };

    // Trickle ICE — post our candidates to server
    pc.onicecandidate = async (ev) => {
      if (ev.candidate && !p2pAbortRef.current) {
        await p2pPostSignal(roomId, 'responder', 'ice-candidate', ev.candidate.toJSON());
      }
    };

    // Chunk reassembly state
    const chunkMap = new Map<number, ArrayBuffer>();
    let totalChunks = 0; let received = 0;
    let recvFileName = ''; let recvFileSize = 0;

    pc.ondatachannel = (ev) => {
      const dc = ev.channel;
      dc.binaryType = 'arraybuffer';
      setP2pStatus('transferring');

      dc.onmessage = async (e) => {
        if (p2pAbortRef.current) return;
        if (typeof e.data === 'string') {
          const msg = JSON.parse(e.data);
          if (msg.type === 'meta') {
            recvFileName = msg.name; recvFileSize = msg.size; totalChunks = msg.totalChunks;
            setP2pFileName(msg.name); setP2pFileSize(msg.size); setP2pTotalChunks(msg.totalChunks);
          } else if (msg.type === 'done') {
            // All chunks received — assemble and trigger download
            if (received < totalChunks) {
              setP2pStatus('error'); setP2pError(`Only ${received}/${totalChunks} chunks received.`); return;
            }
            const ordered = Array.from({ length: totalChunks }, (_, i) => chunkMap.get(i)!);
            const blob = new Blob(ordered.map(c => new Uint8Array(c)), { type: 'application/octet-stream' });
            const url  = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = recvFileName;
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 5000);
            setP2pStatus('done'); toast(`"${recvFileName}" saved!`, 'ok');
            await p2pPostSignal(roomId, 'responder', 'bye', {});
            dc.close(); pc.close();
          }
        } else {
          // Binary chunk: [seq:uint32 BE][iv:12][ciphertext]
          const buf  = e.data as ArrayBuffer;
          const seq  = new DataView(buf).getUint32(0, false);
          const iv   = new Uint8Array(buf, 4, 12);
          const ciph = buf.slice(16);
          try {
            const plain = await aesGcmDecrypt(ciph, fileKey, new Uint8Array(iv));
            chunkMap.set(seq, plain);
            received++;
            setP2pChunksDone(received);
            setP2pProgress(Math.round((received / (totalChunks || 1)) * 100));
          } catch { setP2pStatus('error'); setP2pError('Decryption failed — wrong key or corrupted data.'); }
        }
      };
      dc.onerror = () => { setP2pStatus('error'); setP2pError('DataChannel error during receive.'); };
    };

    // Listen for offer + ICE from initiator via SSE
    const es = new EventSource(`${API}/api/webrtc/${roomId}/stream/?peer=responder`);
    p2pEsRef.current = es;

    es.onmessage = async (ev2) => {
      if (p2pAbortRef.current) return;
      let msg: any; try { msg = JSON.parse(ev2.data); } catch { return; }

      if (msg.type === 'offer') {
        await pc.setRemoteDescription({ type: 'offer', sdp: msg.payload.sdp });
        remoteSet = true; await applyPending();
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await p2pPostSignal(roomId, 'responder', 'answer', { type: 'answer', sdp: answer.sdp });
        es.close(); p2pEsRef.current = null;  // close SSE once negotiated
      } else if (msg.type === 'ice-candidate' && msg.payload) {
        if (remoteSet) await pc.addIceCandidate(msg.payload);
        else pendingCandidates.push(msg.payload);
      } else if (msg.type === 'error' || msg.type === 'expired') {
        setP2pStatus('error'); setP2pError(msg.message || 'Signaling error — room may have expired.');
        cleanupP2P();
      }
    };
    es.onerror = () => {
      if (!remoteSet) { setP2pStatus('error'); setP2pError('Lost connection to signaling server.'); cleanupP2P(); }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ─── QR Camera ────────────────────────────────────────────────────────────
  const openScanner = (cb: (v: string) => void, title = 'Scan QR') => {
    setScanCallback(() => cb); setScannerTitle(title); setShowScanner(true); setCameraError(''); setCameraActive(false); startCamera();
  };
  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      streamRef.current = stream;
      if (videoRef.current) { videoRef.current.srcObject = stream; videoRef.current.play(); setCameraActive(true); startScan(); }
    } catch (e: any) { setCameraError(e?.message || 'Camera access denied'); }
  };
  const startScan = () => {
    const tick = () => {
      if (!videoRef.current || !canvasRef.current) return;
      const v = videoRef.current; const c = canvasRef.current;
      c.width = v.videoWidth; c.height = v.videoHeight;
      const ctx = c.getContext('2d');
      if (!ctx || !v.videoWidth) { scanTimerRef.current = requestAnimationFrame(tick); return; }
      ctx.drawImage(v, 0, 0);
      const img = ctx.getImageData(0, 0, c.width, c.height);
      const code = jsQR(img.data, img.width, img.height);
      if (code?.data) { closeScanner(); scanCallback?.(code.data); } else { scanTimerRef.current = requestAnimationFrame(tick); }
    };
    scanTimerRef.current = requestAnimationFrame(tick);
  };
  const closeScanner = () => {
    if (scanTimerRef.current) cancelAnimationFrame(scanTimerRef.current);
    streamRef.current?.getTracks().forEach(t => t.stop()); streamRef.current = null;
    setShowScanner(false); setCameraActive(false);
  };

  const copyLink = async (url: string) => {
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // Fallback for browsers where clipboard API is restricted
      const ta = document.createElement('textarea');
      ta.value = url; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setLinkCopied(true);
    setTimeout(() => setLinkCopied(false), 2500); toast('Copied!', 'ok');
    // Auto-close the link modal if the setting is on
    if (settings.autoCloseModalOnCopy) setShowLinkModal(false);
  };

  // ─── Bluetooth GATT Constants ─────────────────────────────────────────────
  // Custom 128-bit UUID for the Aegix GATT signaling service.
  // A companion app exposing this UUID can receive a P2P URL directly over BLE.
  const AEGIX_SERVICE_UUID  = '0000ae91-0000-1000-8000-00805f9b34fb';
  const AEGIX_URL_CHAR_UUID = '0000ae92-0000-1000-8000-00805f9b34fb';

  const updateBleDevice = (id: string, patch: Partial<BleDeviceInfo>) =>
    setBleDeviceInfos(prev => prev.map(d => d.id === id ? { ...d, ...patch } : d));

  const connectBluetooth = async () => {
    // Web Bluetooth requires a secure context (HTTPS or localhost).
    // On LAN IP accessed via plain HTTP it is silently unavailable.
    if (!window.isSecureContext) {
      toast(
        'Bluetooth requires HTTPS or localhost. Open http://localhost:8000 on this machine, or set up HTTPS.',
        'err',
      );
      return;
    }
    if (!('bluetooth' in navigator)) {
      toast('Web Bluetooth not supported. Use Chrome or Edge on desktop / Android.', 'err'); return;
    }
    try {
      setBleStatus('connecting');
      // requestDevice triggers the browser's native OS Bluetooth picker UI.
      // optionalServices grants access to those service UUIDs after pairing.
      const device = await (navigator as any).bluetooth.requestDevice({
        acceptAllDevices: true,
        optionalServices: [
          'generic_access',
          'generic_attribute',
          'device_information',
          'battery_service',
          AEGIX_SERVICE_UUID,
        ],
      });

      const devId   = device.id as string;
      const devName = (device.name as string | undefined) || `Unknown (${devId.slice(0, 8)})`;

      bleDeviceRefs.current.set(devId, device);

      setBleDeviceInfos(prev => {
        if (prev.find(d => d.id === devId)) {
          return prev.map(d => d.id === devId
            ? { ...d, name: devName, status: 'gatt-connecting', errorMsg: undefined, lastActivity: Date.now() }
            : d);
        }
        return [...prev, { id: devId, name: devName, status: 'gatt-connecting', hasAegixService: false, servicesCount: 0, lastActivity: Date.now() }];
      });
      setBleDevices(p => p.find(d => d.id === devId) ? p : [...p, { name: devName, id: devId }]);

      device.addEventListener('gattserverdisconnected', () => {
        gattServerRefs.current.delete(devId);
        updateBleDevice(devId, { status: 'disconnected', lastActivity: Date.now() });
        toast(`"${devName}" disconnected`, 'info');
      });

      let server: any;
      try {
        server = await device.gatt.connect();
        gattServerRefs.current.set(devId, server);
      } catch (gattErr: any) {
        updateBleDevice(devId, { status: 'error', errorMsg: gattErr?.message || 'GATT connect failed' });
        setBleStatus('idle');
        toast(`"${devName}" found but GATT connect failed: ${gattErr?.message}. Try pairing the device in OS settings first.`, 'err');
        return;
      }

      // Mark as connected immediately — don't wait for service reads to succeed
      updateBleDevice(devId, { status: 'connected', lastActivity: Date.now() });
      setBleStatus('connected');
      toast(`Connected to "${devName}"! Reading services…`, 'ok');

      // Read optional service details asynchronously; failures are informational only
      let manufacturer: string | undefined;
      let battery:      number | undefined;
      let hasAegixService = false;
      let servicesCount   = 0;

      try {
        const svcs: any[] = await server.getPrimaryServices();
        servicesCount = svcs.length;
        for (const s of svcs) { if (s.uuid === AEGIX_SERVICE_UUID) hasAegixService = true; }
      } catch { /* device may not expose service list — not a failure */ }

      try {
        const di = await server.getPrimaryService('device_information');
        const mc = await di.getCharacteristic('manufacturer_name_string');
        const mv = await mc.readValue();
        manufacturer = new TextDecoder().decode(mv).replace(/\0/g, '').trim() || undefined;
      } catch { /* optional */ }

      try {
        const bs = await server.getPrimaryService('battery_service');
        const bc = await bs.getCharacteristic('battery_level');
        const bv = await bc.readValue();
        battery = bv.getUint8(0);
      } catch { /* optional */ }

      updateBleDevice(devId, { manufacturer, battery, hasAegixService, servicesCount, lastActivity: Date.now() });
      const details = [manufacturer, battery !== undefined ? `${battery}%` : undefined].filter(Boolean).join(' · ');
      if (details || servicesCount > 0) {
        toast(`"${devName}" — ${details ? details + ' · ' : ''}${servicesCount} service${servicesCount !== 1 ? 's' : ''}`, 'info');
      }

    } catch (e: any) {
      setBleStatus(e?.name === 'NotFoundError' ? 'idle' : 'error');
      if (e?.name !== 'NotFoundError') toast(`Bluetooth: ${e?.message}`, 'err');
    }
  };

  const sendP2PLinkViaBluetooth = async (devId: string, url: string, devName: string) => {
    const server = gattServerRefs.current.get(devId);
    if (!server || !server.connected) { toast('Device not connected. Reconnect first.', 'err'); return; }
    try {
      const svc   = await server.getPrimaryService(AEGIX_SERVICE_UUID);
      const ch    = await svc.getCharacteristic(AEGIX_URL_CHAR_UUID);
      await ch.writeValue(new TextEncoder().encode(url));
      toast(`P2P link sent to "${devName}" via Bluetooth GATT ✓`, 'ok');
      updateBleDevice(devId, { lastActivity: Date.now() });
    } catch {
      setQrContent(url); setQrTitle(`Bluetooth → ${devName}`); setShowQR(true);
      toast('Device lacks Aegix GATT service — showing QR instead.', 'info');
    }
  };

  const reconnectBleDevice = async (devId: string) => {
    const device = bleDeviceRefs.current.get(devId);
    if (!device) { toast('Device reference lost — please scan again.', 'err'); return; }
    updateBleDevice(devId, { status: 'gatt-connecting', errorMsg: undefined });
    try {
      const server = await device.gatt.connect();
      gattServerRefs.current.set(devId, server);
      let hasAegixService = false; let servicesCount = 0;
      let manufacturer: string | undefined; let battery: number | undefined;
      try { const svcs: any[] = await server.getPrimaryServices(); servicesCount = svcs.length; for (const s of svcs) { if (s.uuid === AEGIX_SERVICE_UUID) hasAegixService = true; } } catch {}
      try { const di = await server.getPrimaryService('device_information'); const mc = await di.getCharacteristic('manufacturer_name_string'); const mv = await mc.readValue(); manufacturer = new TextDecoder().decode(mv).replace(/\0/g, '').trim() || undefined; } catch {}
      try { const bs = await server.getPrimaryService('battery_service'); const bc = await bs.getCharacteristic('battery_level'); const bv = await bc.readValue(); battery = bv.getUint8(0); } catch {}
      updateBleDevice(devId, { status: 'connected', hasAegixService, servicesCount, manufacturer, battery, lastActivity: Date.now() });
      toast(`Reconnected to "${bleDeviceInfos.find(d => d.id === devId)?.name || devId}"`, 'ok');
    } catch (e: any) {
      updateBleDevice(devId, { status: 'error', errorMsg: e?.message || 'Reconnect failed' });
      toast(`Reconnect failed: ${e?.message}`, 'err');
    }
  };

  // Web Serial — Bluetooth Classic / SPP virtual COM ports (Windows desktop)
  // Paired Bluetooth devices with Serial Port Profile create COM ports the
  // browser can access via navigator.serial. We write AEGIX_P2P:<url>\n
  // so any listening software can parse and open the P2P link.
  const connectBluetoothSerial = async (url: string) => {
    if (!('serial' in navigator)) { toast('Web Serial not supported — use Chrome/Edge on desktop.', 'err'); return; }
    let port: any = null;
    try {
      port = await (navigator as any).serial.requestPort({ filters: [] });
      await port.open({ baudRate: 115200 });
      const writer = port.writable.getWriter();
      await writer.write(new TextEncoder().encode(`AEGIX_P2P:${url}\n`));
      await writer.close();
      toast('P2P link sent via Bluetooth Serial (SPP) ✓', 'ok');
    } catch (e: any) {
      if (e?.name !== 'NotFoundError') toast(`Serial: ${e?.message}`, 'err');
    } finally {
      if (port) { try { await port.close(); } catch {} }
    }
  };


  const handleReceiveLink = () => {
    const trimmed = recvLink.trim();
    if (!trimmed) { toast('Paste a link first.', 'err'); return; }
    try {
      const url = new URL(trimmed);
      // Extract just the hash — works regardless of what host the link was generated from.
      // This lets you receive a link even if it was generated with a different hostname.
      if (url.hash.startsWith('#/download')) {
        window.location.hash = url.hash.slice(1);
        return;
      }
    } catch { /* not a full URL — might be just the hash fragment */ }
    // Handle bare hash strings like "#/download?id=...&key=..."
    if (trimmed.startsWith('#/download')) {
      window.location.hash = trimmed.slice(1);
    } else if (trimmed.includes('#/download')) {
      window.location.hash = trimmed.slice(trimmed.indexOf('#/download') + 1);
    } else {
      toast('Invalid link format. Paste the full Aegix share link.', 'err');
    }
  };

  // ─── Sidebar nav items ────────────────────────────────────────────────────
  const NAV = [
    { id: 'send' as Tab,     icon: <Upload className="w-5 h-5" />,   label: 'Send & Receive' },
    { id: 'nearby' as Tab,   icon: <Radio className="w-5 h-5" />,    label: 'Nearby' },
    { id: 'history' as Tab,  icon: <Clock className="w-5 h-5" />,    label: 'History' },
    { id: 'library' as Tab,  icon: <Database className="w-5 h-5" />, label: 'Library' },
    { id: 'settings' as Tab, icon: <Settings className="w-5 h-5" />, label: 'Settings' },
    { id: 'profile' as Tab,  icon: <User className="w-5 h-5" />,     label: 'Profile' },
  ];

  // ─── AUTH ─────────────────────────────────────────────────────────────────
  if (!isLoggedIn) {
    return (
      <div style={{minHeight:'100dvh',background:'var(--c-bg)',display:'flex',alignItems:'center',justifyContent:'center',padding:'var(--sp-4)'}}>
        <div style={{width:'100%',maxWidth:'360px'}}>
          <div style={{textAlign:'center',marginBottom:'var(--sp-8)'}}>
            <div style={{display:'inline-flex',alignItems:'center',justifyContent:'center',width:'44px',height:'44px',borderRadius:'var(--r-lg)',background:'var(--c-accent-x)',border:'1px solid var(--c-accent-b)',marginBottom:'var(--sp-4)'}}>
              <Shield size={22} color="var(--c-accent)" />
            </div>
            <h1 style={{fontSize:'var(--ts-xl)',fontWeight:700,color:'var(--c-t1)',letterSpacing:'-0.02em',marginBottom:'4px'}}>AEGIX SHARE</h1>
            <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',letterSpacing:'0.04em'}}>Zero-knowledge encrypted file sharing</p>
          </div>
          <div className="card" style={{padding:'var(--sp-6)'}}>
            <div style={{display:'flex',background:'var(--c-bg)',border:'1px solid var(--c-b1)',borderRadius:'var(--r-lg)',padding:'3px',marginBottom:'var(--sp-6)',gap:'3px'}}>
              {(['login', 'register'] as AuthPage[]).map(p => (
                <button key={p} onClick={() => setAuthPage(p)}
                  style={{flex:1,padding:'8px 12px',borderRadius:'var(--r-md)',fontSize:'var(--ts-xs)',fontWeight:600,cursor:'pointer',
                    border:authPage===p?'1px solid var(--c-accent-b)':'1px solid transparent',
                    background:authPage===p?'var(--c-accent-x)':'transparent',
                    color:authPage===p?'var(--c-accent)':'var(--c-t3)',
                    transition:'all 0.15s ease',fontFamily:'inherit'}}>
                  {p === 'login' ? 'Sign In' : 'Create Account'}
                </button>
              ))}
            </div>
            <div style={{display:'flex',flexDirection:'column',gap:'var(--sp-3)'}}>
              {authPage === 'register' && (
                <input className="input" value={authName} onChange={e => setAuthName(e.target.value)} placeholder="Full name" />
              )}
              <input className="input" value={authEmail} onChange={e => setAuthEmail(e.target.value)} placeholder="Email address" type="email" />
              <div style={{position:'relative'}}>
                <input className="input" value={authPwd} onChange={e => setAuthPwd(e.target.value)} placeholder="Password" type={showPwd ? 'text' : 'password'} style={{paddingRight:'44px'}} />
                <button onClick={() => setShowPwd(p => !p)} className="btn-ghost" style={{position:'absolute',right:'8px',top:'50%',transform:'translateY(-50%)',padding:'4px'}}>
                  {showPwd ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              <button className="btn-primary" style={{width:'100%',padding:'11px',marginTop:'var(--sp-2)'}}
                onClick={() => {
                  if (authPage === 'register' && authName) setProfileName(authName);
                  if (authEmail) setProfileEmail(authEmail);
                  setIsGuest(false); setIsLoggedIn(true);
                  toast(`Welcome${authPage === 'register' ? `, ${authName || 'User'}` : ' back'}!`, 'ok');
                }}>
                {authPage === 'login' ? 'Sign In' : 'Create Account'}
              </button>
              <div style={{display:'flex',alignItems:'center',gap:'var(--sp-3)'}}>
                <div className="divider" style={{flex:1}} />
                <span style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',letterSpacing:'0.08em',textTransform:'uppercase'}}>or</span>
                <div className="divider" style={{flex:1}} />
              </div>
              <button className="btn-secondary" style={{width:'100%',padding:'11px'}}
                onClick={() => { setIsGuest(true); setIsLoggedIn(true); setProfileName('Guest'); setProfileEmail(''); toast('Continuing as guest.', 'info'); }}>
                <User size={15} /> Continue as Guest
              </button>
            </div>
          </div>
          <p style={{textAlign:'center',fontSize:'var(--ts-xs)',color:'var(--c-t3)',marginTop:'var(--sp-4)'}}>No account required to receive · End-to-end encrypted</p>
        </div>
        <ToastStack toasts={toasts} />
      </div>
    );
  }

  // ─── RECEIVER page ────────────────────────────────────────────────────────
  if (receiverMode) {
    // ── Show loading / error while fetching or if meta is unavailable ─────────
    if (!recvMeta) {
      return (
        <div className="min-h-dvh bg-[#0d0e17] flex items-center justify-center p-4">
          <div className="w-full max-w-md">
            <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden shadow-2xl p-10 flex flex-col items-center gap-5 text-center">
              {recvStatus === 'connecting' ? (
                <>
                  <div className="w-12 h-12 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                  <p className="text-white font-extrabold text-base">Loading secure link…</p>
                  <p className="text-xs text-slate-500">Verifying transfer on server</p>
                </>
              ) : (
                <>
                  <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                    <AlertTriangle className="w-7 h-7 text-red-400" />
                  </div>
                  <div>
                    <h1 className="text-white font-extrabold text-base mb-1">Link unavailable</h1>
                    <p className="text-sm text-slate-400 leading-relaxed">
                      This link has <strong className="text-red-400">expired</strong>, reached its
                      <strong className="text-red-400"> download limit</strong>, or is invalid.
                    </p>
                  </div>
                  <button
                    onClick={() => { window.location.hash = ''; window.location.reload(); }}
                    className="px-6 py-2.5 rounded-xl bg-[#1a1d2e] border border-[#1e2133] text-slate-300 text-xs font-bold hover:bg-[#20243a] transition-all">
                    ← Go back
                  </button>
                </>
              )}
            </div>
          </div>
          <ToastStack toasts={toasts} />
        </div>
      );
    }

    // ── Normal receiver UI with metadata ──────────────────────────────────
    const hasPassword = recvMeta.wrapped_key?.length > 0;
    const downloadsLeft = recvMeta.download_limit > 0
      ? recvMeta.download_limit - recvMeta.download_count
      : null;
    return (
      <div className="min-h-dvh bg-[#0d0e17] flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden shadow-2xl">
            <div className="px-6 pt-6 pb-4 border-b border-[#1e2133]">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-emerald-400" />
                </div>
                <div><h1 className="font-extrabold text-white text-sm">Secure file received</h1><p className="text-[10px] text-slate-500">AES-256-GCM · Zero-knowledge</p></div>
              </div>
            </div>
            <div className="px-6 py-5 flex flex-col gap-4">
              <div className="flex items-center gap-3 p-3.5 rounded-xl bg-[#0d0e17] border border-[#1e2133]">
                <File className="w-8 h-8 text-indigo-400 shrink-0" />
                <div className="min-w-0">
                  <p className="text-sm font-bold text-slate-200 truncate">{recvMeta.name}</p>
                  <p className="text-[10px] text-slate-500">{fmtBytes(recvMeta.size)} · {recvMeta.total_chunks} chunk{recvMeta.total_chunks !== 1 ? 's' : ''}</p>
                </div>
              </div>
              {hasPassword && recvStatus === 'idle' && (
                <div>
                  <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1.5 block">Password required</label>
                  <div className="relative">
                    <input type={showRecvPwd ? 'text' : 'password'} placeholder="Enter transfer password"
                      value={recvPassword} onChange={e => setRecvPassword(e.target.value)} onKeyDown={e => e.key === 'Enter' && startDownload()}
                      className="w-full bg-[#0d0e17] border border-[#1e2133] rounded-xl px-4 py-3 pr-11 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 placeholder-slate-600" />
                    <button onClick={() => setShowRecvPwd(p => !p)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                      {showRecvPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              )}
              {recvStatus === 'downloading' && (
                <div className="flex flex-col gap-2">
                  <div className="flex justify-between text-xs"><span className="font-bold text-indigo-400">Decrypting…</span><span className="text-slate-400">{recvChunksGot}/{recvMeta.total_chunks}</span></div>
                  <div className="h-2 bg-[#0d0e17] rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full transition-all duration-300" style={{ width: `${recvProgress}%` }} /></div>
                </div>
              )}
              {recvStatus === 'done' && (
                <div className="flex flex-col gap-2.5">
                  <div className="flex items-center gap-3 p-3.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20">
                    <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                    <div>
                      <p className="text-sm font-bold text-emerald-300">File decrypted ✓</p>
                      <p className="text-[10px] text-slate-500">Tap the button below to save it to your device</p>
                    </div>
                  </div>
                  {/* Save File anchor — this IS a real user gesture so mobile Chrome/Safari allow download */}
                  {recvDownloadReady && (
                    <a
                      id="save-file-btn"
                      href={recvDownloadReady.blobUrl}
                      download={recvDownloadReady.filename}
                      onClick={(e) => {
                        // iOS Safari: blob download via anchor doesn't work;
                        // open in new tab so Safari's share sheet offers Save to Files
                        if (/iP(hone|ad|od)/i.test(navigator.userAgent)) {
                          e.preventDefault();
                          const w = window.open(recvDownloadReady.blobUrl, '_blank');
                          if (!w) toast('Allow pop-ups then tap again, or long-press the link to save.', 'info');
                        }
                      }}
                      className="w-full py-3.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 text-white font-extrabold text-sm flex items-center justify-center gap-2 shadow-lg hover:from-emerald-500 hover:to-teal-500 transition-all text-center no-underline"
                    >
                      <Download className="w-4 h-4" /> Save File — {recvDownloadReady.filename}
                    </a>
                  )}
                </div>
              )}
              {recvStatus === 'error' && (<div className="flex items-center gap-3 p-3.5 rounded-xl bg-red-500/8 border border-red-500/20"><AlertTriangle className="w-5 h-5 text-red-400 shrink-0" /><p className="text-sm font-bold text-red-300">Transfer failed — tap Retry to try again</p></div>)}
              <div className="flex flex-wrap gap-1.5">
                {recvMeta.self_destruct && <span className="text-[10px] font-bold text-amber-300 bg-amber-500/10 px-2.5 py-1 rounded-full border border-amber-500/20">Self-destruct</span>}
                {hasPassword && <span className="text-[10px] font-bold text-purple-300 bg-purple-500/10 px-2.5 py-1 rounded-full border border-purple-500/20">Password protected</span>}
                {downloadsLeft !== null && (
                  <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full border ${
                    downloadsLeft > 0
                      ? 'text-indigo-300 bg-indigo-500/10 border-indigo-500/20'
                      : 'text-red-300 bg-red-500/10 border-red-500/20'
                  }`}>{downloadsLeft > 0 ? `${downloadsLeft} download${downloadsLeft !== 1 ? 's' : ''} left` : 'Download limit reached'}</span>
                )}
              </div>
              {(recvStatus === 'idle' || recvStatus === 'error') && downloadsLeft !== 0 && (
                <button onClick={startDownload}
                  className="w-full py-3.5 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-extrabold text-sm flex items-center justify-center gap-2 shadow-lg hover:from-indigo-500 hover:to-purple-500 transition-all">
                  <Download className="w-4 h-4" /> {recvStatus === 'error' ? 'Retry Download' : 'Decrypt & Download'}
                </button>
              )}
            </div>
          </div>
        </div>
        <ToastStack toasts={toasts} />
      </div>
    );
  }


  // ─── P2P RECEIVER PAGE (────────────────────────────────────────────────
  if (p2pMode === 'receive' && p2pRoomId && p2pKeyHex) {
    // Auto-start receive on first render for this room
    if (p2pStatus === 'connecting') {
      // Kick off receive async (avoids calling async in render)
      setTimeout(() => startP2PReceive(p2pRoomId!, p2pKeyHex!), 0);
    }
    return (
      <div className="min-h-dvh bg-[#0d0e17] flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden shadow-2xl">
            <div className="px-6 pt-6 pb-4 border-b border-[#1e2133]">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                  <Wifi className="w-5 h-5 text-blue-400" />
                </div>
                <div><h1 className="font-extrabold text-white text-sm">P2P Direct Transfer</h1><p className="text-[10px] text-slate-500">WebRTC · AES-256-GCM · End-to-end encrypted</p></div>
              </div>
            </div>
            <div className="px-6 py-5 flex flex-col gap-4">
              {(p2pStatus === 'connecting' || p2pStatus === 'waiting') && (
                <div className="flex items-center gap-3 p-3.5 rounded-xl bg-indigo-500/8 border border-indigo-500/20">
                  <div className="w-4 h-4 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin shrink-0" />
                  <p className="text-xs font-bold text-indigo-300">Connecting to sender…</p>
                </div>
              )}
              {p2pStatus === 'transferring' && (
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-3 p-3.5 rounded-xl bg-[#0d0e17] border border-[#1e2133]">
                    <File className="w-7 h-7 text-blue-400 shrink-0" />
                    <div className="min-w-0"><p className="text-xs font-bold text-slate-200 truncate">{p2pFileName}</p><p className="text-[10px] text-slate-500">{fmtBytes(p2pFileSize)}</p></div>
                  </div>
                  <div className="flex justify-between text-xs"><span className="font-bold text-blue-400">Receiving via P2P…</span><span className="text-slate-400">{p2pChunksDone}/{p2pTotalChunks}</span></div>
                  <div className="h-2 bg-[#0d0e17] rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 rounded-full transition-all duration-300" style={{ width: `${p2pProgress}%` }} /></div>
                </div>
              )}
              {p2pStatus === 'done' && (<div className="flex items-center gap-3 p-3.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20"><CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" /><div><p className="text-sm font-bold text-emerald-300">File saved to downloads</p><p className="text-[10px] text-slate-500">Direct P2P — never touched the server</p></div></div>)}
              {p2pStatus === 'error' && (<div className="flex items-center gap-3 p-3.5 rounded-xl bg-red-500/8 border border-red-500/20"><AlertTriangle className="w-5 h-5 text-red-400 shrink-0" /><p className="text-sm font-bold text-red-300">{p2pError || 'Transfer failed'}</p></div>)}
              <div className="flex items-start gap-2 p-3 rounded-xl bg-blue-500/5 border border-blue-500/10">
                <Zap className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                <p className="text-[10px] text-slate-500">Files transfer directly device-to-device. The server only handles the initial handshake — your file data never passes through it.</p>
              </div>
            </div>
          </div>
        </div>
        <ToastStack toasts={toasts} />
      </div>
    );
  }

  // ─── MAIN APP ─────────────────────────────────────────────────────────────
  return (
    <div style={{minHeight:'100dvh',background:'var(--c-bg)',display:'flex'}}>
      {/* Sidebar — desktop */}
      <aside className="hidden md:flex" style={{flexDirection:'column',width:'60px',borderRight:'1px solid var(--c-b1)',paddingTop:'var(--sp-4)',paddingBottom:'var(--sp-4)',gap:'2px',alignItems:'center',flexShrink:0}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'center',width:'34px',height:'34px',borderRadius:'var(--r-lg)',background:'var(--c-accent-x)',border:'1px solid var(--c-accent-b)',marginBottom:'var(--sp-6)'}}>
          <Shield size={17} color="var(--c-accent)" />
        </div>
        {NAV.map(n => (
          <button key={n.id} onClick={() => setTab(n.id)} title={n.label}
            className="nav-item" data-active={String(tab === n.id)}
            style={{width:'40px',height:'40px',flexShrink:0}}>
            {n.icon}
          </button>
        ))}
      </aside>

      {/* Main */}
      <main id="aegix-app-root" style={{flex:1,display:'flex',flexDirection:'column',maxHeight:'100dvh',overflow:'hidden'}}>
        {/* Mobile header */}
        <header className="md:hidden" style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'12px 16px',borderBottom:'1px solid var(--c-b1)'}}>
          <div style={{display:'flex',alignItems:'center',gap:'var(--sp-2)'}}>
            <div style={{width:'28px',height:'28px',borderRadius:'var(--r-md)',background:'var(--c-accent-x)',border:'1px solid var(--c-accent-b)',display:'flex',alignItems:'center',justifyContent:'center'}}>
              <Shield size={14} color="var(--c-accent)" />
            </div>
            <span className="wordmark">AEGIX <span>SHARE</span></span>
          </div>
          <span style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)'}}>{NAV.find(n => n.id === tab)?.label}</span>
        </header>

        <div style={{flex:1,overflowY:'auto'}}>
          <div style={{maxWidth:'672px',margin:'0 auto',padding:'var(--sp-6) var(--sp-4)',display:'flex',flexDirection:'column',gap:'var(--sp-6)'}}>

            {/* ── HTTP security notice ── */}
            {!window.isSecureContext &&
             window.location.hostname !== 'localhost' &&
             window.location.hostname !== '127.0.0.1' && (
              <div style={{background:'color-mix(in srgb,var(--c-warn) 8%,transparent)',border:'1px solid color-mix(in srgb,var(--c-warn) 28%,transparent)',borderRadius:'var(--r-xl)',padding:'var(--sp-3) var(--sp-4)',display:'flex',alignItems:'flex-start',gap:'var(--sp-3)'}}>
                <Lock size={15} color="var(--c-warn)" style={{flexShrink:0,marginTop:'1px'}} />
                <div>
                  <p style={{fontSize:'var(--ts-sm)',fontWeight:600,color:'var(--c-warn)'}}>HTTP — File downloads may be blocked on mobile</p>
                  <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',marginTop:'2px'}}>
                    Run <span style={{fontFamily:"var(--font-mono)",color:'var(--c-accent)'}}>start_https.bat</span> for HTTPS mode (port 8443), then reopen from that URL.
                  </p>
                </div>
              </div>
            )}

            {/* ── SEND & RECEIVE TAB ── */}
            {tab === 'send' && (
              <div style={{display:'flex',flexDirection:'column',gap:'var(--sp-6)'}}>
                <div>
                  <h1 style={{fontSize:'var(--ts-2xl)',fontWeight:700,color:'var(--c-t1)',letterSpacing:'-0.02em'}}>Send &amp; Receive</h1>
                  <p style={{fontSize:'var(--ts-sm)',color:'var(--c-t3)',marginTop:'var(--sp-1)'}}>Zero-knowledge end-to-end encryption — servers never see your data</p>
                </div>

                {/* Sub-tabs */}
                <div style={{display:'flex',borderBottom:'1px solid var(--c-b1)',gap:'var(--sp-6)'}}>
                  {([['send', 'Send'], ['receive', 'Receive']] as [SendSubTab, string][]).map(([id, label]) => (
                    <button key={id} onClick={() => setSendSubTab(id)}
                      className="tab-btn" data-active={String(sendSubTab === id)}>
                      {label}
                    </button>
                  ))}
                </div>

                {/* ── SEND SUB-TAB ── */}
                {sendSubTab === 'send' && (
                  <div style={{display:'flex',flexDirection:'column',gap:'var(--sp-5)'}}>
                    <div>
                      <p className="section-label" style={{marginBottom:'var(--sp-3)'}}>Select files</p>
                      <div
                        onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={e => { e.preventDefault(); setIsDragging(false); setUploadQueue(Array.from(e.dataTransfer.files)); }}
                        onClick={() => document.getElementById('file-input')?.click()}
                        className="drop-zone" data-active={String(isDragging)}
                        style={{padding:'var(--sp-12) var(--sp-4)'}}
                      >
                        <input type="file" id="file-input" className="hidden" onChange={e => setUploadQueue(Array.from(e.target.files || []))} />
                        <div style={{width:'48px',height:'48px',borderRadius:'var(--r-xl)',background:'var(--c-s2)',border:'1px solid var(--c-b1)',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--c-t3)'}}>
                          <Upload size={22} />
                        </div>
                        <div style={{textAlign:'center'}}>
                          <p style={{fontWeight:600,color:'var(--c-t1)',fontSize:'var(--ts-base)'}}>Drop files here</p>
                          <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',marginTop:'4px'}}>Any file type · No size limit · AES-256 encrypted</p>
                        </div>
                        <button className="btn-secondary" style={{fontSize:'var(--ts-xs)'}}>Browse files</button>
                      </div>
                    </div>

                    {uploadQueue.length > 0 && (
                      <div className="card" style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'var(--sp-3) var(--sp-4)'}}>
                        <div style={{display:'flex',alignItems:'center',gap:'var(--sp-3)',minWidth:0}}>
                          <File size={16} color="var(--c-accent)" style={{flexShrink:0}} />
                          <div style={{minWidth:0}}>
                            <p style={{fontSize:'var(--ts-sm)',fontWeight:600,color:'var(--c-t1)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{uploadQueue[0].name}</p>
                            <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)'}}>{fmtBytes(uploadQueue[0].size)}</p>
                          </div>
                        </div>
                        <button onClick={() => setUploadQueue([])} className="btn-ghost" style={{padding:'4px',color:'var(--c-err)',flexShrink:0,marginLeft:'var(--sp-2)'}}><X size={15} /></button>
                      </div>
                    )}

                    {/* Security settings */}
                    <div className="card" style={{padding:'var(--sp-5)',display:'flex',flexDirection:'column',gap:'var(--sp-4)'}}>
                      <div className="flex items-center gap-2">
                        <Lock size={14} color="var(--c-accent)" />
                        <p className="section-label">Security Settings</p>
                      </div>

                      <div className="flex flex-col gap-1.5">
                        <label className="section-label">Link expires in</label>
                        <select value={linkExpiry} onChange={e => setLinkExpiry(Number(e.target.value))}
                          className="bg-[#0d0e17] border border-[#1e2133] rounded-xl text-xs px-3.5 py-3 text-slate-200 focus:outline-none focus:border-indigo-500">
                          {EXPIRY_OPTIONS.map(o => <option key={o.label} value={o.value}>{o.label}</option>)}
                        </select>
                      </div>

                      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
                        <div>
                          <p style={{fontSize:'var(--ts-sm)',fontWeight:500,color:'var(--c-t1)'}}>Self-destruct after download</p>
                          <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',marginTop:'2px'}}>Link becomes permanently invalid after first download</p>
                        </div>
                        <Toggle val={selfDestruct} onChange={() => setSelfDestruct(p => !p)} />
                      </div>

                      <div className="flex flex-col gap-1.5">
                        <label className="section-label">Download limit</label>
                        <select value={downloadLimit} onChange={e => setDownloadLimit(Number(e.target.value))}
                          className="bg-[#0d0e17] border border-[#1e2133] rounded-xl text-xs px-3.5 py-3 text-slate-200 focus:outline-none focus:border-indigo-500">
                          {DOWNLOAD_LIMIT_OPTIONS.map(o => <option key={o.label} value={o.value}>{o.label}</option>)}
                        </select>
                      </div>

                      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
                        <div>
                          <p style={{fontSize:'var(--ts-sm)',fontWeight:500,color:'var(--c-t1)'}}>Require password</p>
                          <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',marginTop:'2px'}}>Recipients must enter a password to access files</p>
                        </div>
                        <Toggle val={requirePassword} onChange={() => { setRequirePassword(p => !p); if (requirePassword) setPassword(''); }} />
                      </div>

                      {requirePassword && (
                        <div style={{position:'relative'}}>
                          <input className="input" type={showSendPwd ? 'text' : 'password'} placeholder="Set access password" value={password} onChange={e => setPassword(e.target.value)} style={{paddingRight:'44px'}} />
                          <button onClick={() => setShowSendPwd(p => !p)} className="btn-ghost" style={{position:'absolute',right:'8px',top:'50%',transform:'translateY(-50%)',padding:'4px'}}>
                            {showSendPwd ? <EyeOff size={14} /> : <Eye size={14} />}
                          </button>
                        </div>
                      )}
                    </div>

                    <div style={{display:'flex',alignItems:'center',justifyContent:'flex-end',gap:'var(--sp-3)'}}>
                      <button className="btn-secondary" style={{padding:'10px 20px'}} onClick={() => { setUploadQueue([]); setPassword(''); setRequirePassword(false); }}>Clear</button>
                      <button className="btn-primary" style={{padding:'10px 24px'}} onClick={startUpload} disabled={!uploadQueue.length || isUploading}>
                        <Shield size={15} /> {isUploading ? 'Encrypting…' : 'Encrypt & Share'} <ArrowRight size={15} />
                      </button>
                    </div>

                    {/* Upload progress */}
                    {transfers.filter(t => t.status === 'uploading').map(t => (
                      <div key={t.id} className="p-4 rounded-2xl bg-[#13161f] border border-[#1e2133] flex flex-col gap-2">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-[var(--c-accent)] animate-pulse" /><span className="font-bold text-slate-200 truncate max-w-xs">{t.name}</span></div>
                          <span className="font-bold shrink-0" style={{color:"var(--c-accent)"}}>{t.uploadedChunks}/{t.totalChunks}</span>
                        </div>
                        <div className="h-1.5 bg-[#0d0e17] rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full transition-all" style={{ width: `${Math.round((t.uploadedChunks / t.totalChunks) * 100)}%` }} /></div>
                      </div>
                    ))}

                    {/* Completed */}
                    {transfers.filter(t => t.status === 'done').map(t => (
                      <div key={t.id} className="p-4 rounded-2xl bg-[#13161f] border border-emerald-500/15 flex flex-col gap-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2.5">
                            <div className="w-8 h-8 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center"><Check className="w-4 h-4 text-emerald-400" /></div>
                            <div><p className="text-xs font-bold text-slate-200 truncate max-w-xs">{t.name}</p><p className="text-[10px] text-slate-500">{fmtBytes(t.size)} · {t.totalChunks} chunks</p></div>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <button onClick={() => { setQrContent(t.downloadUrl); setQrTitle(`QR — ${t.name}`); setShowQR(true); }}
                              className="p-2 rounded-lg bg-[#1a1d2e] hover:bg-[#20243a] border border-[#1e2133] text-slate-500 hover:text-indigo-400 transition-all"><QrCode className="w-3.5 h-3.5" /></button>
                            <button onClick={() => copyLink(t.downloadUrl)}
                              className="p-2 rounded-lg bg-indigo-600/10 hover:bg-indigo-600/20 border border-indigo-500/20 text-indigo-400 text-xs font-bold flex items-center gap-1.5 transition-all"><Copy className="w-3.5 h-3.5" /> Copy</button>
                            <button onClick={() => setTransfers(p => p.filter(x => x.id !== t.id))} className="p-2 text-slate-600 hover:text-red-400 transition-colors"><X className="w-3.5 h-3.5" /></button>
                          </div>
                        </div>
                        <div className="text-[10px] text-slate-500 bg-[#0d0e17] px-3 py-2.5 rounded-lg border border-[#1e2133] font-mono break-all select-all">{t.downloadUrl}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* ── RECEIVE SUB-TAB ── */}
                {sendSubTab === 'receive' && (
                  <div className="flex flex-col gap-5">
                    {/* QR Scanner area */}
                    <div>
                      <div className="flex items-center gap-2 mb-3"><QrCode className="w-4 h-4 text-indigo-400" /><h2 className="text-sm font-bold text-slate-200">Scan QR code</h2></div>
                      <div
                        onClick={() => openScanner(data => {
                          if (data.includes('#/download')) window.location.hash = data.slice(data.indexOf('#/download') + 1);
                          else { setRecvLink(data); setSendSubTab('receive'); }
                        }, 'Scan Aegix QR')}
                        className="border-2 border-dashed border-[#1e2133] rounded-2xl py-12 flex flex-col items-center gap-4 cursor-pointer hover:border-indigo-500/40 hover:bg-[#1a1d2e]/20 transition-all">
                        <div className="w-12 h-12 flex items-center justify-center text-slate-600">
                          <svg viewBox="0 0 24 24" className="w-10 h-10" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" />
                            <rect x="14" y="14" width="3" height="3" /><rect x="18" y="14" width="3" height="3" /><rect x="14" y="18" width="3" height="3" /><rect x="18" y="18" width="3" height="3" />
                          </svg>
                        </div>
                        <div className="text-center"><p className="font-bold text-slate-200 text-sm">Point camera at QR code</p><p className="text-[11px] text-slate-500 mt-1">Tap to open camera · scans the link automatically</p></div>
                        <button className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-indigo-500/25 text-indigo-400 text-xs font-bold hover:bg-indigo-600/10 transition-all">
                          <Camera className="w-3.5 h-3.5" /> Open camera scanner
                        </button>
                      </div>
                    </div>

                    {/* Paste link */}
                    <div>
                      <div className="flex items-center gap-2 mb-3"><Link2 className="w-4 h-4 text-indigo-400" /><h2 className="text-sm font-bold text-slate-200">Or paste link manually</h2></div>
                      <p className="text-[11px] text-slate-500 mb-2">Secure share link</p>
                      <input value={recvLink} onChange={e => setRecvLink(e.target.value)} placeholder="Paste the full Aegix share link here…"
                        onKeyDown={e => e.key === 'Enter' && handleReceiveLink()}
                        className="w-full bg-[#1a1d2e] border border-[#1e2133] rounded-xl px-4 py-3.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 placeholder-slate-600 mb-3" />
                      <button onClick={handleReceiveLink}
                        className="btn-primary">
                        <Download className="w-4 h-4" /> Decrypt & download
                      </button>
                    </div>

                    <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/15 flex items-start gap-3">
                      <Shield className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div><p className="text-xs font-bold text-emerald-300">Zero-knowledge decryption</p><p className="text-[10px] text-slate-500 mt-0.5">The encryption key is embedded in the link fragment (after #) and never transmitted to any server. Decryption happens entirely in your browser.</p></div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── NEARBY TAB ── */}
            {tab === 'nearby' && (
              <div className="flex flex-col gap-5">
                <div>
                  <h1 className="text-2xl font-extrabold text-white tracking-tight">Nearby Devices</h1>
                  <p className="text-xs text-slate-500 mt-1">Real Bluetooth LE scanning + encrypted WebRTC P2P transfer — no internet required</p>
                </div>

                {/* Sub-tabs */}
                <div className="flex border-b border-[#1e2133]">
                  {([['lan', 'LAN / QR Share'], ['wifi', 'WiFi · Same device'], ['ble', 'Bluetooth LE']] as [NearbySubTab, string][]).map(([id, label]) => (
                    <button key={id} onClick={() => setNearbySubTab(id)}
                      className={`pb-3 mr-6 text-sm font-bold transition-all border-b-2 -mb-px whitespace-nowrap ${nearbySubTab === id ? 'text-indigo-400 border-indigo-500' : 'text-slate-500 border-transparent hover:text-slate-300'}`}>
                      {label}
                    </button>
                  ))}
                </div>

                {/* ── LAN / QR Share ── */}
                {nearbySubTab === 'lan' && (
                  <div className="flex flex-col gap-4">
                    <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-4 flex flex-col gap-1">
                      <div className="flex items-center gap-2 mb-1"><Wifi className="w-4 h-4 text-indigo-400" /><span className="text-sm font-bold text-slate-200">LAN / local network sharing</span></div>
                      <p className="text-[11px] text-slate-500 leading-relaxed">Like SHAREit — direct device-to-device transfer over your WiFi network. No internet required. Files are AES-256-GCM encrypted before leaving your device. Supports files up to 1 GB.</p>
                    </div>

                    {/* Step 1: Select files */}
                    <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-5 flex flex-col gap-3">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="w-6 h-6 rounded-full bg-indigo-600 flex items-center justify-center text-white text-[11px] font-bold shrink-0">1</div>
                        <h3 className="text-sm font-bold text-slate-200">Select files to share</h3>
                      </div>
                      <div
                        onClick={() => document.getElementById('nearby-file-input')?.click()}
                        className="border-2 border-dashed border-[#1e2133] hover:border-indigo-500/40 rounded-xl py-8 flex flex-col items-center gap-3 cursor-pointer transition-all hover:bg-[#1a1d2e]/30">
                        <input type="file" id="nearby-file-input" className="hidden" multiple onChange={e => setNearbyFiles(Array.from(e.target.files || []))} />
                        <FolderOpen className="w-8 h-8 text-slate-600" />
                        <div className="text-center"><p className="text-xs font-bold text-slate-300">Click to select files</p><p className="text-[10px] text-slate-500 mt-0.5">Any file type · up to 1 GB</p></div>
                      </div>
                      {nearbyFiles.length > 0 && (
                        <div className="flex flex-col gap-2">
                          {nearbyFiles.map((f, i) => (
                            <div key={i} className="flex items-center gap-2.5 p-2.5 rounded-lg bg-[#0d0e17] border border-[#1e2133]">
                              <File className="w-4 h-4 text-indigo-400 shrink-0" />
                              <div className="flex-1 min-w-0"><p className="text-xs font-bold text-slate-200 truncate">{f.name}</p><p className="text-[10px] text-slate-500">{fmtBytes(f.size)}</p></div>
                              <button onClick={() => setNearbyFiles(p => p.filter((_, j) => j !== i))} className="text-slate-600 hover:text-red-400 transition-colors"><X className="w-3.5 h-3.5" /></button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Step 2: Choose role */}
                    <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-5 flex flex-col gap-3">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="w-6 h-6 rounded-full bg-indigo-600 flex items-center justify-center text-white text-[11px] font-bold shrink-0">2</div>
                        <h3 className="text-sm font-bold text-slate-200">Choose your role</h3>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <button onClick={() => {
                            if (!nearbyFiles.length) { toast('Select files first.', 'err'); return; }
                            sendNearbyFiles();
                          }}
                          disabled={nearbyStatus === 'uploading'}
                          className="flex flex-col items-center gap-3 p-5 rounded-xl border border-[#1e2133] hover:border-indigo-500/40 hover:bg-[#1a1d2e] transition-all cursor-pointer disabled:opacity-50">
                          <Upload className="w-6 h-6 text-indigo-400" />
                          <div className="text-center"><p className="text-xs font-bold text-slate-200">Send files</p><p className="text-[10px] text-slate-500 mt-0.5">Generate a QR code for the receiver to scan</p></div>
                        </button>
                        <button onClick={() => openScanner(data => {
                            // Handle both full URLs (http://192.168.x.x:8000/#/download?...) and bare hashes
                            try {
                              const parsed = new URL(data);
                              // Navigate to the correct origin with the hash
                              if (parsed.origin !== window.location.origin) {
                                window.location.href = data;
                              } else {
                                window.location.hash = parsed.hash;
                              }
                            } catch {
                              // Not a full URL, treat as hash fragment
                              if (data.includes('#/download') || data.includes('#/p2p')) {
                                window.location.hash = data.startsWith('#') ? data.slice(1) : data.slice(data.indexOf('#') + 1);
                              }
                            }
                          }, 'Scan sender QR')}
                          className="flex flex-col items-center gap-3 p-5 rounded-xl border border-[#1e2133] hover:border-emerald-500/40 hover:bg-[#1a1d2e] transition-all cursor-pointer">
                          <Download className="w-6 h-6 text-emerald-400" />
                          <div className="text-center"><p className="text-xs font-bold text-slate-200">Receive files</p><p className="text-[10px] text-slate-500 mt-0.5">Scan the sender's QR code to connect</p></div>
                        </button>
                      </div>
                    </div>

                    {/* Nearby upload progress */}
                    {nearbyStatus === 'uploading' && (
                      <div className="p-4 rounded-2xl bg-[#13161f] border border-indigo-500/20 flex flex-col gap-2">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-[var(--c-accent)] animate-pulse" /><span className="font-bold text-slate-200">Encrypting & uploading…</span></div>
                          <span className="text-indigo-400 font-bold">{nearbyProgress}%</span>
                        </div>
                        <div className="h-1.5 bg-[#0d0e17] rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full transition-all" style={{ width: `${nearbyProgress}%` }} /></div>
                      </div>
                    )}

                    {nearbyStatus === 'done' && nearbyLink && (
                      <div className="p-5 rounded-2xl bg-[#13161f] border border-emerald-500/20 flex flex-col gap-4">
                        <div className="flex items-center gap-2">
                          <CheckCircle className="w-5 h-5 text-emerald-400" />
                          <p className="text-sm font-bold text-emerald-300">File ready! Scan this QR from your phone</p>
                        </div>

                        {/* LAN IP info badge */}
                        {serverIp && serverIp !== window.location.hostname && serverIp !== '127.0.0.1' ? (
                          <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-indigo-500/5 border border-indigo-500/15">
                            <Wifi className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                            <p className="text-[10px] text-slate-400">
                              Your PC's LAN IP: <strong className="text-indigo-300 font-mono">{serverIp}</strong>
                              {' '}&mdash; make sure your phone is on the <strong>same WiFi</strong> network.
                            </p>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-amber-500/5 border border-amber-500/15">
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                            <p className="text-[10px] text-slate-400">
                              Server LAN IP not detected. Make sure Django is started with <code className="text-amber-300 bg-[#0d0e17] px-1 rounded text-[9px]">0.0.0.0:8000</code>
                            </p>
                          </div>
                        )}

                        {/* Embedded QR — uses LAN IP link so mobile can open it */}
                        <div className="flex flex-col items-center gap-3 p-5 rounded-2xl bg-white">
                          <QRCodeSVG value={nearbyLanLink || nearbyLink} size={200} />
                          <p className="text-[10px] text-slate-600 text-center font-mono break-all px-2">{nearbyLanLink || nearbyLink}</p>
                        </div>

                        {/* Copy buttons */}
                        <div className="flex gap-2">
                          <button
                            onClick={() => copyLink(nearbyLanLink || nearbyLink)}
                            className="flex-1 py-2.5 rounded-xl bg-indigo-600/10 hover:bg-indigo-600/20 border border-indigo-500/20 text-indigo-400 text-xs font-bold flex items-center justify-center gap-2 transition-all">
                            <Copy className="w-3.5 h-3.5" /> Copy LAN link
                          </button>
                          <button
                            onClick={() => { setQrContent(nearbyLanLink || nearbyLink); setQrTitle('LAN Share QR — scan with phone'); setShowQR(true); }}
                            className="flex-1 py-2.5 rounded-xl bg-slate-800/40 hover:bg-slate-800 border border-[#1e2133] text-slate-300 text-xs font-bold flex items-center justify-center gap-2 transition-all">
                            <QrCode className="w-3.5 h-3.5" /> Fullscreen QR
                          </button>
                        </div>
                        {nearbyLink !== nearbyLanLink && (
                          <button
                            onClick={() => copyLink(nearbyLink)}
                            className="text-[10px] text-slate-600 hover:text-slate-400 transition-colors">
                            Copy localhost link (same-device only)
                          </button>
                        )}
                        <button
                          onClick={() => { setNearbyStatus('idle'); setNearbyProgress(0); setNearbyLink(''); setNearbyLanLink(''); setNearbyFiles([]); }}
                          className="text-xs text-slate-500 hover:text-slate-300 transition-colors">
                          Send another file
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* ── WiFi / P2P Direct tab ── */}
                {nearbySubTab === 'wifi' && (
                  <div className="flex flex-col gap-4">

                    {/* P2P Send */}
                    <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-5 flex flex-col gap-3">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="w-6 h-6 rounded-full bg-blue-600 flex items-center justify-center text-white text-[11px] font-bold shrink-0">S</div>
                        <h3 className="text-sm font-bold text-slate-200">Send a file via P2P</h3>
                      </div>
                      <p className="text-[11px] text-slate-500">Files transfer directly device-to-device (WebRTC DataChannel) encrypted with AES-256-GCM. Works on the same WiFi network across any devices.</p>
                      <div
                        onClick={() => document.getElementById('p2p-file-input')?.click()}
                        className="border-2 border-dashed border-[#1e2133] hover:border-blue-500/40 rounded-xl py-8 flex flex-col items-center gap-3 cursor-pointer transition-all hover:bg-[#1a1d2e]/30">
                        <input type="file" id="p2p-file-input" className="hidden" onChange={e => {
                          const f = e.target.files?.[0];
                          if (f) { setP2pFile(f); setP2pStatus('idle'); setP2pError(''); setP2pProgress(0); setP2pRoomId(null); setP2pLink(''); setP2pLanLink(''); }
                        }} />
                        <Wifi className="w-7 h-7 text-slate-600" />
                        <div className="text-center">
                          <p className="text-xs font-bold text-slate-300">{p2pFile && p2pMode === 'send' ? p2pFile.name : 'Click to select file'}</p>
                          <p className="text-[10px] text-slate-500 mt-0.5">{p2pFile && p2pMode !== 'receive' ? fmtBytes(p2pFile.size) : 'Any type · direct P2P · no server storage'}</p>
                        </div>
                      </div>
                      {p2pFile && p2pStatus === 'idle' && (
                        <button onClick={() => { setP2pMode('send'); startP2PSend(p2pFile); }}
                          className="w-full py-3 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-bold text-xs flex items-center justify-center gap-2 hover:from-blue-500 hover:to-indigo-500 transition-all">
                          <Zap className="w-4 h-4" /> Start P2P Session
                        </button>
                      )}

                      {/* Waiting for peer */}
                      {p2pMode === 'send' && (p2pStatus === 'waiting' || p2pStatus === 'creating') && p2pLink && (
                        <div className="flex flex-col gap-3 p-4 rounded-xl bg-blue-500/5 border border-blue-500/20">
                          <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded-full border-2 border-blue-400 border-t-transparent animate-spin shrink-0" />
                            <p className="text-xs font-bold text-blue-300">Waiting for receiver to connect…</p>
                          </div>
                          <div className="flex justify-center p-3 bg-white rounded-xl">
                            <QRCodeSVG value={p2pLanLink || p2pLink} size={160} />
                          </div>
                          <p className="text-[10px] text-slate-500 text-center">Scan QR with receiving device (same WiFi) or copy link for same machine</p>
                          <div className="flex gap-2">
                            <button onClick={() => copyLink(p2pLink)} className="flex-1 py-2 rounded-xl bg-indigo-600/10 hover:bg-indigo-600/20 border border-indigo-500/20 text-indigo-400 text-[11px] font-bold flex items-center justify-center gap-1.5 transition-all">
                              <Copy className="w-3 h-3" /> Copy link
                            </button>
                            <button onClick={() => { setQrContent(p2pLanLink || p2pLink); setQrTitle('P2P Transfer QR'); setShowQR(true); }} className="flex-1 py-2 rounded-xl bg-slate-800/40 hover:bg-slate-800 border border-[#1e2133] text-slate-300 text-[11px] font-bold flex items-center justify-center gap-1.5 transition-all">
                              <QrCode className="w-3 h-3" /> Fullscreen QR
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Transfer in progress */}
                      {p2pMode === 'send' && p2pStatus === 'connecting' && (
                        <div className="flex items-center gap-2 p-3 rounded-xl bg-blue-500/5 border border-blue-500/20">
                          <div className="w-3 h-3 rounded-full border-2 border-blue-400 border-t-transparent animate-spin shrink-0" />
                          <p className="text-xs font-bold text-blue-300">Establishing P2P connection…</p>
                        </div>
                      )}
                      {p2pMode === 'send' && p2pStatus === 'transferring' && (
                        <div className="flex flex-col gap-2">
                          <div className="flex justify-between text-xs"><span className="font-bold text-blue-400">Sending via P2P…</span><span className="text-slate-400">{p2pChunksDone}/{p2pTotalChunks}</span></div>
                          <div className="h-2 bg-[#0d0e17] rounded-full overflow-hidden"><div className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 rounded-full transition-all" style={{ width: `${p2pProgress}%` }} /></div>
                        </div>
                      )}
                      {p2pMode === 'send' && p2pStatus === 'done' && (
                        <div className="flex items-center gap-3 p-3.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20">
                          <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                          <div><p className="text-xs font-bold text-emerald-300">Transfer complete!</p><p className="text-[10px] text-slate-500">File went directly device-to-device</p></div>
                        </div>
                      )}
                      {p2pMode === 'send' && p2pStatus === 'error' && (
                        <div className="flex items-center gap-3 p-3.5 rounded-xl bg-red-500/8 border border-red-500/20">
                          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                          <p className="text-xs font-bold text-red-300">{p2pError || 'P2P connection failed'}</p>
                        </div>
                      )}
                      {(p2pStatus === 'done' || p2pStatus === 'error') && p2pMode === 'send' && (
                        <button onClick={() => { setP2pStatus('idle'); setP2pMode(null); setP2pFile(null); setP2pProgress(0); setP2pRoomId(null); setP2pLink(''); setP2pLanLink(''); cleanupP2P(); }} className="text-xs text-slate-500 hover:text-slate-300 transition-colors text-center">
                          Send another file
                        </button>
                      )}
                    </div>

                    {/* P2P Receive */}
                    <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-5 flex flex-col gap-3">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="w-6 h-6 rounded-full bg-emerald-600 flex items-center justify-center text-white text-[11px] font-bold shrink-0">R</div>
                        <h3 className="text-sm font-bold text-slate-200">Receive a file via P2P</h3>
                      </div>
                      <p className="text-[11px] text-slate-500">Scan the sender's QR code with your camera, or paste the P2P link below.</p>
                      <button onClick={() => openScanner(data => {
                        if (data.includes('#/p2p')) window.location.hash = data.slice(data.indexOf('#/p2p') + 1);
                        else if (data.includes('#/download')) window.location.hash = data.slice(data.indexOf('#/download') + 1);
                      }, 'Scan P2P QR')}
                        className="w-full py-2.5 rounded-xl border border-[#1e2133] hover:border-blue-500/40 text-slate-300 hover:text-blue-300 text-xs font-bold flex items-center justify-center gap-2 transition-all">
                        <Camera className="w-4 h-4" /> Scan QR to receive
                      </button>
                    </div>

                    {/* Same-device BroadcastChannel discovery */}
                    <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-5 flex flex-col gap-3">
                      <div className="flex items-center justify-between">
                        <div><p className="text-xs font-bold text-slate-300">Same-device tab discovery</p><p className="text-[10px] text-slate-500 mt-0.5">Other Aegix tabs on this browser</p></div>
                        <div className="flex items-center gap-2 text-[10px] text-slate-500"><div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />Scanning</div>
                      </div>
                      {lanDevices.length === 0 ? (
                        <p className="text-[11px] text-slate-600 text-center py-2">Open another Aegix tab on this device to see it here.</p>
                      ) : lanDevices.map(d => (
                        <div key={d.id} className="flex items-center justify-between p-3 rounded-xl bg-[#0d0e17] border border-[#1e2133]">
                          <div className="flex items-center gap-2.5">
                            <div className="w-8 h-8 rounded-xl bg-indigo-600/10 border border-indigo-500/20 flex items-center justify-center"><Monitor className="w-4 h-4 text-indigo-400" /></div>
                            <div><p className="text-xs font-bold text-slate-200">{d.name}</p><p className="text-[10px] text-slate-500">{d.id}</p></div>
                          </div>
                          <button onClick={() => { if (!nearbyFiles.length) { toast('Select files in LAN tab first.', 'info'); setNearbySubTab('lan'); } else { setNearbyTarget(d); sendNearbyFiles(d); setNearbySubTab('lan'); } }}
                            className="px-3 py-1.5 rounded-xl bg-indigo-600/10 hover:bg-indigo-600/20 border border-indigo-500/20 text-indigo-400 text-[11px] font-bold transition-all">Send</button>
                        </div>
                      ))}
                      <div className="flex items-center justify-between">
                        <div><p className="text-xs font-bold text-slate-300">Discoverable</p><p className="text-[10px] text-slate-500">Announce to same-device tabs</p></div>
                        <Toggle val={lanDiscoverable} onChange={() => setLanDiscoverable(p => !p)} />
                      </div>
                    </div>

                  </div>
                )}

                {/* ── Bluetooth LE + GATT ── */}
                {nearbySubTab === 'ble' && (
                  <div className="flex flex-col gap-4">

                    {/* Browser support warning */}
                    {!bleSupported && (
                      <div className="flex items-start gap-3 p-4 rounded-2xl bg-amber-500/5 border border-amber-500/20">
                        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-xs font-bold text-amber-300">Web Bluetooth not supported in this browser</p>
                          <p className="text-[10px] text-slate-400 mt-1">Use <strong>Google Chrome</strong> or <strong>Microsoft Edge</strong> on Windows, macOS, Linux, or Android. Firefox and Safari do not implement the Web Bluetooth API.</p>
                        </div>
                      </div>
                    )}

                    {/* Header with scan button */}
                    <div className="flex items-center justify-between">
                      <div>
                        <h2 className="text-sm font-bold text-slate-200">Bluetooth devices</h2>
                        <p className="text-[10px] text-slate-500 mt-0.5">
                          {bleSupported ? 'Real BLE hardware via Web Bluetooth API · GATT client' : 'Requires Chrome or Edge'}
                        </p>
                      </div>
                      <button
                        onClick={connectBluetooth}
                        disabled={!bleSupported || bleStatus === 'connecting'}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl bg-indigo-600/10 hover:bg-indigo-600/20 border border-indigo-500/20 text-indigo-400 text-xs font-bold transition-all disabled:opacity-40">
                        <RefreshCw className={`w-3.5 h-3.5 ${bleStatus === 'connecting' ? 'animate-spin' : ''}`} />
                        {bleStatus === 'connecting' ? 'Pairing…' : 'Scan & Connect'}
                      </button>
                    </div>

                    {/* Device list — driven by bleDeviceInfos */}
                    {bleDeviceInfos.length === 0 ? (
                      <div className="py-12 flex flex-col items-center gap-3 text-slate-600">
                        <div className="relative">
                          <Bluetooth className="w-10 h-10" />
                          <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-[#0d0e17] border border-[#1e2133] flex items-center justify-center">
                            <div className="w-2 h-2 rounded-full bg-slate-700" />
                          </div>
                        </div>
                        <div className="text-center">
                          <p className="text-xs font-bold text-slate-500">No Bluetooth devices connected</p>
                          <p className="text-[10px] text-slate-600 mt-1">Click <strong className="text-slate-500">Scan &amp; Connect</strong> — your browser opens<br/>the OS Bluetooth picker for your real BLE hardware.</p>
                        </div>
                      </div>
                    ) : bleDeviceInfos.map(d => {
                      const isConn = d.status === 'connected';
                      const isErr  = d.status === 'error';
                      const isDisc = d.status === 'disconnected';
                      const isBusy = d.status === 'gatt-connecting' || d.status === 'pairing';
                      return (
                        <div key={d.id} className={`rounded-2xl border p-4 flex flex-col gap-3 transition-all ${
                          isConn ? 'bg-[#141824] border-blue-500/30'
                          : isErr ? 'bg-[#1a1220] border-red-500/20'
                          : 'bg-[#1a1d2e] border-[#1e2133] opacity-80'
                        }`}>

                          {/* Device header row */}
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex items-center gap-3 min-w-0">
                              <div className={`w-10 h-10 rounded-xl flex items-center justify-center border shrink-0 ${
                                isConn ? 'bg-blue-600/15 border-blue-500/30'
                                : isErr ? 'bg-red-600/10 border-red-500/20'
                                : 'bg-[#0d0e17] border-[#1e2133]'
                              }`}>
                                {isBusy
                                  ? <div className="w-4 h-4 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin" />
                                  : <Bluetooth className={`w-5 h-5 ${isConn ? 'text-blue-400' : isErr ? 'text-red-400' : 'text-slate-600'}`} />
                                }
                              </div>
                              <div className="min-w-0">
                                <p className="text-xs font-bold text-slate-200 truncate">{d.name}</p>
                                <div className="flex items-center gap-2 flex-wrap mt-0.5">
                                  {d.manufacturer && <span className="text-[10px] text-slate-500">{d.manufacturer}</span>}
                                  {d.battery !== undefined && (
                                    <span className={`text-[10px] font-bold ${d.battery > 50 ? 'text-emerald-400' : d.battery > 20 ? 'text-amber-400' : 'text-red-400'}`}>
                                      ⚡ {d.battery}%
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>

                            {/* Status + capability badges */}
                            <div className="flex flex-col items-end gap-1 shrink-0">
                              <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border whitespace-nowrap ${
                                isConn ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                                : isBusy ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'
                                : isErr ? 'bg-red-500/10 text-red-400 border-red-500/20'
                                : 'bg-slate-800 text-slate-500 border-slate-700'
                              }`}>
                                {isConn ? '● GATT Connected' : isBusy ? '◌ Connecting…' : isErr ? '✗ Error' : '○ Disconnected'}
                              </span>
                              {isConn && d.servicesCount > 0 && (
                                <span className="text-[9px] text-slate-600">{d.servicesCount} GATT service{d.servicesCount !== 1 ? 's' : ''}</span>
                              )}
                              {isConn && (
                                <span className={`text-[9px] font-bold px-1.5 py-px rounded-full ${
                                  d.hasAegixService ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-600 bg-slate-800/60'
                                }`}>
                                  {d.hasAegixService ? '✓ Aegix service' : 'No Aegix svc'}
                                </span>
                              )}
                            </div>
                          </div>

                          {/* Error message */}
                          {isErr && d.errorMsg && (
                            <p className="text-[10px] text-red-300 bg-red-500/5 border border-red-500/10 rounded-lg px-3 py-2">{d.errorMsg}</p>
                          )}

                          {/* ── Connected: file sharing actions ── */}
                          {isConn && (
                            <div className="border-t border-[#1e2133] pt-3 flex flex-col gap-2.5">
                              <p className="text-[10px] text-slate-500 font-medium">
                                Share a file with <strong className="text-slate-300">{d.name}</strong>:
                              </p>
                              <div className="grid grid-cols-3 gap-2">
                                {/* Select file → P2P session → GATT link delivery */}
                                <div
                                  onClick={() => document.getElementById(`ble-gatt-${d.id}`)?.click()}
                                  className="col-span-2 border border-dashed border-[#1e2133] hover:border-blue-500/40 rounded-xl py-3 flex flex-col items-center justify-center gap-1.5 cursor-pointer text-[11px] text-slate-500 hover:text-blue-300 transition-all">
                                  <input type="file" id={`ble-gatt-${d.id}`} className="hidden" onChange={async e => {
                                    const f = e.target.files?.[0];
                                    if (!f) return;
                                    // Switch to WiFi tab so user sees the P2P QR
                                    setNearbySubTab('wifi');
                                    setP2pMode('send'); setP2pStatus('idle');
                                    setP2pFile(f); setP2pProgress(0); setP2pRoomId(null); setP2pLink(''); setP2pLanLink('');
                                    toast('P2P session starting — once the QR appears, use "Send via BLE" to deliver the link over Bluetooth.', 'info');
                                    startP2PSend(f);
                                  }} />
                                  <Bluetooth className="w-4 h-4" />
                                  <span>Start P2P + send via BLE</span>
                                </div>

                                {/* Manual: send current P2P link via GATT write */}
                                <button
                                  onClick={() => sendP2PLinkViaBluetooth(d.id, p2pLanLink || p2pLink || window.location.href, d.name)}
                                  title={p2pLink ? 'Write P2P link to Aegix GATT characteristic' : 'Start a P2P session first'}
                                  className={`rounded-xl flex flex-col items-center justify-center gap-1 py-3 border text-[10px] font-bold transition-all ${
                                    p2pLink
                                      ? 'bg-blue-600/10 hover:bg-blue-600/20 border-blue-500/20 text-blue-400'
                                      : 'bg-[#0d0e17] border-[#1e2133] text-slate-700 cursor-not-allowed'
                                  }`}>
                                  <Bluetooth className="w-3.5 h-3.5" />
                                  <span>Send link</span>
                                </button>
                              </div>

                              <div className="flex gap-2">
                                {/* QR fallback */}
                                <button
                                  onClick={() => { setQrContent(p2pLanLink || p2pLink || window.location.href); setQrTitle(`BT QR → ${d.name}`); setShowQR(true); }}
                                  className="flex-1 py-2 rounded-xl bg-slate-800/40 hover:bg-slate-800 border border-[#1e2133] text-slate-400 text-[11px] font-bold flex items-center justify-center gap-1.5 transition-all">
                                  <QrCode className="w-3 h-3" /> QR code
                                </button>
                                {/* Disconnect */}
                                <button
                                  onClick={() => {
                                    const dev = bleDeviceRefs.current.get(d.id);
                                    if (dev?.gatt?.connected) dev.gatt.disconnect();
                                    else updateBleDevice(d.id, { status: 'disconnected' });
                                  }}
                                  className="flex-1 py-2 rounded-xl bg-red-600/5 hover:bg-red-600/10 border border-red-500/10 text-red-400 text-[11px] font-bold flex items-center justify-center gap-1.5 transition-all">
                                  <X className="w-3 h-3" /> Disconnect
                                </button>
                              </div>
                            </div>
                          )}

                          {/* ── Disconnected / Error: reconnect button ── */}
                          {(isDisc || isErr) && (
                            <button
                              onClick={() => reconnectBleDevice(d.id)}
                              className="w-full py-2.5 rounded-xl bg-indigo-600/10 hover:bg-indigo-600/20 border border-indigo-500/20 text-indigo-400 text-xs font-bold flex items-center justify-center gap-2 transition-all">
                              <RefreshCw className="w-3.5 h-3.5" /> Reconnect GATT
                            </button>
                          )}
                        </div>
                      );
                    })}

                    {/* Web Serial — Bluetooth Classic (SPP COM ports, Windows) */}
                    {serialSupported && (
                      <div className="bg-[#13161f] border border-purple-500/20 rounded-2xl p-4 flex flex-col gap-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <div className="w-7 h-7 rounded-lg bg-purple-600/10 border border-purple-500/20 flex items-center justify-center">
                              <Bluetooth className="w-3.5 h-3.5 text-purple-400" />
                            </div>
                            <div>
                              <p className="text-xs font-bold text-slate-200">Bluetooth Classic · Serial Port (SPP)</p>
                              <p className="text-[10px] text-slate-500">Send P2P link via COM port — Windows desktop</p>
                            </div>
                          </div>
                          <span className="text-[9px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded-full">Web Serial</span>
                        </div>
                        <p className="text-[10px] text-slate-500">
                          Bluetooth devices paired with <strong className="text-slate-400">Serial Port Profile (SPP)</strong> on Windows appear as COM ports. Click below — the browser opens a COM port picker — and writes the current P2P link to the port.
                        </p>
                        <button
                          onClick={() => connectBluetoothSerial(p2pLanLink || p2pLink || window.location.href)}
                          disabled={!p2pLink}
                          className="w-full py-2.5 rounded-xl bg-purple-600/10 hover:bg-purple-600/20 border border-purple-500/20 text-purple-400 text-xs font-bold flex items-center justify-center gap-2 transition-all disabled:opacity-40">
                          <Bluetooth className="w-3.5 h-3.5" />
                          {p2pLink ? 'Send P2P Link via Bluetooth Serial' : 'Start a P2P session first (WiFi tab)'}
                        </button>
                      </div>
                    )}

                    {/* Technical explanation */}
                    <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-4 flex flex-col gap-3">
                      <div className="flex items-center gap-2">
                        <Bluetooth className="w-3.5 h-3.5 text-blue-400" />
                        <p className="text-xs font-bold text-slate-200">How Bluetooth sharing works</p>
                      </div>
                      <ol className="text-[11px] text-slate-500 flex flex-col gap-2 list-none">
                        <li className="flex gap-2.5">
                          <span className="w-4 h-4 rounded-full bg-indigo-600 text-white text-[8px] font-bold flex items-center justify-center shrink-0 mt-0.5">1</span>
                          <span>Click <strong className="text-slate-400">Scan &amp; Connect</strong> — the browser requests Bluetooth permission from the OS and opens the native device picker showing real BLE hardware in range.</span>
                        </li>
                        <li className="flex gap-2.5">
                          <span className="w-4 h-4 rounded-full bg-indigo-600 text-white text-[8px] font-bold flex items-center justify-center shrink-0 mt-0.5">2</span>
                          <span>The browser establishes a real GATT connection and reads device information (manufacturer, battery level, available services).</span>
                        </li>
                        <li className="flex gap-2.5">
                          <span className="w-4 h-4 rounded-full bg-indigo-600 text-white text-[8px] font-bold flex items-center justify-center shrink-0 mt-0.5">3</span>
                          <span>Start a <strong className="text-slate-400">P2P WiFi session</strong> (WiFi tab). Once ready, click <strong className="text-slate-400">Send link</strong> — it writes the URL to the device's Aegix GATT characteristic. Or show a <strong className="text-slate-400">QR code</strong> for manual scan.</span>
                        </li>
                        <li className="flex gap-2.5">
                          <span className="w-4 h-4 rounded-full bg-indigo-600 text-white text-[8px] font-bold flex items-center justify-center shrink-0 mt-0.5">4</span>
                          <span>The receiving device opens the link — file transfers directly device-to-device via <strong className="text-slate-400">WebRTC (never through the server)</strong>, AES-256-GCM encrypted end-to-end.</span>
                        </li>
                      </ol>
                      <div className="flex items-start gap-2 p-3 rounded-xl bg-blue-500/5 border border-blue-500/10">
                        <Shield className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                        <p className="text-[10px] text-slate-500">
                          <strong className="text-slate-400">BLE = discovery + out-of-band signaling.</strong> File data travels over WebRTC (100× faster than BLE). Browsers can only act as GATT clients — the receiving device needs the Aegix native app or any software that exposes UUID <code className="text-[9px] bg-[#0d0e17] px-1 py-px rounded font-mono">ae91</code> to receive the link automatically via GATT write.
                        </p>
                      </div>
                    </div>

                  </div>
                )}

              </div>
            )}

            {/* ── HISTORY TAB ── */}
            {tab === 'history' && (
              <div className="flex flex-col gap-5">
                <div className="flex items-center justify-between">
              <h1 style={{fontSize:'var(--ts-2xl)',fontWeight:700,color:'var(--c-t1)',letterSpacing:'-0.02em'}}>Transfer History</h1>
                  {transfers.length > 0 && <button onClick={() => setTransfers([])} className="text-xs text-red-400 hover:text-red-300 font-bold transition-all">Clear</button>}
                </div>
                {transfers.length === 0 ? (
                  <div className="py-16 text-center text-slate-600"><Clock className="w-10 h-10 mx-auto mb-3 opacity-30" /><p className="text-sm font-bold">No transfers yet</p></div>
                ) : transfers.map(t => (
                  <div key={t.id} className="p-4 rounded-2xl bg-[#13161f] border border-[#1e2133] flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 ${t.status === 'done' ? 'bg-emerald-500/10 border border-emerald-500/20' : t.status === 'failed' ? 'bg-red-500/10 border border-red-500/20' : 'bg-indigo-500/10 border border-indigo-500/20'}`}>
                      {t.status === 'done' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : t.status === 'failed' ? <X className="w-3.5 h-3.5 text-red-400" /> : <Upload className="w-3.5 h-3.5 text-indigo-400" />}
                    </div>
                    <div className="flex-1 min-w-0"><p className="text-xs font-bold text-slate-200 truncate">{t.name}</p><p className="text-[10px] text-slate-500">{fmtBytes(t.size)} · {t.totalChunks} chunks · {t.status}</p></div>
                    {t.status === 'done' && (
                      <button onClick={() => copyLink(t.downloadUrl)} className="shrink-0 p-2 rounded-lg bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 hover:bg-indigo-600/20 transition-all"><Copy className="w-3.5 h-3.5" /></button>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* ── LIBRARY TAB ── */}
            {tab === 'library' && (
              <div className="flex flex-col gap-5">
                <div className="flex items-center justify-between">
              <h1 style={{fontSize:'var(--ts-2xl)',fontWeight:700,color:'var(--c-t1)',letterSpacing:'-0.02em'}}>File Library</h1>
                  <button onClick={fetchStats} className="p-2 rounded-xl bg-[#1a1d2e] border border-[#1e2133] text-slate-400 hover:text-white transition-all"><RefreshCw className="w-4 h-4" /></button>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[{ label: 'Active transfers', value: libStats.count }, { label: 'Total stored', value: fmtBytes(libStats.bytes) }].map(s => (
                    <div key={s.label} className="bg-[#13161f] border border-[#1e2133] rounded-2xl p-4">
                      <p className="text-xl font-extrabold text-white">{s.value}</p><p className="text-[10px] text-slate-500 mt-0.5">{s.label}</p>
                    </div>
                  ))}
                </div>
                {libStats.files.length === 0 ? (
                  <div className="py-16 text-center text-slate-600"><Database className="w-10 h-10 mx-auto mb-3 opacity-30" /><p className="text-sm font-bold">No active transfers on server</p></div>
                ) : libStats.files.map((f: any) => (
                  <div key={f.id} className="p-4 rounded-2xl bg-[#13161f] border border-[#1e2133] flex items-center gap-3">
                    <File className="w-5 h-5 text-indigo-400 shrink-0" />
                    <div className="flex-1 min-w-0"><p className="text-xs font-bold text-slate-200 truncate">{f.name}</p><p className="text-[10px] text-slate-500">{fmtBytes(f.size)} · {f.uploaded_chunks}/{f.total_chunks} chunks{f.is_complete ? ' · ✓' : ' · uploading…'}</p></div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${f.is_complete ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'}`}>{f.is_complete ? 'ready' : 'live'}</span>
                  </div>
                ))}
              </div>
            )}

            {/* ==== SETTINGS TAB ==== */}
            {tab === 'settings' && (
              <div className="flex flex-col gap-5">
                <h1 style={{fontSize:'var(--ts-2xl)',fontWeight:700,color:'var(--c-t1)',letterSpacing:'-0.02em'}}>Settings</h1>
                <p className="text-xs text-slate-500 -mt-3">All changes save automatically and persist across sessions.</p>

                {/* A: Transfer Defaults */}
                <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2133] bg-[#0f1120]/60">
                    <div className="w-8 h-8 rounded-xl bg-indigo-600/20 flex items-center justify-center" data-accent><SlidersHorizontal className="w-4 h-4 text-indigo-400" /></div>
                    <div><p className="text-sm font-bold text-white">Transfer Defaults</p><p className="text-[10px] text-slate-500">Applied automatically to each new upload</p></div>
                  </div>
                  <div className="flex flex-col divide-y divide-[#1e2133]">
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Default link expiry</p><p className="text-[10px] text-slate-500 mt-0.5">How long generated links stay active</p></div>
                      <select id="settings-default-expiry" value={settings.defaultExpiryHours} onChange={e => updateSetting('defaultExpiryHours', Number(e.target.value))} className="bg-[#1a1d2e] border border-[#2a2d3e] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer min-w-[150px]">
                        {EXPIRY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                      </select>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Default download limit</p><p className="text-[10px] text-slate-500 mt-0.5">Max times a link can be downloaded</p></div>
                      <select id="settings-default-dl-limit" value={settings.defaultDownloadLimit} onChange={e => updateSetting('defaultDownloadLimit', Number(e.target.value))} className="bg-[#1a1d2e] border border-[#2a2d3e] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer min-w-[150px]">
                        {DOWNLOAD_LIMIT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                      </select>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Chunk size</p><p className="text-[10px] text-slate-500 mt-0.5">Encryption block size. Larger = fewer API calls. Takes effect on next upload.</p></div>
                      <select id="settings-chunk-size" value={settings.defaultChunkKB} onChange={e => updateSetting('defaultChunkKB', Number(e.target.value))} className="bg-[#1a1d2e] border border-[#2a2d3e] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer min-w-[150px]">
                        <option value={256}>256 KB - slow network</option>
                        <option value={512}>512 KB - balanced (default)</option>
                        <option value={1024}>1 MB - fast network</option>
                        <option value={2048}>2 MB - LAN / high-speed</option>
                      </select>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Self-destruct by default</p><p className="text-[10px] text-slate-500 mt-0.5">Delete file after first download</p></div>
                      <Toggle val={settings.defaultSelfDestruct} onChange={() => updateSetting('defaultSelfDestruct', !settings.defaultSelfDestruct)} />
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Require password by default</p><p className="text-[10px] text-slate-500 mt-0.5">Prompt for a password on every upload</p></div>
                      <Toggle val={settings.defaultRequirePassword} onChange={() => updateSetting('defaultRequirePassword', !settings.defaultRequirePassword)} />
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Auto-show QR after upload</p><p className="text-[10px] text-slate-500 mt-0.5">Automatically open the QR code modal when upload completes</p></div>
                      <Toggle val={settings.showQrOnUpload} onChange={() => updateSetting('showQrOnUpload', !settings.showQrOnUpload)} />
                    </div>
                  </div>
                </div>

                {/* B: Appearance */}
                <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2133] bg-[#0f1120]/60">
                    <div className="w-8 h-8 rounded-xl bg-purple-600/20 flex items-center justify-center"><Palette className="w-4 h-4 text-purple-400" /></div>
                    <div><p className="text-sm font-bold text-white">Appearance</p><p className="text-[10px] text-slate-500">Customize the look and feel</p></div>
                  </div>
                  <div className="flex flex-col divide-y divide-[#1e2133]">
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Accent color</p><p className="text-[10px] text-slate-500 mt-0.5">Hue-shifts the primary action color across the UI</p></div>
                      <div className="flex items-center gap-2">
                        {[{hue:235,label:'Indigo'},{hue:260,label:'Violet'},{hue:200,label:'Sky'},{hue:158,label:'Emerald'},{hue:340,label:'Rose'},{hue:30,label:'Amber'}].map(({hue,label}) => (
                          <button key={hue} id={'settings-accent-'+label.toLowerCase()} title={label}
                            onClick={() => updateSetting('accentHue', hue)}
                            className={'w-6 h-6 rounded-full transition-all duration-150 ' + (settings.accentHue===hue ? 'ring-2 ring-white ring-offset-1 ring-offset-[#13161f] scale-110' : 'hover:scale-105')}
                            style={{background:'hsl('+hue+',65%,55%)'}} />
                        ))}
                      </div>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Display density</p><p className="text-[10px] text-slate-500 mt-0.5">Controls spacing across the interface</p></div>
                      <div className="flex bg-[#0d0e17] border border-[#2a2d3e] rounded-lg overflow-hidden text-[11px] font-bold">
                        {(['compact','normal','comfortable'] as const).map(d => (
                          <button key={d} id={'settings-density-'+d} onClick={() => updateSetting('density', d)}
                            className={'px-3 py-1.5 capitalize transition-colors ' + (settings.density===d ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200')}>
                            {d}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Reduce motion</p><p className="text-[10px] text-slate-500 mt-0.5">Disable non-essential animations</p></div>
                      <Toggle val={settings.reducedMotion} onChange={() => updateSetting('reducedMotion', !settings.reducedMotion)} />
                    </div>
                  </div>
                </div>

                {/* C: Security & Privacy */}
                <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2133] bg-[#0f1120]/60">
                    <div className="w-8 h-8 rounded-xl bg-emerald-600/20 flex items-center justify-center"><ShieldCheck className="w-4 h-4 text-emerald-400" /></div>
                    <div><p className="text-sm font-bold text-white">Security and Privacy</p><p className="text-[10px] text-slate-500">Control data retention and visibility</p></div>
                  </div>
                  <div className="flex flex-col divide-y divide-[#1e2133]">
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">History retention</p><p className="text-[10px] text-slate-500 mt-0.5">Auto-clear transfer history after a period</p></div>
                      <select id="settings-history-retention" value={settings.historyRetentionDays} onChange={e => updateSetting('historyRetentionDays', Number(e.target.value))} className="bg-[#1a1d2e] border border-[#2a2d3e] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer min-w-[130px]">
                        <option value={0}>Keep forever</option>
                        <option value={7}>7 days</option>
                        <option value={30}>30 days</option>
                        <option value={90}>90 days</option>
                      </select>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Show key in history</p><p className="text-[10px] text-slate-500 mt-0.5">Reveal decryption key in transfer history cards</p></div>
                      <Toggle val={settings.showTransferKeys} onChange={() => updateSetting('showTransferKeys', !settings.showTransferKeys)} />
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Close modal after copy</p><p className="text-[10px] text-slate-500 mt-0.5">Dismiss link modal automatically when link is copied</p></div>
                      <Toggle val={settings.autoCloseModalOnCopy} onChange={() => updateSetting('autoCloseModalOnCopy', !settings.autoCloseModalOnCopy)} />
                    </div>
                    <div className="px-5 py-4 bg-[#0a0c14]/50">
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2.5">Encryption stack</p>
                      <div className="grid grid-cols-1 gap-1.5">
                        {[{icon:<ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0"/>,text:'AES-256-GCM per-chunk encryption'},{icon:<Cpu className="w-3 h-3 text-indigo-400 shrink-0"/>,text:'PBKDF2-SHA-256 100k iterations'},{icon:<Layers className="w-3 h-3 text-purple-400 shrink-0"/>,text:'Independent 12-byte IV per chunk'},{icon:<ShieldCheck className="w-3 h-3 text-sky-400 shrink-0"/>,text:'Zero-knowledge - key never reaches server'},{icon:<Network className="w-3 h-3 text-amber-400 shrink-0"/>,text:'@noble/ciphers fallback for plain-HTTP LAN'}].map(({icon,text}) => (
                          <div key={text} className="flex items-center gap-2 text-[11px] text-slate-400">{icon}{text}</div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* D: Network */}
                <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2133] bg-[#0f1120]/60">
                    <div className="w-8 h-8 rounded-xl bg-sky-600/20 flex items-center justify-center"><Network className="w-4 h-4 text-sky-400" /></div>
                    <div><p className="text-sm font-bold text-white">Network</p><p className="text-[10px] text-slate-500">LAN discovery and device identity</p></div>
                  </div>
                  <div className="flex flex-col divide-y divide-[#1e2133]">
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">LAN discoverable</p><p className="text-[10px] text-slate-500 mt-0.5">Announce this device on the local network</p></div>
                      <Toggle val={settings.lanDiscoverable} onChange={() => updateSetting('lanDiscoverable', !settings.lanDiscoverable)} />
                    </div>
                    <div className="flex flex-col gap-2 px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Device display name</p><p className="text-[10px] text-slate-500 mt-0.5">Shown to other devices on the LAN</p></div>
                      <div className="flex gap-2">
                        <input id="settings-device-name" value={settings.deviceDisplayName} onChange={e => updateSetting('deviceDisplayName', e.target.value)} maxLength={32} placeholder="e.g. My Laptop" className="flex-1 bg-[#0d0e17] border border-[#2a2d3e] rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500" />
                        <button onClick={() => updateSetting('deviceDisplayName', deviceName)} className="px-3 py-2 rounded-lg bg-[#1a1d2e] text-slate-400 hover:text-white text-xs font-bold transition-colors">Reset</button>
                      </div>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">LAN IP address</p><p className="text-[10px] text-slate-500 mt-0.5">Current server IP on the local network</p></div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/20">{serverIp || 'detecting...'}</span>
                        <button onClick={() => {navigator.clipboard.writeText(serverIp||'');toast('IP copied!','ok');}} className="p-1.5 rounded-lg hover:bg-[#1a1d2e] text-slate-500 hover:text-white transition-colors"><Copy className="w-3.5 h-3.5"/></button>
                      </div>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Device ID</p><p className="text-[10px] text-slate-500 mt-0.5">Unique identifier stored in localStorage</p></div>
                      <span className="font-mono text-[11px] text-slate-500 bg-[#0d0e17] px-2.5 py-1 rounded-lg border border-[#1e2133]">{deviceId}</span>
                    </div>
                  </div>
                </div>

                {/* E: Notifications */}
                <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2133] bg-[#0f1120]/60">
                    <div className="w-8 h-8 rounded-xl bg-amber-600/20 flex items-center justify-center"><Bell className="w-4 h-4 text-amber-400"/></div>
                    <div><p className="text-sm font-bold text-white">Notifications</p><p className="text-[10px] text-slate-500">Configure in-app alerts and feedback</p></div>
                  </div>
                  <div className="flex flex-col divide-y divide-[#1e2133]">
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Upload complete alert</p><p className="text-[10px] text-slate-500 mt-0.5">Toast when a file finishes uploading</p></div>
                      <Toggle val={settings.notifyOnUpload} onChange={() => updateSetting('notifyOnUpload', !settings.notifyOnUpload)} />
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Download ready alert</p><p className="text-[10px] text-slate-500 mt-0.5">Toast when decryption finishes on receiver</p></div>
                      <Toggle val={settings.notifyOnDownload} onChange={() => updateSetting('notifyOnDownload', !settings.notifyOnDownload)} />
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">LAN device found alert</p><p className="text-[10px] text-slate-500 mt-0.5">Alert when a new device appears on the network</p></div>
                      <Toggle val={settings.notifyOnLanPeer} onChange={() => updateSetting('notifyOnLanPeer', !settings.notifyOnLanPeer)} />
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div className="flex items-center gap-2">{settings.soundEffects ? <Volume2 className="w-3.5 h-3.5 text-amber-400"/> : <VolumeX className="w-3.5 h-3.5 text-slate-500"/>}<div><p className="text-sm font-semibold text-slate-200">Sound effects</p><p className="text-[10px] text-slate-500 mt-0.5">Subtle tones on upload or download complete</p></div></div>
                      <Toggle val={settings.soundEffects} onChange={() => {updateSetting('soundEffects', !settings.soundEffects); if (!settings.soundEffects) setTimeout(()=>playSfx('done'),50);}} />
                    </div>
                  </div>
                </div>

                {/* F: Data Management */}
                <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2133] bg-[#0f1120]/60">
                    <div className="w-8 h-8 rounded-xl bg-rose-600/20 flex items-center justify-center"><HardDriveDownload className="w-4 h-4 text-rose-400"/></div>
                    <div><p className="text-sm font-bold text-white">Data Management</p><p className="text-[10px] text-slate-500">Export, import, and clear stored data</p></div>
                  </div>
                  <div className="flex flex-col divide-y divide-[#1e2133]">
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Export settings</p><p className="text-[10px] text-slate-500 mt-0.5">Download your settings as a JSON file</p></div>
                      <button id="settings-export-btn" onClick={() => downloadJson('aegix-settings.json', settings)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1a1d2e] hover:bg-[#20243a] text-slate-300 text-xs font-bold transition-colors"><FileJson className="w-3.5 h-3.5"/> Export</button>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Import settings</p><p className="text-[10px] text-slate-500 mt-0.5">Load settings from a previously exported file</p></div>
                      <label id="settings-import-label" className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1a1d2e] hover:bg-[#20243a] text-slate-300 text-xs font-bold transition-colors cursor-pointer"><HardDriveDownload className="w-3.5 h-3.5"/> Import<input type="file" accept=".json,application/json" className="hidden" onChange={e => {const f=e.target.files?.[0];if(!f)return;const r=new FileReader();r.onload=ev=>{try{const p=JSON.parse(ev.target?.result as string) as Partial<AppSettings>;const m={...DEFAULT_SETTINGS,...p,schemaVersion:DEFAULT_SETTINGS.schemaVersion};saveSettings(m);setSettings(m);applyAccentHue(m.accentHue);applyDensity(m.density);applyReducedMotion(m.reducedMotion);toast('Settings imported!','ok');}catch{toast('Invalid file.','err');}};r.readAsText(f);e.target.value='';}} /></label>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Clear transfer history</p><p className="text-[10px] text-slate-500 mt-0.5">Remove all local transfer records from this session</p></div>
                      <button id="settings-clear-history-btn" onClick={() => {setTransfers([]);toast('Transfer history cleared.','info');}} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-500/30 text-amber-400 hover:bg-amber-500/10 text-xs font-bold transition-colors"><Trash2 className="w-3.5 h-3.5"/> Clear</button>
                    </div>
                    <div className="flex items-center justify-between px-5 py-3.5">
                      <div><p className="text-sm font-semibold text-slate-200">Reset to defaults</p><p className="text-[10px] text-slate-500 mt-0.5">Restore all settings to factory defaults</p></div>
                      <button id="settings-reset-btn" onClick={() => {const d={...DEFAULT_SETTINGS};saveSettings(d);setSettings(d);applyAccentHue(d.accentHue);applyDensity(d.density);applyReducedMotion(d.reducedMotion);toast('Settings reset.','info');}} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1a1d2e] hover:bg-[#20243a] text-slate-300 text-xs font-bold transition-colors"><RotateCcw className="w-3.5 h-3.5"/> Reset</button>
                    </div>
                  </div>
                </div>

                {/* G: About */}
                <div className="bg-[#13161f] border border-[#1e2133] rounded-2xl overflow-hidden">
                  <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2133] bg-[#0f1120]/60">
                    <div className="w-8 h-8 rounded-xl bg-slate-600/20 flex items-center justify-center"><Info className="w-4 h-4 text-slate-400"/></div>
                    <div><p className="text-sm font-bold text-white">About Aegix Share</p><p className="text-[10px] text-slate-500">Version, credits and diagnostics</p></div>
                  </div>
                  <div className="flex flex-col divide-y divide-[#1e2133]">
                    <div className="flex items-center justify-between px-5 py-3.5"><p className="text-sm font-semibold text-slate-200">App version</p><span className="font-mono text-xs text-slate-400 bg-[#0d0e17] px-2.5 py-1 rounded-lg border border-[#1e2133]">v1.0.0</span></div>
                    <div className="flex items-center justify-between px-5 py-3.5"><p className="text-sm font-semibold text-slate-200">Settings schema</p><span className="font-mono text-xs text-slate-400 bg-[#0d0e17] px-2.5 py-1 rounded-lg border border-[#1e2133]">v{settings.schemaVersion}</span></div>
                    <div className="flex items-center justify-between px-5 py-3.5"><p className="text-sm font-semibold text-slate-200">Secure context</p><span className={'font-mono text-xs px-2.5 py-1 rounded-lg border '+(window.isSecureContext?'text-emerald-400 bg-emerald-500/10 border-emerald-500/20':'text-amber-400 bg-amber-500/10 border-amber-500/20')}>{window.isSecureContext?'Yes - Web Crypto API':'No - noble fallback'}</span></div>
                    <div className="flex items-center justify-between px-5 py-3.5"><p className="text-sm font-semibold text-slate-200">Crypto engine</p><span className="font-mono text-xs text-slate-400 bg-[#0d0e17] px-2.5 py-1 rounded-lg border border-[#1e2133]">{window.isSecureContext?'WebCrypto (native)':'noble/ciphers (JS)'}</span></div>
                    <div className="px-5 py-4">
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2.5">Open Source Libraries</p>
                      {[['React','Meta / MIT'],['Django','DSF / BSD'],['@noble/ciphers','paulmillr / MIT'],['@noble/hashes','paulmillr / MIT'],['qrcode.react','zpao / MIT'],['Lucide','Lucide Contributors / ISC'],['Vite','Evan You / MIT']].map(([lib,lic]) => (
                        <div key={lib} className="flex items-center justify-between text-[11px] py-0.5"><span className="text-slate-300 font-semibold">{lib}</span><span className="text-slate-500">{lic}</span></div>
                      ))}
                    </div>
                  </div>
                </div>

              </div>
            )}

            {/* ── PROFILE TAB ── */}
            {tab === 'profile' && (
              <div style={{display:'flex',flexDirection:'column',gap:'var(--sp-6)'}}>

                {/* Header */}
                <div>
                  <h1 style={{fontSize:'var(--ts-2xl)',fontWeight:700,color:'var(--c-t1)',letterSpacing:'-0.02em'}}>Profile</h1>
                  <p style={{fontSize:'var(--ts-sm)',color:'var(--c-t3)',marginTop:'var(--sp-1)'}}>Manage your identity, preferences and privacy</p>
                </div>

                {/* Identity card */}
                <div className="card" style={{padding:'var(--sp-5)',display:'flex',flexDirection:'column',gap:'var(--sp-4)'}}>
                  <p className="section-label">Identity</p>
                  <div style={{display:'flex',alignItems:'center',gap:'var(--sp-4)'}}>
                    <div style={{width:'60px',height:'60px',borderRadius:'50%',background:'var(--c-accent-x)',border:'2px solid var(--c-accent-b)',display:'flex',alignItems:'center',justifyContent:'center',color:'var(--c-accent)',fontWeight:700,fontSize:'24px',flexShrink:0}}>
                      {profileName.charAt(0).toUpperCase()}
                    </div>
                    <div style={{minWidth:0}}>
                      <p style={{fontWeight:700,color:'var(--c-t1)',fontSize:'var(--ts-lg)'}}>{profileName}</p>
                      <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',marginTop:'2px'}}>{profileEmail || 'No email set'}</p>
                      {isGuest && <span className="badge badge-warn" style={{marginTop:'4px',display:'inline-flex'}}>Guest session</span>}
                    </div>
                  </div>
                  {([{ label: 'Display Name', val: profileName, set: setProfileName, type: 'text', placeholder: 'Your name' }, { label: 'Email', val: profileEmail, set: setProfileEmail, type: 'email', placeholder: 'you@example.com' }] as { label: string; val: string; set: (v:string)=>void; type: string; placeholder: string }[]).map(({ label, val, set, type, placeholder }) => (
                    <div key={label} style={{display:'flex',flexDirection:'column',gap:'var(--sp-2)'}}>
                      <label className="section-label">{label}</label>
                      <input type={type} value={val} onChange={e => set(e.target.value)} placeholder={placeholder} className="input" />
                    </div>
                  ))}
                  <div style={{display:'flex',flexDirection:'column',gap:'var(--sp-2)'}}>
                    <label className="section-label">Device Name (LAN)</label>
                    <input type="text" value={deviceName} onChange={e => setDeviceName(e.target.value)} placeholder="My Device" className="input" />
                    <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)'}}>Shown to nearby devices on the same network</p>
                  </div>
                  <button className="btn-primary" onClick={() => {
                    localStorage.setItem('aegix_profile', JSON.stringify({ name: profileName, email: profileEmail, device: deviceName }));
                    toast('Profile saved!', 'ok');
                  }}>Save changes</button>
                </div>

                {/* Stats card */}
                <div className="card" style={{padding:'var(--sp-5)',display:'flex',flexDirection:'column',gap:'var(--sp-4)'}}>
                  <p className="section-label">Session Statistics</p>
                  <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'var(--sp-3)'}}>
                    {([
                      { label: 'Files Encrypted', value: String(libStats.count ?? 0) },
                      { label: 'Total Size', value: libStats.bytes != null ? (libStats.bytes >= 1073741824 ? (libStats.bytes/1073741824).toFixed(1)+' GB' : libStats.bytes >= 1048576 ? (libStats.bytes/1048576).toFixed(1)+' MB' : (libStats.bytes/1024).toFixed(0)+' KB') : '0 KB' },
                      { label: 'Transfers', value: String(transfers.length) },
                      { label: 'Server IP', value: serverIp || '—' },
                    ] as {label:string;value:string}[]).map(({ label, value }) => (
                      <div key={label} className='card' style={{padding:'var(--sp-3) var(--sp-4)',background:'var(--c-s2)'}}>
                        <p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)'}}>{label}</p>
                        <p style={{fontSize:'var(--ts-base)',fontWeight:700,color:'var(--c-t1)',marginTop:'2px',fontFamily:'var(--font-mono)'}}>{value}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Security info */}
                <div className="card" style={{padding:'var(--sp-5)',display:'flex',flexDirection:'column',gap:'var(--sp-3)'}}>
                  <p className="section-label">Security</p>
                  <div className="status-row status-row-accent" style={{gap:'var(--sp-3)'}}>
                    <Shield size={16} color="var(--c-accent)" style={{flexShrink:0}} />
                    <div><p style={{fontSize:'var(--ts-sm)',fontWeight:600,color:'var(--c-t1)'}}>AES-256-GCM Encryption</p><p style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',marginTop:'2px'}}>All files encrypted client-side. Servers never see your data.</p></div>
                  </div>
                  <div className="status-row status-row-muted" style={{gap:'var(--sp-3)'}}>
                    <Lock size={16} color="var(--c-t3)" style={{flexShrink:0}} />
                    <div><p style={{fontSize:'var(--ts-sm)',fontWeight:500,color:'var(--c-t1)'}}>HTTPS Status</p>
                      <p style={{fontSize:'var(--ts-xs)',color:window.isSecureContext?'var(--c-ok)':'var(--c-warn)',marginTop:'2px'}}>
                        {window.isSecureContext ? '\u2713 Secure — downloads & camera work on all devices' : '\u26A0 HTTP only — run start_https.bat for mobile support'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Privacy & Data */}
                <div className="card" style={{padding:'var(--sp-5)',display:'flex',flexDirection:'column',gap:'var(--sp-3)'}}>
                  <p className="section-label">Privacy &amp; Data</p>
                  <button className='btn-secondary' style={{justifyContent:'flex-start',gap:'var(--sp-3)'}} onClick={() => { setTransfers([]); toast('Transfer history cleared', 'ok'); }}>
                    <X size={15} /> Clear transfer history
                  </button>
                  <button className='btn-danger' style={{justifyContent:'flex-start',gap:'var(--sp-3)'}} onClick={() => {
                    if (confirm('Delete all session data? This cannot be undone.')) {
                      setTransfers([]); setUploadQueue([]); setPassword(''); localStorage.clear(); toast('All session data cleared', 'info');
                    }
                  }}>
                    <LogOut size={15} /> Clear all session data
                  </button>
                </div>

                {/* About */}
                <div className="card" style={{padding:'var(--sp-5)',display:'flex',flexDirection:'column',gap:'var(--sp-3)'}}>
                  <p className="section-label">About</p>
                  <div style={{display:'flex',flexDirection:'column',gap:0}}>
                    {([['App','AEGIX SHARE'],['Encryption','AES-256-GCM + PBKDF2-SHA256'],['Transport','Chunked multipart over HTTP(S)'],['Zero-knowledge','Key in URL fragment — never sent'],['LAN mode','Direct WiFi — no internet needed']] as [string,string][]).map(([k,v]) => (
                      <div key={k} style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',gap:'var(--sp-4)',padding:'var(--sp-2) 0',borderBottom:'1px solid var(--c-b1)'}}>
                        <span style={{fontSize:'var(--ts-xs)',color:'var(--c-t3)',flexShrink:0}}>{k}</span>
                        <span style={{fontSize:'var(--ts-xs)',color:'var(--c-t2)',textAlign:'right'}}>{v}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Sign out */}
                <button className='btn-danger' style={{justifyContent:'center',gap:'var(--sp-2)'}} onClick={() => { setIsLoggedIn(false); setIsGuest(false); toast('Signed out.', 'info'); }}>
                  <LogOut size={16} /> Sign out
                </button>

              </div>
            )}
          </div>
        </div>

        {/* Mobile bottom nav */}
        <nav className="md:hidden" style={{display:'flex',borderTop:'1px solid var(--c-b1)',background:'var(--c-bg)'}}>
          {NAV.map(n => (
            <button key={n.id} onClick={() => setTab(n.id)}
              style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',
                padding:'10px 0',gap:'3px',fontSize:'var(--ts-xs)',fontWeight:600,
                color:tab===n.id?'var(--c-accent)':'var(--c-t3)',
                background:'none',border:'none',cursor:'pointer',fontFamily:'inherit',transition:'color 0.15s ease'}}>
              {n.icon}{n.label.split(' ')[0]}
            </button>
          ))}
        </nav>
      </main>

      {/* ── TOASTS ── */}
      <ToastStack toasts={toasts} />

      {/* ── QR DISPLAY MODAL (z-index 200 to be above everything) ── */}
      {showQR && (
        <div className="overlay" style={{zIndex:200}} onClick={e => { if (e.target === e.currentTarget) setShowQR(false); }}>
          <div className="card animate-slide-up" style={{padding:'var(--sp-6)',maxWidth:'380px',width:'100%',display:'flex',flexDirection:'column',alignItems:'center',gap:'var(--sp-4)'}}>
            <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',width:'100%'}}>
              <h3 style={{fontWeight:600,color:'var(--c-t1)',fontSize:'var(--ts-base)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',maxWidth:'280px'}}>{qrTitle}</h3>
              <button onClick={() => setShowQR(false)} className="btn-ghost" style={{padding:'4px'}}><X size={16} /></button>
            </div>
            <div className="qr-wrapper"><QRCodeSVG value={qrContent} size={200} /></div>
            <div className="mono-data" style={{width:'100%',maxHeight:'72px',overflowY:'auto',textAlign:'center'}}>{qrContent}</div>
            <div style={{display:'flex',gap:'var(--sp-3)',width:'100%'}}>
              <button className="btn-primary" style={{flex:1,padding:'10px'}} onClick={() => { navigator.clipboard.writeText(qrContent); toast('Copied!', 'ok'); setShowQR(false); }}><Copy size={14} /> Copy</button>
              <button className="btn-secondary" style={{flex:1,padding:'10px'}} onClick={() => setShowQR(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* ── QR SCANNER ── */}
      {showScanner && (
        <div className="fixed inset-0 bg-slate-950/90 backdrop-blur-sm flex items-center justify-center p-6 z-[150]">
          <div className="bg-[#13161f] border border-[#1e2133] rounded-3xl p-6 max-w-md w-full flex flex-col items-center gap-4 shadow-2xl">
            <div className="w-full flex items-center justify-between border-b border-[#1e2133] pb-3">
              <div className="flex items-center gap-2"><Scan className="w-4 h-4 text-indigo-400" /><h3 className="font-bold text-slate-200 text-sm">{scannerTitle}</h3></div>
              <button onClick={closeScanner} className="text-slate-500 hover:text-white text-xs font-bold">Cancel</button>
            </div>
            <div className="w-full aspect-video rounded-xl bg-black border border-[#1e2133] overflow-hidden relative flex items-center justify-center">
              {!cameraActive && (<div className="absolute inset-0 flex flex-col items-center justify-center p-4 text-center"><VideoOff className="w-9 h-9 text-slate-700 mb-2" /><p className="text-xs text-slate-500">{cameraError || 'Activating camera…'}</p></div>)}
              <video ref={videoRef} className={`w-full h-full object-cover ${cameraActive ? 'block' : 'hidden'}`} />
              <canvas ref={canvasRef} className="hidden" />
              {cameraActive && (
                <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                  <div className="w-44 h-44 border-2 border-indigo-400/70 border-dashed rounded-2xl animate-pulse" />
                </div>
              )}
            </div>
            <p className="text-[10px] text-slate-500 text-center">Position QR inside the guide to scan automatically</p>
            <div className="w-full border-t border-[#1e2133] pt-3 flex flex-col gap-1.5">
              <label className="text-[10px] font-bold text-slate-400">Or paste link manually</label>
              <input placeholder="Paste link here…" onChange={e => { const v = e.target.value.trim(); if (v && scanCallback) { scanCallback(v); closeScanner(); } }}
                className="w-full bg-[#0d0e17] border border-[#1e2133] rounded-xl text-[11px] px-3.5 py-2.5 focus:outline-none focus:border-indigo-500 text-slate-300 font-mono" />
            </div>
          </div>
        </div>
      )}

      {/* ── LINK READY MODAL ── */}
      {showLinkModal && lastTransfer && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4 z-[100]">
          <div className="bg-[#13161f] border border-[#1e2133] rounded-3xl w-full max-w-[420px] flex flex-col shadow-2xl overflow-hidden animate-slide-up">
            <div className="flex items-center justify-between px-6 pt-6 pb-0">
              <h2 className="text-base font-extrabold text-white">Secure link ready</h2>
              <button onClick={() => setShowLinkModal(false)} className="w-7 h-7 rounded-full bg-[#1a1d2e] hover:bg-[#20243a] flex items-center justify-center text-slate-400 hover:text-white transition-all"><X className="w-3.5 h-3.5" /></button>
            </div>
            <div className="px-6 pt-4">
              <div className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20">
                <div className="w-4 h-4 rounded-full bg-emerald-500 flex items-center justify-center shrink-0"><Check className="w-2.5 h-2.5 text-white" /></div>
                <span className="text-[11px] font-semibold text-emerald-300"><strong>1 file</strong> encrypted · key is in the link hash, never on server</span>
              </div>
            </div>
            <div className="px-6 pt-4 flex flex-col gap-1.5">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Secure transfer link</span>
              <div className="flex items-center gap-2 bg-[#0d0e17] border border-[#1e2133] rounded-xl px-3.5 py-3">
                <Lock className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                <span className="flex-1 font-mono text-[11px] text-slate-300 truncate">{lastTransfer.downloadUrl}</span>
                <button onClick={() => copyLink(lastTransfer.downloadUrl)} className="shrink-0 p-1.5 rounded-lg hover:bg-[#1a1d2e] text-slate-500 hover:text-indigo-400 transition-all">
                  {linkCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
            <div className="px-6 pt-4 grid grid-cols-2 gap-3">
              <button onClick={() => { setShowShareSheet(true); setShowLinkModal(false); }}
                className="flex items-center justify-center gap-2 py-3 rounded-2xl bg-[#1a1d2e] hover:bg-[#20243a] border border-[#1e2133] text-slate-200 font-bold text-xs transition-all"><Globe className="w-4 h-4" /> Share</button>
              <button onClick={() => { setQrContent(lastTransfer.downloadLanUrl || lastTransfer.downloadUrl); setQrTitle(`${lastTransfer.name} (LAN QR)`); setShowQR(true); }}
                className="flex items-center justify-center gap-2 py-3 rounded-2xl bg-[#1a1d2e] hover:bg-[#20243a] border border-[#1e2133] text-slate-200 font-bold text-xs transition-all"><QrCode className="w-4 h-4" /> LAN QR</button>
            </div>
            <div className="px-6 pt-3 flex flex-wrap gap-2">
              <span className="text-[10px] font-bold text-slate-400 bg-[#1a1d2e] px-2.5 py-1 rounded-full border border-[#1e2133]">Expires in {EXPIRY_OPTIONS.find(o => Math.abs(o.value - lastTransfer.linkExpiry) < 0.01)?.label || `${lastTransfer.linkExpiry}h`}</span>
              {lastTransfer.selfDestruct && <span className="text-[10px] font-bold text-amber-300 bg-amber-500/10 px-2.5 py-1 rounded-full border border-amber-500/20">Self-destruct</span>}
              {lastTransfer.requirePassword && <span className="text-[10px] font-bold text-purple-300 bg-purple-500/10 px-2.5 py-1 rounded-full border border-purple-500/20">Password protected</span>}
              {lastTransfer.downloadLimit > 0 ? <span className="text-[10px] font-bold text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-full border border-indigo-500/20">{lastTransfer.downloadLimit} download(s) max</span> : <span className="text-[10px] font-bold text-slate-400 bg-[#1a1d2e] px-2.5 py-1 rounded-full border border-[#1e2133]">Unlimited downloads</span>}
            </div>
            <div className="px-6 pt-5 pb-6 flex gap-3">
              <button onClick={() => setShowLinkModal(false)} className="flex-1 py-3 rounded-2xl border border-[#1e2133] hover:bg-[#1a1d2e] text-slate-300 font-bold text-xs transition-all">Done</button>
              <button onClick={() => copyLink(lastTransfer.downloadUrl)}
                className="flex-1 py-3 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-extrabold text-xs flex items-center justify-center gap-2 shadow-lg hover:from-indigo-500 hover:to-purple-500 transition-all">
                {linkCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />} {linkCopied ? 'Copied!' : 'Copy link'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── SHARE SHEET ── */}
      {showShareSheet && lastTransfer && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-end sm:items-center justify-center p-0 sm:p-4 z-[100]"
          onClick={e => { if (e.target === e.currentTarget) setShowShareSheet(false); }}>
          <div className="bg-[#13161f] border border-[#1e2133] rounded-t-3xl sm:rounded-3xl w-full sm:max-w-sm flex flex-col shadow-2xl overflow-hidden animate-slide-up">
            <div className="flex items-start justify-between px-5 pt-5 pb-0">
              <div><h2 className="text-base font-extrabold text-white">Share link</h2><p className="text-[11px] text-slate-500 mt-0.5">Encrypted · expires soon</p></div>
              <button onClick={() => setShowShareSheet(false)} className="w-7 h-7 rounded-full bg-[#1a1d2e] hover:bg-[#20243a] flex items-center justify-center text-slate-400 hover:text-white transition-all"><X className="w-3.5 h-3.5" /></button>
            </div>
            <div className="px-5 pt-3.5">
              <div className="flex items-center gap-2.5 bg-[#0d0e17] border border-[#1e2133] rounded-xl px-3.5 py-3">
                <Lock className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                <span className="flex-1 font-mono text-[11px] text-slate-400 truncate">{lastTransfer.downloadUrl.replace(/^https?:\/\//, '').slice(0, 40)}…</span>
                <button onClick={() => { navigator.clipboard.writeText(lastTransfer.downloadUrl); toast('Copied!', 'ok'); }} className="shrink-0 flex items-center gap-1 text-[11px] font-bold text-indigo-400 hover:text-indigo-300 px-2 py-1 rounded-lg hover:bg-indigo-500/10 transition-all"><Copy className="w-3.5 h-3.5" /> Copy</button>
              </div>
            </div>
            <div className="px-5 pt-3">
              <button onClick={async () => { if (navigator.share) { try { await navigator.share({ title: `Aegix: ${lastTransfer.name}`, url: lastTransfer.downloadUrl }); } catch { } } else { navigator.clipboard.writeText(lastTransfer.downloadUrl); toast('Link copied', 'info'); } }}
                className="w-full flex items-center gap-3.5 px-4 py-3.5 rounded-2xl bg-[#1a1d2e] hover:bg-[#20243a] border border-[#1e2133] transition-all group">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shrink-0"><Globe className="w-5 h-5 text-white" /></div>
                <div className="flex-1 text-left"><p className="text-xs font-bold text-slate-200">System share…</p><p className="text-[10px] text-slate-500">Open your device share menu</p></div>
                <ChevronRight className="w-4 h-4 text-slate-600" />
              </button>
            </div>
            <div className="px-5 pt-4 pb-1"><span className="text-[9px] font-extrabold text-slate-600 uppercase tracking-[0.15em]">Share via app</span></div>
            <div className="px-3 pb-6 flex flex-col gap-0.5">
              {([
                {
                  name: 'WhatsApp',
                  color: '#25D366',
                  svg: (<svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347zM11.999 2C6.477 2 2 6.477 2 12c0 1.756.459 3.45 1.337 4.937L2 22l5.233-1.37A9.959 9.959 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 11.999 2zm0 18.333a8.333 8.333 0 01-4.237-1.155l-.305-.181-3.105.814.832-3.021-.199-.32A8.34 8.34 0 013.667 12c0-4.604 3.745-8.333 8.332-8.333 4.59 0 8.334 3.73 8.334 8.333 0 4.604-3.745 8.333-8.334 8.333z"/></svg>),
                  href: () => `https://wa.me/?text=${encodeURIComponent(`📦 ${lastTransfer.name}\n${lastTransfer.downloadUrl}`)}`,
                  copy: false,
                },
                {
                  name: 'Telegram',
                  color: '#0088CC',
                  svg: (<svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg>),
                  href: () => `https://t.me/share/url?url=${encodeURIComponent(lastTransfer.downloadUrl)}&text=${encodeURIComponent(lastTransfer.name)}`,
                  copy: false,
                },
                {
                  name: 'X / Twitter',
                  color: '#000000',
                  svg: (<svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.744l7.73-8.835L1.254 2.25H8.08l4.213 5.567zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>),
                  href: () => `https://twitter.com/intent/tweet?url=${encodeURIComponent(lastTransfer.downloadUrl)}&text=${encodeURIComponent(`Sharing: ${lastTransfer.name}`)}`,
                  copy: false,
                },
                {
                  name: 'Email',
                  color: '#6264A7',
                  svg: (<svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>),
                  href: () => `mailto:?subject=${encodeURIComponent(lastTransfer.name)}&body=${encodeURIComponent(`Download: ${lastTransfer.downloadUrl}`)}`,
                  copy: false,
                },
                {
                  name: 'SMS',
                  color: '#34C759',
                  svg: (<svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H5.17L4 17.17V4h16v12zM7 9h2v2H7zm4 0h2v2h-2zm4 0h2v2h-2z"/></svg>),
                  href: () => `sms:?body=${encodeURIComponent(`${lastTransfer.name}: ${lastTransfer.downloadUrl}`)}`,
                  copy: false,
                },
                {
                  name: 'Instagram (copy link)',
                  color: '#E1306C',
                  svg: (<svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z"/></svg>),
                  href: () => '',
                  copy: true,
                },
              ] as { name: string; color: string; svg: React.ReactNode; href: () => string; copy: boolean }[]).map(({ name, color, svg, href, copy }) => (
                <button key={name} onClick={() => {
                  if (copy) { navigator.clipboard.writeText(lastTransfer.downloadUrl); toast('Link copied for Instagram!', 'ok'); }
                  else window.open(href(), '_blank');
                }}
                  style={{width:'100%',display:'flex',alignItems:'center',gap:'14px',padding:'12px',borderRadius:'var(--r-xl)',transition:'background 0.15s ease',background:'transparent',border:'none',cursor:'pointer',fontFamily:'inherit'}}
                  onMouseEnter={e=>(e.currentTarget as HTMLElement).style.background='var(--c-s2)'}
                  onMouseLeave={e=>(e.currentTarget as HTMLElement).style.background='transparent'}
                >
                  <div style={{width:'40px',height:'40px',borderRadius:'var(--r-lg)',background:color,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}>
                    {svg}
                  </div>
                  <div style={{flex:1,textAlign:'left'}}>
                    <p style={{fontSize:'var(--ts-sm)',fontWeight:600,color:'var(--c-t1)'}}>{name}</p>
                  </div>
                  {copy ? <Copy size={14} color="var(--c-t3)" /> : <ChevronRight size={14} color="var(--c-t3)" />}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Toast Stack ───────────────────────────────────────────────────────────────
function ToastStack({ toasts }: { toasts: Toast[] }) {
  return (
    <div style={{position:'fixed',top:'var(--sp-4)',right:'var(--sp-4)',display:'flex',flexDirection:'column',gap:'var(--sp-2)',zIndex:300,pointerEvents:'none'}}>
      {toasts.map(t => (
        <div key={t.id}
          className={`animate-slide-down pointer-events-auto ${
            t.kind === 'ok'  ? 'toast toast-ok'
          : t.kind === 'err' ? 'toast toast-err'
          :                    'toast toast-info'
          }`}
        >
          {t.text}
        </div>
      ))}
    </div>
  );
}