import os
import socket as _socket
from pathlib import Path

# ─── Load .env file if present (development convenience) ──────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — env vars must be set externally

# ─── Base paths ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ─── Security — read from environment variables ────────────────────────────────
# In production: set DJANGO_SECRET_KEY to a long random string.
# Never commit the real key to source control.
SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'django-insecure-CHANGE-ME-IN-PRODUCTION-use-DJANGO_SECRET_KEY-env-var'
)

# Default True for local / LAN use; set DJANGO_DEBUG=False in production.
DEBUG = os.environ.get('DJANGO_DEBUG', 'True').lower() in ('true', '1', 'yes')

# ─── ALLOWED_HOSTS — include all LAN IPs automatically ───────────────────────
# This app is designed to serve devices on the local network (LAN sharing).
# We auto-detect every IP bound to this machine so that phones/tablets opening
# the QR-code URL (e.g. http://192.168.31.192:8000/) are never rejected.
_raw_hosts = os.environ.get('DJANGO_ALLOWED_HOSTS', '')
if _raw_hosts:
    ALLOWED_HOSTS = [h.strip() for h in _raw_hosts.split(',') if h.strip()]
else:
    # Start with the wildcard in DEBUG; narrow it in production if desired.
    ALLOWED_HOSTS = ['*']

# Always auto-include this machine's hostname and all bound LAN IPs so that
# requests arriving via the LAN IP pass Django's host-header validation even
# when ALLOWED_HOSTS is narrowed to a specific list in production.
try:
    _hostname = _socket.gethostname()
    if _hostname and _hostname not in ALLOWED_HOSTS and '*' not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(_hostname)
    _, _, _addrs = _socket.gethostbyname_ex(_hostname)
    for _addr in _addrs:
        # Only IPv4 addresses; skip loopback (already in the list or implicit)
        if _addr and ':' not in _addr and _addr not in ALLOWED_HOSTS and '*' not in ALLOWED_HOSTS:
            ALLOWED_HOSTS.append(_addr)
except Exception:
    pass   # never crash settings loading due to network unavailability

# ─── File upload limits ────────────────────────────────────────────────────────
# Allow large file uploads — up to 1 GB
# AES-GCM ciphertext is original size + 16-byte tag, so we allow 1 GB + 16 MB headroom
_1GB = 1 * 1024 * 1024 * 1024          # 1,073,741,824 bytes
DATA_UPLOAD_MAX_MEMORY_SIZE = _1GB + 16 * 1024 * 1024   # 1 GB + 16 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = _1GB + 16 * 1024 * 1024   # 1 GB + 16 MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000   # keep default reasonable

# ─── Application definition ───────────────────────────────────────────────────
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic',  # must be before django.contrib.staticfiles
    'django.contrib.staticfiles',

    # Third party
    'corsheaders',

    # Custom apps
    'api',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',          # CORS headers must be first
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',      # static files in production
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'dist'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

# ─── Database ─────────────────────────────────────────────────────────────────
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {
            # Increase SQLite busy-wait timeout from the default 5 s to 20 s.
            # Prevents OperationalError under rapid concurrent write requests.
            'timeout': 20,
        },
    }
}

# ─── Password validation ──────────────────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ─── Internationalization ─────────────────────────────────────────────────────
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ─── Static files (CSS, JavaScript, Images) ───────────────────────────────────
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Assets from the Vite build live in dist/assets/; WhiteNoise also picks them
# up via the custom serve_static_asset view in urls.py.
STATICFILES_DIRS = [
    BASE_DIR / 'dist',
]

# WhiteNoise compressed manifest storage (fingerprinted filenames for cache-busting)
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# ─── Media files (encrypted chunk uploads) ────────────────────────────────────
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ─── CORS ─────────────────────────────────────────────────────────────────────
# The API is fully token/link-based (transfer id + key in the URL fragment) and
# never relies on cookies or session auth, so credentialed CORS requests are not
# needed. CORS_ALLOW_ALL_ORIGINS=True together with CORS_ALLOW_CREDENTIALS=True
# is a contradictory combination per the CORS spec — keep credentials off.
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = False

# ─── Security headers (applied in production only) ────────────────────────────
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    # Enable HSTS only when your site has a valid TLS certificate
    # SECURE_HSTS_SECONDS = 31536000
    # SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    # SECURE_HSTS_PRELOAD = True
    # SECURE_SSL_REDIRECT = True  # redirect HTTP → HTTPS
