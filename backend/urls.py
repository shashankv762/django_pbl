"""
backend/urls.py — URL configuration for Aegix Share

Routing strategy:
  /admin/           → Django admin
  /api/             → REST API (api app)
  /media/<path>     → Encrypted chunk files served directly (dev + prod)
  /assets/<path>    → Vite-built JS/CSS bundles from dist/assets/
  /<filename>       → Public root files (logo.png, favicon.ico, etc.)
  /                 → React SPA (dist/index.html) — catch-all for hash routing
"""
import os
import mimetypes
import posixpath

from django.contrib import admin
from django.urls import path, include, re_path
from django.http import HttpResponse, FileResponse
from django.conf import settings

# ─── MIME type registration ───────────────────────────────────────────────────
# Windows registry sometimes has wrong or missing entries for modern web types.
# Registering explicitly here ensures browsers receive correct Content-Type
# headers and execute JS/CSS correctly regardless of host OS configuration.
mimetypes.add_type('application/javascript',  '.js')
mimetypes.add_type('application/javascript',  '.mjs')
mimetypes.add_type('text/css',                '.css')
mimetypes.add_type('application/wasm',        '.wasm')
mimetypes.add_type('image/svg+xml',           '.svg')
mimetypes.add_type('application/json',        '.json')
mimetypes.add_type('font/woff2',              '.woff2')
mimetypes.add_type('font/woff',               '.woff')
mimetypes.add_type('image/png',               '.png')
mimetypes.add_type('image/jpeg',              '.jpg')
mimetypes.add_type('image/x-icon',            '.ico')


# ─── Helper: add CORS + no-cache headers to every file response ──────────────

def _cors_headers(response):
    """
    Add permissive CORS and no-cache headers to a response.
    Required when a phone on the LAN IP opens the QR URL and the browser
    loads JS/CSS chunks as module scripts — browser enforces CORS on ES modules.
    """
    response['Access-Control-Allow-Origin']   = '*'
    response['Access-Control-Allow-Methods']  = 'GET, OPTIONS'
    response['Access-Control-Allow-Headers']  = '*'
    return response


# ─── Views ───────────────────────────────────────────────────────────────────

def serve_react(request, *args, **kwargs):
    """
    Serve the React SPA index.html for all non-API routes.
    This ensures client-side hash routing (#/download?id=...) works correctly
    when a phone opens a QR code URL — the path is always '/' and the hash
    fragment is processed entirely in the browser.
    """
    index_path = os.path.join(settings.BASE_DIR, 'dist', 'index.html')
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            content = f.read()
        response = HttpResponse(content, content_type='text/html; charset=utf-8')
        # Never cache index.html — must always be fresh so QR links work
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response['Pragma'] = 'no-cache'
        return response
    else:
        return HttpResponse(
            "<h2>Frontend not built.</h2>"
            "<p>Run <code>npm run build</code> in the project root, then restart Django.</p>"
            "<p>Or for development run <code>npm run dev</code> on port 5173.</p>",
            content_type='text/html',
            status=503
        )


def serve_static_asset(request, asset_path):
    """
    Serve Vite-built JS/CSS bundles from dist/assets/.

    Why a custom view instead of WhiteNoise?
    WhiteNoise serves at /static/ prefix. Vite outputs assets at /assets/ (no
    prefix). We bridge that gap here with proper MIME types and CORS headers so
    module scripts load correctly on both localhost AND LAN IP.
    """
    # Security: <path:asset_path> already prevents traversal above dist/assets/
    # but we double-check by stripping leading slashes and normalising.
    safe_rel  = posixpath.normpath(asset_path).lstrip('/')
    file_path = os.path.join(settings.BASE_DIR, 'dist', 'assets', safe_rel)
    dist_assets_real = os.path.realpath(os.path.join(settings.BASE_DIR, 'dist', 'assets'))
    if not os.path.realpath(file_path).startswith(dist_assets_real + os.sep):
        return HttpResponse('Forbidden', status=403)

    if not os.path.exists(file_path):
        return HttpResponse('Asset not found', status=404)

    content_type, _ = mimetypes.guess_type(file_path)
    with open(file_path, 'rb') as f:
        data = f.read()

    response = HttpResponse(data, content_type=content_type or 'application/octet-stream')
    # Vite outputs content-hashed filenames — safe to cache for 1 year
    response['Cache-Control'] = 'public, max-age=31536000, immutable'
    return _cors_headers(response)


def serve_public_file(request, filename):
    """
    Serve files from the Vite public/ directory (logo.png, favicon.ico, etc.)
    that end up in the dist/ root after build.
    """
    # Security: <str:filename> only matches a single path segment without '/'.
    # No traversal possible, but we still reject names with dots that step up.
    if '..' in filename:
        return HttpResponse('Forbidden', status=403)

    # Try dist/ first (production build), fall back to public/ (dev)
    for base in (os.path.join(settings.BASE_DIR, 'dist'),
                 os.path.join(settings.BASE_DIR, 'public')):
        file_path = os.path.join(base, filename)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            with open(file_path, 'rb') as f:
                data = f.read()
            response = HttpResponse(data, content_type=content_type or 'application/octet-stream')
            response['Cache-Control'] = 'public, max-age=3600'
            return _cors_headers(response)

    return HttpResponse('File not found', status=404)


def serve_media_chunk(request, path):
    """
    Serve encrypted chunk files from MEDIA_ROOT in both debug and production.

    WhiteNoise does NOT serve MEDIA files — we handle them explicitly.
    The files are AES-256-GCM ciphertext so serving without additional
    auth is safe: without the key (URL fragment) they are meaningless.

    Adds full CORS headers so a device on the LAN IP can fetch chunks
    from the same Django origin without cross-origin issues.
    """
    # Sanitize path to prevent directory traversal
    safe_path      = posixpath.normpath(path).lstrip('/')
    file_path      = os.path.join(settings.MEDIA_ROOT, safe_path)
    media_root_real = os.path.realpath(settings.MEDIA_ROOT)
    file_path_real  = os.path.realpath(file_path)

    if not file_path_real.startswith(media_root_real + os.sep):
        return HttpResponse('Forbidden', status=403)

    if not os.path.exists(file_path):
        resp = HttpResponse('Media file not found', status=404)
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    content_type, _ = mimetypes.guess_type(file_path)
    response = FileResponse(
        open(file_path, 'rb'),
        content_type=content_type or 'application/octet-stream',
    )
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response['Pragma']        = 'no-cache'
    response['Access-Control-Allow-Origin']  = '*'
    response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    return response


def serve_favicon(request):
    """Redirect /favicon.ico to the logo.png."""
    return serve_public_file(request, 'logo.png')


# ─── URL patterns ─────────────────────────────────────────────────────────────

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),

    # Favicon shortcut
    path('favicon.ico', serve_favicon, name='favicon'),

    # Serve encrypted media chunks (works in both DEBUG and production)
    re_path(r'^media/(?P<path>.+)$', serve_media_chunk, name='serve_media'),

    # Serve Vite-built JS/CSS bundles (content-hashed, 1-year cache)
    path('assets/<path:asset_path>', serve_static_asset, name='serve_asset'),

    # Serve public root files: logo.png, favicon.ico, etc.
    path('<str:filename>', serve_public_file, name='serve_public_file'),

    # Catch-all: serve React SPA (must be last — handles all hash routes)
    path('index.html', serve_react, name='react_spa_index'),
    re_path(r'^$', serve_react, name='react_spa_root'),
]
