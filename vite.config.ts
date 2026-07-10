import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],

  // ── Development server ──────────────────────────────────────────────────────
  server: {
    host: true,
    port: 5173,
    // Proxy API and media requests to Django dev server so the frontend
    // never hits CORS issues during development (both served from same origin).
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/media': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },

  // ── Path aliases ────────────────────────────────────────────────────────────
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },

  // ── Production build ────────────────────────────────────────────────────────
  build: {
    outDir: 'dist',
    sourcemap: false,          // no source maps in production build
    emptyOutDir: true,         // clean dist/ before each build
    rollupOptions: {
      output: {
        // Separate vendor chunks for better long-term caching
        manualChunks: {
          react:  ['react', 'react-dom'],
          crypto: ['@noble/ciphers', '@noble/hashes'],
          ui:     ['lucide-react', 'qrcode.react'],
        },
      },
    },
  },
})
