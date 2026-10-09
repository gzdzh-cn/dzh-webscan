import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({ plugins: [vue()], build: { outDir: '../internal/website/ui', emptyOutDir: true, chunkSizeWarningLimit: 800 }, server: { proxy: { '/api': { target: 'https://127.0.0.1:19444', secure: false, changeOrigin: false, configure(proxy) { proxy.on('proxyReq', (outgoing, request) => { if (request.headers.origin) outgoing.setHeader('Origin', `https://${request.headers.host}`) }) } } } } })
