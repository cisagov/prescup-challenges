import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react({ fastRefresh: false })],

  // Keep esbuild in play, but avoid the big dependency scan
  optimizeDeps: {
    noDiscovery: true,
    include: ['react', 'react-dom']
  },

  server: {
    host: true,
    port: 3000,
    allowedHosts: ['safehouse.local'],

    // Critical for constrained runtimes (avoid tons of fs.watch handles)
    watch: {
      usePolling: true,
      interval: 750
    },

    // HMR websocket often causes trouble on challenge ingress
    hmr: false,

    proxy: {
      '/health':    { target: 'http://datawarehouse.safehouse.local:5000', changeOrigin: true, secure: false },
      '/api':       { target: 'http://datawarehouse.safehouse.local:5000', changeOrigin: true, secure: false },
      '/portal':    { target: 'http://datawarehouse.safehouse.local:5000', changeOrigin: true, secure: false },
      '/artifacts': { target: 'http://datawarehouse.safehouse.local:5000', changeOrigin: true, secure: false }
    }
  }
})

