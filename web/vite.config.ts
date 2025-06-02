import path from 'path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueJsx from '@vitejs/plugin-vue-jsx'
import wasmPack from 'vite-plugin-wasm-pack'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'
import { serviceWorkerPlugin } from './plugins/service-worker'
// import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  base: '/',
  envDir: '../',
  envPrefix: 'APP_',
  plugins: [
    vue(),
    vueJsx(),
    wasm(),
    topLevelAwait(),
    wasmPack('../cryptfns'),
    serviceWorkerPlugin({
      filename: 'sw.ts'
    })
    // VitePWA({ ... })
  ],
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:5443',
        changeOrigin: true,
        secure: false
      }
    }
  }, // <-- ✅ COMMA ADDED HERE
  optimizeDeps: {
    exclude: ['cryptfns'],
    esbuildOptions: {
      define: {
        global: 'globalThis'
      }
    },
    include: ['vue', 'vue-router', 'pinia']
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '!': path.resolve(__dirname, 'services'),
      types: path.resolve(__dirname, 'types')
    }
  },
  css: {
    postcss: {
      plugins: [require('tailwindcss'), require('autoprefixer')]
    }
  }
})
