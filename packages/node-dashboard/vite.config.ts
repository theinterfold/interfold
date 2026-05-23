// SPDX-License-Identifier: LGPL-3.0-only
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

/** Rename index.html → dashboard.html in the output bundle */
function renameToDashboard(): Plugin {
  return {
    name: 'rename-to-dashboard',
    enforce: 'post',
    generateBundle(_, bundle) {
      const entry = bundle['index.html']
      if (entry && 'source' in entry) {
        entry.fileName = 'dashboard.html'
        bundle['dashboard.html'] = entry
        delete bundle['index.html']
      }
    },
  }
}

export default defineConfig({
  plugins: [react(), viteSingleFile(), renameToDashboard()],
  build: {
    outDir: '../../crates/dashboard/src',
    emptyOutDir: false,
  },
  server: {
    port: 5174,
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
})
