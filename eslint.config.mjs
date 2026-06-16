import { defineConfig, globalIgnores } from 'eslint/config'
import config from '@interfold/config/eslint.config.js'

export default defineConfig([
  globalIgnores([
    // Github submodules.
    'examples/CRISP/packages/crisp-contracts/lib/risc0-ethereum',
    'templates/default/lib/risc0-ethereum',
    // Build and cache directories.
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/cache/**',
    '**/coverage/**',
    '**/target/**',
    '**/artifacts/**',
    '**/types/**',
    '**/deployments/**',
    '**/.cache-synpress/**',
    '**/.next/**',
    '**/.cargo/**',
    '**/.interfold/**',
    '**/test-results/**',
    '**/playwright-report/**',
    // Generated WASM bindings
    '**/pkg/**',
  ]),
  {
    extends: [config],
    files: ['**/*.{js,jsx,ts,tsx}'],
  },
])
