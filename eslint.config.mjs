import { defineConfig, globalIgnores } from 'eslint/config'
import config from '@interfold/config/eslint.config.js'

export default defineConfig([
  globalIgnores([
    // External Solidity libraries, including copies retained by older checkouts.
    'examples/CRISP/packages/crisp-contracts/lib/**',
    'templates/default/lib/**',
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
    '.claude/worktrees/**',
    '**/test-results/**',
    '**/playwright-report/**',
    // Generated WASM bindings
    '**/pkg/**',
    // Bundled dashboard assets
    'crates/dashboard/assets/**',
  ]),
  {
    extends: [config],
    files: ['**/*.{js,jsx,ts,tsx}'],
  },
])
