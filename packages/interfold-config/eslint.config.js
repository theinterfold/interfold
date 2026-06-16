// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import js from '@eslint/js'
import tseslint from '@typescript-eslint/eslint-plugin'
import tsparser from '@typescript-eslint/parser'
import prettier from 'eslint-config-prettier'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'

export default [
  js.configs.recommended,
  {
    languageOptions: {
      parser: tsparser,
      globals: {
        ...globals.node,
        ...globals.browser,
      },
      ecmaVersion: 2022,
      sourceType: 'module',
    },
    plugins: {
      '@typescript-eslint': tseslint,
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-inferrable-types': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
      ...reactHooks.configs.recommended.rules,
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/exhaustive-deps': 'warn',
      'react-hooks/purity': 'warn',
      'react-refresh/only-export-components': [
        'warn',
        {
          allowConstantExport: true,
        },
      ],
      // todo: remove this use proper typing instead.
      '@typescript-eslint/no-explicit-any': 'off',
      ...prettier.rules,
    },
  },
  {
    files: ['**/*.{spec,test}.{js,jsx,ts,tsx}', '**/test/**/*.{js,jsx,ts,tsx}', '**/tests/**/*.{js,jsx,ts,tsx}'],
    languageOptions: {
      globals: {
        ...globals.mocha,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-expressions': 'off',
    },
  },
]
