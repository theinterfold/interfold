// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SURVEY_API: string
  readonly VITE_CHAIN_ID?: string
  readonly VITE_EXPLORER_TX?: string
  readonly VITE_ADMIN_KEY?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
