# @interfold/config

Shared build tooling configuration for the Interfold monorepo. This is an **internal package** — it
does not export runtime code. It provides common `tsup`, TypeScript, and ESLint configurations
consumed by all other TypeScript packages.

## Exported Configs

| Export                | File                | Purpose                                            |
| --------------------- | ------------------- | -------------------------------------------------- |
| `./tsup`              | `tsup.config.js`    | Shared tsup bundler config (ESM + CJS dual output) |
| `./tsconfig.json`     | `tsconfig.json`     | Base TypeScript config for library packages        |
| `./dom.tsconfig.json` | `dom.tsconfig.json` | TypeScript config for browser/DOM packages         |
| `./eslint.config.js`  | `eslint.config.js`  | Shared ESLint rules                                |

## Usage

Extend the shared TypeScript config in a package's `tsconfig.json`:

```json
{
  "extends": "@interfold/config/tsconfig.json",
  "compilerOptions": {
    "outDir": "dist"
  },
  "include": ["src"]
}
```

Import the shared tsup config in a package's `tsup.config.ts`:

```ts
export { default } from '@interfold/config/tsup'
```

## License

LGPL-3.0-only
