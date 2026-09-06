# @interfold/ckks-editorial

The CRISP editorial look (mint paper, serif, numbered gutters, mono captions), shared by every
CKKS demo app. Ported from `examples/CRISP/client/src/design/` and extended with FHE-specific
components (`Fhe.tsx`): `ProofSteps`, `RoundTimeline`, `EncryptedInputCard`, `ResultCard`,
`RoundCard`, `HonestScope`, `WalletPill`.

Consume as a source package (no build step):

```json
"@interfold/ckks-editorial": "file:../../../ckks-common/packages/ckks-editorial"
```

```tsx
import '@interfold/ckks-editorial/styles.css'
import { EditorialShell, SectionHeader, ResultCard } from '@interfold/ckks-editorial'
```

Palette per app (`<EditorialShell palette=…>`): auction `ink`, salary `moss`, credit `clay`,
matching `interfold` (mint), treasury `bone`, federated averaging `tomato`. Fonts: load Source
Serif 4 + JetBrains Mono from Google Fonts in `index.html` (see CRISP's `client/index.html`).
