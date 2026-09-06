// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link } from 'react-router-dom'
import { Keyhole, Function, ShieldCheck } from '@phosphor-icons/react'
import { Cipher, HonestScope, MarkerUnderline, SectionHeader, ThresholdRow } from '@interfold/ckks-editorial'

const PRINCIPLES = [
  {
    icon: Keyhole,
    label: 'Private',
    body: 'Each DAO’s exposure vector, its weighted copy w∘x and its cross-term mask are encrypted and proven in this browser. The server and the chain only ever see ciphertext and proofs.',
  },
  {
    icon: Function,
    label: 'Aggregated, then multiplied',
    body: 'The network sums every DAO’s ciphertexts FIRST — the per-asset totals never leave encryption — then takes ONE ciphertext × ciphertext product under the committee’s level-0 relinearization key.',
  },
  {
    icon: ShieldCheck,
    label: 'One scalar opens',
    body: 'The committee threshold-decrypts a single ciphertext. Coefficient 0 is the weighted concentration risk of the COMBINED book; every other coefficient is a cross term hidden by the DAOs’ masks.',
  },
]

const STEPS = [
  {
    num: '01',
    title: 'Register the round: weights + DAOs',
    body: 'The round opener registers the public weights w[4] (|wₐ| ≤ 1, fixed point ×2¹⁶, negatives as p − |W| field words) and the DAO list on the program contract: slot i is daos[i]. At least two DAOs per round; each address submits once, from its own wallet.',
  },
  {
    num: '02',
    title: 'Encrypt three ciphertexts, prove seven legs — in your browser',
    body: 'You cap-normalise your exposures to [0, 1] and pick a fresh cross-term mask of 128 integers in [0, 1024). Three vectors are CKKS coefficient-encoded (coefficient k is exactly round(Δ·vₖ), ParamSet 5: N=512, 3 limbs, Δ=2⁴⁰) and encrypted here (WASM): forward(x), reversed(w∘x) and mask(m). Seven UltraHonk proofs are generated locally.',
  },
  {
    num: '03',
    title: 'Submit from your wallet',
    body: 'publishInput is sent from your own key: the circuit’s public address must equal msg.sender, its index your registered slot and its four weights words the round’s registered weights. The contract verifies all seven proofs on-chain (20,037,798 gas measured, 105.6 KB calldata).',
  },
  {
    num: '04',
    title: 'Evaluate + open',
    body: 'Once every registered DAO is in (or the window closes with ≥ 2), the program sums F = Σ forward(xᵢ), R = Σ reversed(w∘xᵢ), M = Σ mask(mᵢ) and computes relin(F · R) + M homomorphically — ONE ct × ct product under the level-0 key, one rescale. Coefficient 0 of the opened output is −Σₐ wₐ(Σᵢ xᵢ,ₐ)² (the tᴺ ≡ −1 wrap; the app negates).',
  },
]

export const Home = () => (
  <>
    <section className="pad-section">
      <div className="split">
        <div className="col" style={{ gap: 36 }}>
          <div className="col" style={{ gap: 18 }}>
            <div className="mono muted">Private treasury risk on a threshold-CKKS committee</div>
            <h1 className="display headline">
              Several treasuries, <MarkerUnderline>one</MarkerUnderline> risk number.
              <br />
              No book is ever opened.
            </h1>
            <p className="lede" style={{ maxWidth: 'none' }}>
              n DAOs learn the weighted concentration risk Σₐ wₐ(Σᵢ xᵢ,ₐ)² of their COMBINED treasury under public risk weights w — without any
              DAO, the coordination server or the committee ever seeing a single book, or even the aggregate book. The committee runs no app
              logic: one DKG, one level-0 relinearization-key ceremony, one threshold decryption of one ciphertext.
            </p>
          </div>
          <ul className="col" style={{ gap: 18, listStyle: 'none', margin: 0, padding: 0 }}>
            {PRINCIPLES.map(({ icon: Icon, label, body }) => (
              <li key={label} className="row" style={{ alignItems: 'flex-start', gap: 16 }}>
                <Icon size={28} weight="light" style={{ flexShrink: 0, marginTop: 2 }} />
                <div>
                  <span className="accent" style={{ fontWeight: 600, marginRight: 8 }}>
                    {label}.
                  </span>
                  <span className="muted">{body}</span>
                </div>
              </li>
            ))}
          </ul>
          <div>
            <Link to="/rounds" className="btn lg" data-testid="go-rounds">
              Open the rounds →
            </Link>
          </div>
        </div>

        <div className="split-visual">
          <div className="card col" style={{ gap: 18 }}>
            <div className="between">
              <span className="mono muted">forward(x), encrypted</span>
              <span className="tag">ParamSet 5 · N=512</span>
            </div>
            <Cipher seed={5} length={128} blockSize={4} highlight />
            <div className="hr-soft" />
            <div className="between">
              <span className="mono muted">reversed(w∘x), encrypted</span>
              <span className="tag">public w[4]</span>
            </div>
            <Cipher seed={512} length={96} blockSize={4} />
            <div className="hr-soft" />
            <div className="between">
              <span className="mono muted">mask(m), encrypted</span>
              <span className="tag">128 × [0, 1024)</span>
            </div>
            <Cipher seed={1024} length={96} blockSize={4} />
            <div className="hr-soft" />
            <div className="col" style={{ gap: 8 }}>
              <span className="mono muted">Threshold committee · n=5, t=1</span>
              <ThresholdRow signed={5} total={5} />
            </div>
          </div>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <SectionHeader num="01" kicker="PROTOCOL" title="Four steps, one opening" meta="depth 1 · 1 ceremony" />
      <div className="grid-2" style={{ marginTop: 28 }}>
        {STEPS.map((s) => (
          <div key={s.num} className="card col" style={{ gap: 10 }}>
            <div className="mono muted">Nº {s.num}</div>
            <div className="h3">{s.title}</div>
            <p className="muted" style={{ margin: 0 }}>
              {s.body}
            </p>
          </div>
        ))}
      </div>
    </section>

    <section className="pad-section">
      <SectionHeader num="02" kicker="PROOFS" title="What the seven proofs establish" meta="Greco ×6 + validity" />
      <div className="col" style={{ gap: 16, marginTop: 28 }}>
        <div className="card">
          <b>Well-formed encryptions (Greco, 3 × 2 legs).</b>{' '}
          <span className="muted">
            ct0 = pk0·u + e0 + m and ct1 = pk1·u + e1 per RNS limb for all THREE ciphertexts, with u/e bounded — each ciphertext really encrypts
            its committed message with fresh randomness (u_commitment shared across its two legs).
          </span>
        </div>
        <div className="card">
          <b>Coefficient layout + policy (treasury leg).</b>{' '}
          <span className="muted">
            The forward message has round(Δ·Xₐ/2¹⁶) on coefficient a+1 with 0 ≤ Xₐ ≤ 2¹⁶; the reversed message has wₐ·xₐ on coefficient N−a−1
            under the PUBLIC weights; the mask message has Δ·mⱼ with mⱼ &lt; 1024 on coefficients 1…128 — and EVERY other coefficient of all
            three is exactly 0. A DAO cannot inflate its own weight, hide an exposure, or break the product’s precision.
          </span>
        </div>
        <div className="card">
          <b>Bindings.</b>{' '}
          <span className="muted">
            The three message commitments recomputed in the treasury leg equal the ones the Greco ct0 legs output; the address is bound to
            msg.sender, the slot to the registered list and the weight words to the round’s registered weights on-chain. Nobody can submit
            somebody else’s book, use different weights, or submit twice.
          </span>
        </div>
        <div className="card">
          <b>Why the masks.</b>{' '}
          <span className="muted">
            The product F·R leaks aggregate cross terms Σ w_b Xₐ X_b on coefficients 1…; each DAO adds uniform integers on those positions so
            the opened cross terms are useless (demo hiding ratio 2¹⁰).
          </span>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <HonestScope
        items={[
          'Insecure N=512 demo params (ParamSet 5, 3 limbs); 20 smudging bits vs the ~78 the calculator requires at λ=50.',
          'Cross-term mask hiding ratio is 2¹⁰ (DEMO), not statistical.',
          'The published plaintext bytes are not bound to the C7 proof’s u_global (decode gap).',
          'RISC0 program-correctness is out of scope; the policy runs natively in program/.',
          'publishInput costs 20,037,798 gas measured (7 on-chain Honk verifies, 105,600 B calldata).',
        ]}
      />
    </section>
  </>
)
