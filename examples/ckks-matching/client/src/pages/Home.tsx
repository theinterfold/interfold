// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link } from 'react-router-dom'
import { Keyhole, Intersect, ShieldCheck } from '@phosphor-icons/react'
import { Cipher, HonestScope, MarkerUnderline, SectionHeader, ThresholdRow } from '@interfold/ckks-editorial'

const PRINCIPLES = [
  {
    icon: Keyhole,
    label: 'Private',
    body: 'Each organisation’s 16-entry profile vector and its cross-term mask are encrypted and proven in this browser. The server, the chain and the committee only ever see ciphertext and proofs.',
  },
  {
    icon: Intersect,
    label: 'Computed, not revealed',
    body: 'The network multiplies the two ENCRYPTED vectors — one ciphertext × ciphertext product under the committee’s level-0 relinearization key. Neither vector is ever opened.',
  },
  {
    icon: ShieldCheck,
    label: 'Only the score opens',
    body: 'The committee threshold-decrypts one ciphertext: coefficient 0 is −⟨a, b⟩, the compatibility score both parties see. Every other coefficient is a cross term hidden by both masks.',
  },
]

const STEPS = [
  {
    num: '01',
    title: 'Register the two parties',
    body: 'The round opener registers [A, B] on the program contract: slot 0 is party A, slot 1 is party B. The slot IS the role — A must submit the forward layout, B the reversed one. Exactly two parties per round; each address submits once, from its own wallet.',
  },
  {
    num: '02',
    title: 'Encrypt vector + mask, prove — in your browser',
    body: 'You cap-normalise your vector to [−1, 1] (fixed point ×2¹⁶) and pick a fresh cross-term mask of 128 integers in [0, 1024). Both are CKKS coefficient-encoded (no slots, no cosine table: coefficient k is exactly round(Δ·v_k), ParamSet 5: N=512, 3 limbs, Δ=2⁴⁰) and encrypted here (WASM); five UltraHonk proofs are generated locally. Vector and mask never leave this page.',
  },
  {
    num: '03',
    title: 'Submit from your wallet',
    body: 'publishInput is sent from your own key: the circuit’s public address must equal msg.sender, its index your registered slot and its role that same slot. The contract verifies all five proofs on-chain (~5 M gas).',
  },
  {
    num: '04',
    title: 'Evaluate + open',
    body: 'Once both parties are in, the program computes forward(a) · reversed(b) homomorphically — ONE ciphertext × ciphertext product relinearized under the committee’s level-0 key, one rescale — and adds both masks. Coefficient 0 of the opened output is −⟨a, b⟩ (the tᴺ ≡ −1 wrap; the app negates). Coefficients 1… are the cross terms a_i·b_j, each hidden by a uniform mask.',
  },
]

export const Home = () => (
  <>
    <section className="pad-section">
      <div className="split">
        <div className="col" style={{ gap: 36 }}>
          <div className="col" style={{ gap: 18 }}>
            <div className="mono muted">Private matching on a threshold-CKKS committee</div>
            <h1 className="display headline">
              Two vectors, one <MarkerUnderline>score</MarkerUnderline>.
              <br />
              Neither is revealed.
            </h1>
            <p className="lede" style={{ maxWidth: 'none' }}>
              Two organisations compute the compatibility ⟨a, b⟩ of their private profile vectors on ciphertext, by a five-node committee that
              runs no app logic: one DKG, one level-0 relinearization ceremony, one threshold decryption of a masked product.
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
              <span className="mono muted">Your profile vector, encrypted</span>
              <span className="tag">ParamSet 5 · N=512</span>
            </div>
            <Cipher seed={5} length={128} blockSize={4} highlight />
            <div className="hr-soft" />
            <div className="between">
              <span className="mono muted">Your cross-term mask, encrypted</span>
              <span className="tag">128 × m ∈ [0, 1024)</span>
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
      <SectionHeader num="02" kicker="PROOFS" title="What the five proofs establish" meta="Greco ×4 + matching" />
      <div className="col" style={{ gap: 16, marginTop: 28 }}>
        <div className="card">
          <b>Well-formed encryptions (Greco, 2 × 2 legs).</b>{' '}
          <span className="muted">
            ct0 = pk0·u + e0 + m and ct1 = pk1·u + e1 per RNS limb for BOTH ciphertexts, with u/e bounded — each ciphertext really encrypts its
            committed message with fresh randomness (u_commitment shared across its two legs).
          </span>
        </div>
        <div className="card">
          <b>Coefficient layout (matching leg).</b>{' '}
          <span className="muted">
            The vector message has round(Δ·V_j/2¹⁶) on coefficient j+1 (role 0, forward) or N−j−1 (role 1, reversed) for 16 entries with |V_j| ≤ 2¹⁶,
            the mask message has Δ·m_j with m_j &lt; 1024 on coefficients 1…128 — and EVERY other coefficient of both is exactly 0 (no hidden
            entries, no out-of-range values that would break the product’s precision).
          </span>
        </div>
        <div className="card">
          <b>Bindings.</b>{' '}
          <span className="muted">
            The message commitments recomputed in the matching leg equal the ones the Greco ct0 legs output; the address is bound to msg.sender and
            the role to the registered slot on-chain. Nobody can submit somebody else’s vector, the wrong layout, or a second vector.
          </span>
        </div>
        <div className="card">
          <b>Why the masks.</b>{' '}
          <span className="muted">
            The product forward(a)·reversed(b) leaks every a_i·b_j on coefficients 1…; each party adds uniform integers on those positions so the
            opened cross terms are useless (demo hiding ratio 2¹⁰).
          </span>
        </div>
      </div>
    </section>

    <section className="pad-section">
      <HonestScope
        items={[
          'Insecure N=512 demo params; 20 smudging bits vs the ~78 the calculator requires at λ=50.',
          'Cross-term mask hiding ratio is 2¹⁰ (DEMO), not statistical.',
          'The published plaintext bytes are not bound to the C7 proof’s u_global (decode gap).',
          'RISC0 program-correctness is out of scope; the policy runs natively in program/.',
        ]}
      />
    </section>
  </>
)
