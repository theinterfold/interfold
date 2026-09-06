// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link } from 'react-router-dom'
import { Keyhole, Sigma, EyeSlash } from '@phosphor-icons/react'
import { Cipher, HonestScope, MarkerUnderline, SectionHeader, ThresholdRow } from '@interfold/ckks-editorial'

const PRINCIPLES = [
  {
    icon: Keyhole,
    label: 'Private',
    body: 'You encrypt a cap-normalised salary and prove it is in range — right here, in the browser. Only the ciphertext and three proofs leave your machine.',
  },
  {
    icon: Sigma,
    label: 'Computed, not revealed',
    body: 'The network computes the sum and the sum of squares on ciphertext: one ct×ct product under the level-0 ceremony key, packed into ONE output ciphertext.',
  },
  {
    icon: EyeSlash,
    label: 'Only the aggregates open',
    body: 'The committee threshold-decrypts slot 0 (Σx) and slot 1 (Σx²) — nothing else. Mean, variance and std-dev follow; the server never sees a salary.',
  },
]

const STEPS = [
  {
    num: '01',
    title: 'DKG + relin ceremony',
    body: 'The committee runs a distributed key generation for a CKKS key (ParamSet 3: N=512, three 36-bit moduli, Δ=2⁴⁰) and a ceremony producing a joint relinearisation key so it can multiply ciphertexts.',
  },
  {
    num: '02',
    title: 'Encrypt + prove in your browser',
    body: 'Your salary is normalised by the public cap, encoded replicated across all 256 slots and encrypted under the joint public key (WASM). Three UltraHonk proofs are generated locally.',
  },
  {
    num: '03',
    title: 'On-chain gate',
    body: 'CkksSalaryE3Program verifies all three proofs, binds them by their commitments, dedupes on the randomness commitment and only then records the ciphertext.',
  },
  {
    num: '04',
    title: 'Statistics + one opening',
    body: 'The coordinator computes Σx (slot 0) and the relinearised Σx² (slot 1) in ONE output ciphertext. t+1 nodes open just that; mean / variance / std-dev are derived from (n, Σx, Σx²).',
  },
]

const Home = () => (
  <>
    <section className="pad-section">
      <div className="split">
        <div className="col" style={{ gap: 36 }}>
          <div className="col" style={{ gap: 18 }}>
            <div className="mono muted">Private salary survey on a threshold-CKKS committee</div>
            <h1 className="display headline">
              The network computes <MarkerUnderline>Σx, Σx²</MarkerUnderline>.
              <br />
              Nobody reads a salary.
            </h1>
            <p className="lede" style={{ maxWidth: 'none' }}>
              A packed statistics policy over encrypted salaries, evaluated by a five-node committee that runs no app logic: one DKG, one
              relinearisation ceremony, one threshold decryption of a single two-slot aggregate.
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
            <Link to="/rounds" className="btn lg">
              Go to rounds →
            </Link>
          </div>
        </div>

        <div className="split-visual">
          <div className="card col" style={{ gap: 18 }}>
            <div className="between">
              <span className="mono muted">Your salary, encrypted</span>
              <span className="tag">ParamSet 3 · N=512</span>
            </div>
            <Cipher seed={3} length={128} blockSize={4} highlight />
            <div className="hr-soft" />
            <div className="between">
              <span className="mono muted">Packed output · slot 0 Σx, slot 1 Σx²</span>
              <span className="tag">1 ct×ct · relin</span>
            </div>
            <Cipher seed={512} length={96} blockSize={4} />
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
      <SectionHeader num="02" kicker="PROOFS" title="What each proof leg establishes" meta="Greco ×2 + validity" />
      <table className="ledger" style={{ marginTop: 24 }}>
        <thead>
          <tr>
            <th>leg</th>
            <th>circuit</th>
            <th>statement</th>
            <th>public outputs</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td className="mono">ct0</td>
            <td className="mono">user_data_encryption_ckks_ct0_ps3</td>
            <td>ct₀ = pk₀·u + e₀ + m (+ r₁·q + r₂·Φ) per RNS limb, with u, e₀, m in their CKKS bounds (Greco).</td>
            <td>
              pk₀ᶜ, ct₀ᶜ, <b>m_commitment</b>, <b>u_commitment</b>
            </td>
          </tr>
          <tr>
            <td className="mono">ct1</td>
            <td className="mono">user_data_encryption_ckks_ct1_ps3</td>
            <td>
              ct₁ = pk₁·u + e₁ (+ p₁·q + p₂·Φ) with the <i>same</i> u.
            </td>
            <td>
              pk₁ᶜ, ct₁ᶜ, <b>u_commitment</b>
            </td>
          </tr>
          <tr>
            <td className="mono">app</td>
            <td className="mono">ckks_salary_validity_ps3</td>
            <td>
              The <i>same</i> m is the slot-replicated encoding of salary/cap with 0 ≤ salary ≤ cap (head |m₀·cap − Δ·salary| ≤ 2·cap, tail |mₖ| ≤ 64 —
              which also enforces replication).
            </td>
            <td>
              cap, <b>m_commitment</b>
            </td>
          </tr>
        </tbody>
      </table>
      <p className="muted" style={{ marginTop: 16 }}>
        The contract requires ct0.u == ct1.u and ct0.m == app.m, so one encryption is proven well-formed AND in-range. Duplicates are rejected on
        (e3Id, u_commitment).
      </p>
    </section>

    <section className="pad-section">
      <HonestScope
        items={[
          'Every individual ciphertext stays sealed: only the evaluated output is ever opened.',
          'The committee\u2019s secret key exists only as Shamir shares; t+1 decryption shares are combined per opening.',
          'The smudging noise in the opened aggregates is truncated to 2 decimals so the on-chain bytes are reproducible.',
          'Insecure demo parameters (N=512) — a sizing input, not a security claim.',
        ]}
      />
    </section>
  </>
)

export default Home
