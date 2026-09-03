// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { Link } from 'react-router-dom'

const Home = () => (
  <div className="page">
    <h1>Private salary survey on threshold CKKS</h1>
    <p className="lead">
      Participants submit their salary <b>encrypted in the browser</b>. A committee of five ciphernodes computes the
      mean and variance homomorphically and threshold-decrypts <b>only the two aggregates</b>. No party — not the
      server, not any single node — ever sees an individual salary.
    </p>

    <section className="card">
      <h3>What happens</h3>
      <ol className="steps">
        <li>
          <b>DKG + relin ceremony.</b> The committee runs a distributed key generation for a CKKS key (ParamSet 3:
          N=512, three 36-bit moduli, Δ=2⁴⁰) and a two-round ceremony producing a joint relinearization key so it can
          multiply ciphertexts.
        </li>
        <li>
          <b>Encrypt + prove in your browser.</b> Your salary is normalized by the public cap, encoded replicated across
          all 256 slots and encrypted under the joint public key (WASM). Three UltraHonk proofs are generated locally.
        </li>
        <li>
          <b>On-chain gate.</b> The <code>CkksSalaryE3Program</code> contract verifies all three proofs, binds them by
          their commitments, dedupes on the randomness commitment and only then records the ciphertext.
        </li>
        <li>
          <b>Homomorphic statistics.</b> The coordinator computes Σx (slot 0) and the relinearized Σx² (slot 1) in ONE
          output ciphertext and publishes it.
        </li>
        <li>
          <b>Threshold decryption.</b> t+1 nodes open just that ciphertext; the canonical fixed-point plaintext lands
          on-chain. Mean / variance / stddev are derived from (n, Σx, Σx²).
        </li>
      </ol>
    </section>

    <section className="card">
      <h3>What each proof leg proves</h3>
      <table className="legs">
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
            <td>ct0</td>
            <td>
              <code>user_data_encryption_ckks_ct0_ps3</code>
            </td>
            <td>ct₀ = pk₀·u + e₀ + m (+ r₁·q + r₂·Φ) per RNS limb, with u, e₀, m in their CKKS bounds (Greco).</td>
            <td>
              pk₀ᶜ, ct₀ᶜ, <b>m_commitment</b>, <b>u_commitment</b>
            </td>
          </tr>
          <tr>
            <td>ct1</td>
            <td>
              <code>user_data_encryption_ckks_ct1_ps3</code>
            </td>
            <td>
              ct₁ = pk₁·u + e₁ (+ p₁·q + p₂·Φ) with the <i>same</i> u.
            </td>
            <td>
              pk₁ᶜ, ct₁ᶜ, <b>u_commitment</b>
            </td>
          </tr>
          <tr>
            <td>app</td>
            <td>
              <code>ckks_salary_validity_ps3</code>
            </td>
            <td>
              The <i>same</i> m is the slot-replicated encoding of salary/cap with 0 ≤ salary ≤ cap (head |m₀·cap −
              Δ·salary| ≤ 2·cap, tail |mₖ| ≤ 64 — which also enforces replication).
            </td>
            <td>
              cap, <b>m_commitment</b>
            </td>
          </tr>
        </tbody>
      </table>
      <p className="muted">
        The contract requires ct0.u == ct1.u and ct0.m == app.m, so one encryption is proven well-formed AND in-range.
        Duplicates are rejected on (e3Id, u_commitment).
      </p>
    </section>

    <section className="card">
      <h3>What never decrypts</h3>
      <ul>
        <li>Every individual ciphertext: only the evaluated output is ever opened.</li>
        <li>The committee's secret key: it exists only as Shamir shares; t+1 decryption shares are combined per opening.</li>
        <li>The smudging noise in the opened aggregates is truncated to 2 decimals so the on-chain bytes are reproducible.</li>
      </ul>
    </section>

    <p>
      <Link to="/rounds" className="button">
        Go to rounds →
      </Link>
    </p>
  </div>
)

export default Home
