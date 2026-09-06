// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

export const Footer = () => (
  <footer className="footer">
    <span className="mono-sm muted">
      Interfold · threshold CKKS demo · insecure N=512 parameters, 20-bit smudging, 2¹⁰ mask hiding ratio — sizing input, not a security claim.
    </span>
    <span className="links">
      <a href="https://docs.theinterfold.com" target="_blank" rel="noreferrer">
        docs
      </a>
      <a href="https://github.com/theinterfold/interfold" target="_blank" rel="noreferrer">
        source
      </a>
    </span>
  </footer>
)
