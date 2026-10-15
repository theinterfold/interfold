<div align="center">
  <picture>
    <img src="./docs/public/interfold-meta.jpg" alt="The Interfold" width="100%">
  </picture>

[![Docs][docs-badge]][docs] [![Github Actions][gha-badge]][gha] [![Hardhat][hardhat-badge]][hardhat]
[![License: LGPL v3][license-badge]][license]

</div>

# The Interfold

> **Note:** The Interfold was previously known as **Interfold**.  
> Many repositories, packages, and CLI tools still use the `interfold` name while the project
> transitions.

This is the monorepo for **The Interfold**, an open-source protocol for confidential coordination.

The Interfold leverages a combination of Fully Homomorphic Encryption (FHE), Zero-Knowledge Proofs
(ZKPs), and Multi-Party Computation (MPC) to enable Encrypted Execution Environments (E3), with
integrity and privacy guarantees rooted in cryptography and economics, rather than hardware and
attestations.

## Documentation

Full documentation is available at: https://docs.theinterfold.com

## Quick Start

Follow instructions in the [quick start][quick-start] section of the documentation.

See the [CRISP example][crisp] for a fully functioning example application.

## Getting Help

Join the community [Telegram group][telegram].

## Contributing

See [CONTRIBUTING.md][contributing].

Maintainers use [RELEASING.md](RELEASING.md) for shared-workspace releases and
[domain documentation](docs/architecture/AGENTS.md) for cross-layer contracts and known limits.

## Development

This section covers the essential commands for setting up and working with the Interfold codebase
locally.

```bash
# Install dependencies
pnpm i

# Build the project
pnpm build

# Clean build artifacts
pnpm clean
```

### Testing

Use the root pnpm scripts for full/layer suites: their setup builds binaries and fixtures that raw
tool commands can omit. Focused `cargo test -p` and `cargo check -p` are also supported once the
affected suite's prerequisites are prepared.

#### Test Scripts

The monorepo provides several test scripts for different components:

- **`pnpm test`** - Runs all tests across the entire monorepo:
  - EVM/Smart contract tests (`evm:test`)
  - Rust crate tests (`rust:test`)
  - SDK tests (`sdk:test`)
  - Noir circuit tests (`noir:test`)

- **`pnpm rust:test`** - Runs all Rust crate tests in the `crates/` directory. This script runs
  tests for all crates in the workspace, not just ciphernode-related crates.

- **`pnpm evm:test`** - Runs tests for the EVM smart contracts in `packages/interfold-contracts`.

- **`pnpm sdk:test`** - Runs tests for the TypeScript SDK in `packages/interfold-sdk`.

- **`pnpm noir:test`** - Runs tests for Noir circuits in the `circuits/` directory using
  `nargo test`. Requires the [Noir toolchain](https://noir-lang.org/docs/installation) (`nargo`) and
  [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (`bb`) to
  be installed and on your `PATH`.

- **`pnpm test:integration`** - Runs integration tests from `tests/integration/`. These tests may
  require prebuilt binaries and can be run with `--no-prebuild` if binaries are already available.
  Pre-built circuit artifacts for the configured BFV preset must be present in the `circuits/`
  artifacts directory.

#### Running Individual Test Suites

Fast `pnpm sdk:test` mocks the prover API boundary; it does not verify a real cryptographic proof.
The separate `pnpm sdk:test:proofs` suite prepares a proof and rejects tampered proof/public inputs;
`pnpm sdk:test:proofs:prepared` reuses an already prepared build/circuit set.

Before `pnpm rust:test:proofs` or the full `pnpm test`, prepare the matching insecure-minimum inner
and recursive circuits with
`pnpm build:circuits --preset insecure-512 --committee minimum --skip-if-built`. Proof substitution
tests additionally need pinned nargo on PATH. Before `pnpm rust:test:slashing`, run `pnpm evm:build`
and provide Anvil. The named proof/slashing suites fail when prerequisites are missing; ordinary
Rust runs leave these expensive tests ignored. A successful fast suite is not evidence that they
ran. See [artifact requirements](docs/architecture/circuit-artifacts.md).

```bash
# Run only Rust crate tests
pnpm rust:test

# Run only EVM/smart contract tests
pnpm evm:test

# Run only SDK tests
pnpm sdk:test

# Run only Noir circuit tests
pnpm noir:test

# Run only integration tests
pnpm test:integration

# Run integration tests without prebuild step (if binaries already exist)
pnpm test:integration --no-prebuild
```

### Contributors

<!-- readme: contributors -start -->
<table>
	<tbody>
		<tr>
			<td align="center">
				<a href="https://github.com/hmzakhalid">
					<img src="https://avatars.githubusercontent.com/u/36852564?v=4" width="100;" alt="hmzakhalid"/>
					<br />
					<sub><b>Hamza Khalid</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/ryardley">
					<img src="https://avatars.githubusercontent.com/u/1256409?v=4" width="100;" alt="ryardley"/>
					<br />
					<sub><b>гλ</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/ctrlc03">
					<img src="https://avatars.githubusercontent.com/u/93448202?v=4" width="100;" alt="ctrlc03"/>
					<br />
					<sub><b>ctrlc03</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/auryn-macmillan">
					<img src="https://avatars.githubusercontent.com/u/8453294?v=4" width="100;" alt="auryn-macmillan"/>
					<br />
					<sub><b>Auryn Macmillan</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/cedoor">
					<img src="https://avatars.githubusercontent.com/u/11427903?v=4" width="100;" alt="cedoor"/>
					<br />
					<sub><b>Cedoor</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/0xjei">
					<img src="https://avatars.githubusercontent.com/u/20580910?v=4" width="100;" alt="0xjei"/>
					<br />
					<sub><b>Giacomo</b></sub>
				</a>
			</td>
		</tr>
		<tr>
			<td align="center">
				<a href="https://github.com/samepant">
					<img src="https://avatars.githubusercontent.com/u/6718506?v=4" width="100;" alt="samepant"/>
					<br />
					<sub><b>samepant</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/cristovaoth">
					<img src="https://avatars.githubusercontent.com/u/12870300?v=4" width="100;" alt="cristovaoth"/>
					<br />
					<sub><b>Cristóvão</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/nginnever">
					<img src="https://avatars.githubusercontent.com/u/7103153?v=4" width="100;" alt="nginnever"/>
					<br />
					<sub><b>Nathan Ginnever</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/Toby1009">
					<img src="https://avatars.githubusercontent.com/u/69885352?v=4" width="100;" alt="Toby1009"/>
					<br />
					<sub><b>Malingshu</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/eccogrinder">
					<img src="https://avatars.githubusercontent.com/u/100447090?v=4" width="100;" alt="eccogrinder"/>
					<br />
					<sub><b>marv</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/0xkeygen">
					<img src="https://avatars.githubusercontent.com/u/211014662?v=4" width="100;" alt="0xkeygen"/>
					<br />
					<sub><b>Bryant</b></sub>
				</a>
			</td>
		</tr>
		<tr>
			<td align="center">
				<a href="https://github.com/zahrajavar">
					<img src="https://avatars.githubusercontent.com/u/81833289?v=4" width="100;" alt="zahrajavar"/>
					<br />
					<sub><b>Zara</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/ozgurarmanc">
					<img src="https://avatars.githubusercontent.com/u/94117770?v=4" width="100;" alt="ozgurarmanc"/>
					<br />
					<sub><b>Armanc</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/neogiacomo">
					<img src="https://avatars.githubusercontent.com/u/20580910?v=4" width="100;" alt="neogiacomo"/>
					<br />
					<sub><b>Giacomo Corrias</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/Subhasish-Behera">
					<img src="https://avatars.githubusercontent.com/u/92573882?v=4" width="100;" alt="Subhasish-Behera"/>
					<br />
					<sub><b>SUBHASISH BEHERA</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/leonschh">
					<img src="https://avatars.githubusercontent.com/u/312806154?v=4" width="100;" alt="leonschh"/>
					<br />
					<sub><b>Ethan</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/jfschwarz">
					<img src="https://avatars.githubusercontent.com/u/524089?v=4" width="100;" alt="jfschwarz"/>
					<br />
					<sub><b>Jan-Felix</b></sub>
				</a>
			</td>
		</tr>
		<tr>
			<td align="center">
				<a href="https://github.com/callumweb3">
					<img src="https://avatars.githubusercontent.com/u/314530502?v=4" width="100;" alt="callumweb3"/>
					<br />
					<sub><b>callumweb3</b></sub>
				</a>
			</td>
			<td align="center">
				<a href="https://github.com/CryptAm">
					<img src="https://avatars.githubusercontent.com/u/102138190?v=4" width="100;" alt="CryptAm"/>
					<br />
					<sub><b>cryptam</b></sub>
				</a>
			</td>
		</tr>
	</tbody>
</table>
<!-- readme: contributors -end -->

## Minimum Rust version

This workspace's minimum supported rustc version is 1.91.1.

## Architecture

The Interfold employs a modular architecture involving numerous actors and participants. The
sequence diagram below offers a high-level overview of the protocol, but necessarily omits most
detail.

```mermaid
sequenceDiagram
    participant Users
    participant Interfold
    participant CiphernodeRegistry
    participant RandomnessProvider
    participant E3Program
    participant ComputeProvider
    participant CiphertextVerifier
    participant DecryptionVerifier
    participant Ciphernodes

    Users->>Interfold: request(parameters)
    Interfold->>E3Program: validate(e3ProgramParams)
    Interfold->>ComputeProvider: validate(computeProviderParams)
    ComputeProvider-->>Interfold: decryptionVerifier
    Interfold->>CiphernodeRegistry: requestCommittee(e3Id, legacySeed, threshold)
    CiphernodeRegistry->>RandomnessProvider: requestRandomness(e3Id)
    RandomnessProvider-->>CiphernodeRegistry: requestId
    CiphernodeRegistry-->>Interfold: success
    Interfold-->>Users: e3Id, E3 struct

    Note over RandomnessProvider: Chainlink verifies and stores the VRF response
    CiphernodeRegistry->>RandomnessProvider: getRandomness(requestId)
    RandomnessProvider-->>CiphernodeRegistry: random word and fulfillment context

    Users->>Interfold: activate(e3Id)
    Interfold->>CiphernodeRegistry: committeePublicKey(e3Id)
    CiphernodeRegistry-->>Interfold: publicKey
    Interfold->>Interfold: Set expiration and committeePublicKey
    Interfold-->>Users: success

    Users->>CRISPServer: stage encrypted input + Noir proof
    CRISPServer-->>Users: signed compact commitment
    Users->>E3Program: publishInput(e3Id, commitment)
    E3Program-->>Users: InputCommitted
    CRISPServer->>Avail: submit_data(encryptedInput)
    CRISPServer->>E3Program: finalizeInput(e3Id, VectorX receipt)
    E3Program-->>CRISPServer: InputPublished

    ComputeProvider-->>CRISPServer: aggregateCiphertext + OpenVM proof
    CRISPServer->>E3Program: verify output proof (read only)
    CRISPServer->>Avail: submit_data(aggregateCiphertext)
    CRISPServer->>Interfold: publishCiphertextOutput(e3Id, reference + VectorX receipt)
    Interfold->>E3Program: verifyDataAvailability(contentHash, receipt)
    Interfold->>CiphertextVerifier: verify compute proof
    CiphertextVerifier-->>Interfold: success
    Interfold->>E3Program: verify compute proof
    E3Program-->>Interfold: success
    Interfold->>Interfold: Store ciphertextOutput
    Interfold-->>CRISPServer: success

    Ciphernodes->>Avail: retrieve aggregateCiphertext
    Ciphernodes->>Interfold: publishPlaintextOutput(e3Id, data)
    Interfold->>E3Program: verify(e3Id, data)
    E3Program-->>Interfold: output, success
    Interfold->>DecryptionVerifier: verify plaintext proof
    DecryptionVerifier-->>Interfold: success
    Interfold->>Interfold: Store plaintextOutput
    Interfold-->>Ciphernodes: success
```

## 🚀 Release Process

### Quick Release

[RELEASING.md](RELEASING.md) owns release preparation, qualification, tagging, and publication.
`pnpm bump:versions` formats, stages, commits, and pushes by default; its dry run is read-only.
Tagging is a separate command after the release PR merges and qualifies on main.

### Release Order

Follow the [release branch and tag sequence](RELEASING.md#prepare-a-reviewable-release-branch).
Stable and prerelease publications use different [channels](RELEASING.md#channels-and-recovery);
neither implies protocol compatibility.

### What the Release Workflow Requires

The tag workflow does not repeat the repository CI that qualified the merged `main` commit. It
checks protected history, builds binaries, and requires a complete source-matched circuit matrix
before publication. See
[publication checks and outputs](RELEASING.md#what-publication-checks-and-produces) for containers,
npm, DAppNode, and GitHub assets. Rust workspace crates are not published to crates.io.

## 🏷️ Version Strategy

### Version Format

The Interfold follows [Semantic Versioning](https://semver.org/):

- **Stable**: `v1.0.0` - Production ready
- **Pre-release**: `v1.0.0-beta.1` - Testing/preview versions
  - `-alpha.X` - Early development, may have breaking changes
  - `-beta.X` - Feature complete, testing for bugs
  - `-rc.X` - Release candidate, final testing

### Which Version Should I Use?

#### For Production (Mainnet)

Use stable versions only:

```bash
curl -fsSL https://raw.githubusercontent.com/theinterfold/interfold/main/install | bash   # Latest release
interfold update --version v1.0.0    # Change to a specific stable version
```

#### For Testing (Testnet)

You can use pre-release versions. `install` without `--version` always selects the latest release:

```bash
interfold update --version dev           # Most recently published release, stable or pre-release
interfold update --version v1.0.0-dev.1  # Specific pre-release
```

#### For Development

Build from source:

```bash
git clone https://github.com/theinterfold/interfold.git
cd interfold
cargo build --release
```

## 🌿 Branch and Tag Strategy

### Current Setup

- **`main`** - Latest code. All releases are tagged from here. Using feature flags for experimental
  features, we ensure that code is always stable.
- **`v*.*.*`** - Version tags for releases
- **`stable`** - Always points to the latest stable release

### Installation Sources

```bash
# Latest stable release (recommended for production)
curl -fsSL https://raw.githubusercontent.com/theinterfold/interfold/stable/install | bash

# Latest development version (may be unstable)
curl -fsSL https://raw.githubusercontent.com/theinterfold/interfold/main/install | bash
```

## 📋 Release Checklist

Use the [qualification and release procedure](RELEASING.md#qualify-the-change), not a second
checklist here. After successful publication, verify the packages on
[npm](https://www.npmjs.com/org/interfold), GitHub binaries, and changelog before announcing or
deploying the release.

## 🔧 Script Options

The [release guide's command table](RELEASING.md#prepare-a-reviewable-release-branch) distinguishes
dry-run, file-only, local-commit, and push modes. `--skip-git` is not read-only.

## 🔄 Rollback Procedure

Follow [channels and recovery](RELEASING.md#channels-and-recovery), including the protocol rollback
decision. Deprecating an npm version does not roll back deployed contracts or node state.

## 📊 Version History

Check our [Releases page](https://github.com/theinterfold/interfold/releases) for full version
history and changelogs.

## Security and Liability

This repo is provided WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.

## License

This repo created under the [LGPL-3.0+ license](LICENSE.md).

[gha]: https://github.com/theinterfold/interfold/actions
[gha-badge]: https://github.com/theinterfold/interfold/actions/workflows/ci.yml/badge.svg
[hardhat]: https://hardhat.org/
[hardhat-badge]: https://img.shields.io/badge/Built%20with-Hardhat-FFDB1C.svg
[license]: https://opensource.org/license/lgpl-3-0
[license-badge]: https://img.shields.io/badge/License-LGPLv3.0-blue.svg
[docs]: https://docs.theinterfold.com
[docs-badge]: https://img.shields.io/badge/Documentation-blue.svg
[quick-start]: https://docs.theinterfold.com/build/quick-start
[crisp]: https://docs.theinterfold.com/CRISP/introduction
[telegram]: https://t.me/+raYAZgrwgOw2ODJh
[contributing]: CONTRIBUTING.md
