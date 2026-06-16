# Template

The Interfold Protocol Template provides a complete development environment for building and testing
applications with Fully Homomorphic Encryption (FHE). This template enables local deployment and
interaction with the Interfold protocol without requiring the core contracts to be copied and
avoiding complexities of specific programs (as zk circuits for CRISP).

## Prerequisites

Before getting started, ensure you have installed:

- [Rust](https://rust-lang.org/tools/install/)
- [NodeJS](https://nodejs.org/en/download)
- [RiscZero](https://dev.risczero.com/api/zkvm/install)
- [pnpm](https://pnpm.io)
- [Metamask](https://metamask.io)

As system requirements:

- Linux/POSIX environment
- For Nix users: A Nix flake is included in the generated template

## Quick Start

### (optional) Install RISC Zero Toolchain

Next, install `rzup` for the `cargo-risczero` toolchain.

```sh
# Install rzup
curl -L https://risczero.com/install | bash

# Install RISC Zero toolchain
rzup install cargo-risczero
```

Verify the installation was successful by running:

```sh
cargo risczero --version
```

At this point, you should have all the tools required to develop and deploy an application with
[RISC Zero](https://www.risczero.com).

### Install Metamask

You can add Metamask as an extension to your browser following the official
[documentation](https://metamask.io).

### Install the Interfold CLI

The easiest way to install the Interfold CLI is using our installer script:
`curl -fsSL https://raw.githubusercontent.com/gnosisguild/interfold/main/install | bash`

Or if you prefer wget:
`wget -qO- https://raw.githubusercontent.com/gnosisguild/interfold/main/install | bash`

This script will download and install interfoldup, which is the standalone installer for the
Interfold CLI.

Once you have `interfoldup` installed, you can manage your Interfold CLI installation:

```bash
# Install to ~/.local/bin (default)
interfoldup install

# Install to /usr/local/bin (requires sudo)
interfoldup install --system
```

Running `interfoldup install` will install the latest version of the Interfold CLI.

After installation, verify that the Interfold CLI is working correctly:

`interfold --help`

You should see the help information for the Interfold CLI.

### Create your Project

Generate a new E3 program from the default template:

```bash
interfold init my-first-e3
cd my-first-e3
```

This creates a complete E3 project with:

- **FHE computation logic** (`./program/`)
- **Smart contracts** (`./contracts/`)
- **Client application** (`./client/`)
- **Coordination server** (`./server/`)
- **Configuration** (`interfold.config.yaml`)

### Compile your E3 Program

First, compile your E3 program to build the Risc0 zkvm image:

```bash
interfold program compile
```

This builds the Risc0 zkvm image that will be deployed on the blockchain and used for verification
of the final proof.

If you want to avoid the proof or you have trouble with Risc0 zkvm installation, you can run it in
dev mode (no proof).

```bash
interfold program start --dev true
```

### Start the Development Environment

Launch all services with one command:

```bash
pnpm dev:all
```

This starts:

- Local Ethereum network (Hardhat)
- Deploys all the smart contracts to the local network
- Multiple ciphernodes for FHE processing
- TypeScript coordination server
- FHE program server
- Frontend client application

**Wait for all services to start** (usually 30-60 seconds).

### Access Your Application

1. Open your browser to [http://localhost:3000](http://localhost:3000)
2. Import the local development private key:
   `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` (DO NOT USE IN PRODUCTION)
3. Configure MetaMask for local network development:
   - Network: `http://localhost:8545`
   - Chain ID: `31337`
4. Switch to the network.

### Test the FHE Computation

The default template includes a simple addition program that:

1. **Encrypts** two numbers on the client
2. **Computes** their sum using FHE (without decrypting)
3. **Returns** the encrypted result
4. **Decrypts** and displays the result

Try it:

- Input two numbers in the web interface
- Click "Submit"
- Watch the encrypted computation happen!

### What Just Happened?

You successfully ran a **Fully Homomorphic Encryption** computation where:

- Your inputs were encrypted before leaving the browser
- The computation happened on encrypted data
- The result was computed without exposing your private inputs
- All coordination was handled by the Interfold protocol

## Manual Start

If you prefer to install the Interfold CLI manually, please visit the dedicated section in the
[documentation](https://docs.interfold.gg/installation#manual-installation).

## Next Steps

Now that you have a working E3 program:

1. **Explore the code**: Check out `./program/src/lib.rs` to see the FHE computation
2. **Modify the computation**: Try changing the addition to multiplication
3. **Update the UI**: Customize the client in `./client/src/`
4. **Deploy**: Learn about production deployment

Ready to dive deeper? Continue with our
[Hello World Tutorial](https://docs.interfold.gg/hello-world-tutorial) for a step-by-step breakdown
of building E3 programs from scratch.
