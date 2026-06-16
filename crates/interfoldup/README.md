# interfoldup

A standalone installer for the Interfold CLI tool.

## Installation

### Quick Install

Use the provided install script to download and install `interfoldup`:

```bash
curl -fsSL https://raw.githubusercontent.com/gnosisguild/interfold/main/install | bash
```

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/gnosisguild/interfold/main/install | bash
```

### Manual Installation

1. Download the appropriate binary for your platform from the
   [releases page](https://github.com/gnosisguild/interfold/releases)
2. Extract the binary and place it in your PATH (e.g., `~/.local/bin` or `/usr/local/bin`)
3. Make sure the binary is executable: `chmod +x interfoldup`

## Usage

### Install the Interfold CLI

```bash
# Install to ~/.local/bin (default)
interfoldup install

# Install to /usr/local/bin (requires sudo)
interfoldup install --system
```

### Update the Interfold CLI

```bash
# Update from ~/.local/bin
interfoldup update

# Update from /usr/local/bin
interfoldup update --system
```

### Uninstall the Interfold CLI

```bash
# Remove from ~/.local/bin
interfoldup uninstall

# Remove from /usr/local/bin
interfoldup uninstall --system
```

### Get Help

```bash
interfoldup --help
interfoldup install --help
```

## Building from Source

To build `interfoldup` from source:

```bash
cd interfoldup
cargo build --locked --release
```

The binary will be available at `target/release/interfoldup`.

## Platform Support

| Platform | Architecture             | Status             |
| -------- | ------------------------ | ------------------ |
| Linux    | x86_64                   | ✅ Native binary   |
| macOS    | Apple Silicon (M1/M2/M3) | ✅ Native binary   |
| macOS    | Intel                    | ✅ Via Rosetta 2\* |

\* Intel Macs automatically run Apple Silicon binaries through Rosetta 2 translation

## Binary Naming Convention

The installer expects GitHub releases to contain assets with this naming pattern:

**For Interfold CLI:**

- `interfold-linux-x86_64.tar.gz`
- `interfold-macos-aarch64.tar.gz`

**For interfoldup itself:**

- `interfoldup-linux-x86_64.tar.gz`
- `interfoldup-macos-aarch64.tar.gz`

Each tarball contains the binary at the root level.

## Dependencies

- `curl` or `wget` (for the install script)
- `tar` (for extracting archives)
- Internet connection (for downloading releases)
