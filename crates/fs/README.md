# e3-fs

## Purpose

Asynchronous virtual filesystem for project/template tooling. The same read, copy, discovery, and
replacement operations work over physical files or an isolated in-memory filesystem.

## Map

| Location                                                     | Responsibility                                                         |
| ------------------------------------------------------------ | ---------------------------------------------------------------------- |
| [`fs.rs`](src/fs.rs)                                         | Backend constructors and read/write/copy/find/replace implementations. |
| [`traits.rs`](src/traits.rs), [`prelude.rs`](src/prelude.rs) | Async operation interfaces and consumer imports.                       |

Tooling selects a root/backend, then applies the same transformations to memory or physical files.
Discovery and replacement are separate operations, so callers can inspect a file set before
rewriting it. The [initializer](../init/README.md) is the template-copy consumer.

## In-memory transformations

Inside an async context:

```rust
use e3_fs::{prelude::*, Fs};

let fs = Fs::mem();
fs.mkdirp("project").await?;
fs.write_to_file("project/config.txt", "hello").await?;
assert_eq!(fs.read_to_string("project/config.txt").await?, "hello");
```

The fragment assumes an enclosing function returning `anyhow::Result`. The prelude imports the
operation traits (`FileReader`, `FileWriter`, `DirectoryManager`, `FileCopier`, `FileFinder`,
`Replacer`). `Fs::physical_path(root)` selects a physical root; `Fs::physical()` roots at the
filesystem root. `Fs::new` accepts an existing async VFS path.

Paths are VFS-root-relative. `cp(source, destination)` preserves directory nesting, while copying
`source/.` copies its contents into the destination. `find_files(folder, glob)` matches VFS path
strings, not only basenames. `replace_in_place(regex, replacement, path)` writes only when the
content changes.

The [initializer](../init/README.md) uses this boundary for filtered template copies. It is not a
symlink-safe sandbox or a transactional filesystem.

## Tests

Run `cargo test --locked -p e3-fs`. Inline tests in [`fs.rs`](src/fs.rs) cover recursive copying,
glob discovery, reads/writes, and replacement tables using memory storage; no external services are
required. Physical filesystem behavior remains a separate adapter boundary. See
[AGENTS.md](AGENTS.md) for path/copy change guidance.
