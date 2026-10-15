# e3-fs

Maintain the async VFS adapter shared by physical-file and in-memory tooling.

- Preserve VFS-root-relative path handling. `physical()` roots at the filesystem root; memory tests
  must not accidentally exercise a different path interpretation from physical callers.
- Copying a directory and copying `source/.` have different destination nesting. Keep both forms
  covered, including recursive contents, before replacing the underlying VFS operations.
- File discovery matches the VFS path string, not only its basename; glob changes can alter which
  generated/template files callers rewrite.
- Replacement writes only when content changes. Preserve that property so no-op tooling does not
  needlessly invalidate timestamps or rebuild generated artifacts.

Run `cargo test --locked -p e3-fs`; use the in-memory adapter for deterministic transformation tests
and temporary physical roots when changing filesystem-specific semantics. This adapter is not a
symlink-safe sandbox or a transactional filesystem.
