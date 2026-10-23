# e3-init

This crate owns project-template materialization and dependency rewriting, not generated-project
protocol behavior.

- The default template follows the CLI package version; user URLs can select a ref and subpath.
  Preserve parsing of these separately so a template path cannot accidentally become a Git ref.
- Generated Rust dependencies pin the downloaded template commit, while npm versions come from that
  checkout's packages. Do not replace these with the current working tree's versions.
- Copy filters, workspace-member rewrites, and support-script relative paths must agree. Test the
  resulting project shape, not merely whether a string replacement matched.
- Installation clones, copies, installs dependencies, and removes temporary content. Keep cleanup
  limited to owned paths; the current fixed scratch path also means concurrent installs can collide.

Use the [README tests/prerequisites](README.md#tests). Exercise full-install changes in a disposable
destination, not an existing project. Check [template usage](../../templates/default/README.md) for
user-facing changes.
