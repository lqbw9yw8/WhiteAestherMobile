# Aether upstream provenance

- Repository: https://github.com/CluvexStudio/Aether
- Revision: (fill in from the v1.9.0 tag page -- a source ZIP download does
  not carry the commit SHA; open the tag on GitHub and copy it from there)
- Version: Aether 1.9.0
- Imported: 2026-09-06
- License: GNU Affero General Public License v3.0; see `LICENSE`.

This tracked snapshot is the Android integration baseline. Android-specific
refactoring must preserve upstream copyright, trademark, and license notices.

## 1.8.0 -> 1.9.0 update notes (this bump)
- `rust-version` raised 1.88 -> 1.91 upstream; `native/rust-toolchain.toml`
  bumped to match. Build will fail on the old pin.
- `smoltcp` raised 0.12 -> 0.14 upstream; reflected in this crate's
  `Cargo.toml`. `Cargo.lock` was NOT regenerated (no network in the
  environment that made this patch) -- run `cargo update` (or just build)
  wherever this is actually compiled.
- `src/ffi.rs` still deliberately excluded, same reason as before.
- Android-only additions carried forward from 1.8.0 and reapplied on top of
  the fresh 1.9.0 source: `socketprotect` module + its call sites in
  `masque_h2.rs`, `quic.rs`, `upstream.rs`, `wg_prober.rs`; the whole
  embedded/JNI-facing API surface in `lib.rs` (EmbeddedConfig, export/import
  identity, prepare/scan/test/run_embedded, the WG-anchor hunting helpers).
- This reapplication was done by text-level transplant, not a compiler- or
  git-verified merge (no rustc/cargo/network available here) -- treat it as
  a draft to build and fix, not a finished patch. See chat for the specific
  files most likely to need a follow-up look.
