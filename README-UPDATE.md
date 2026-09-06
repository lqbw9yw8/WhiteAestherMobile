# Aether core update: 1.8.0 -> 1.9.0 (draft patch)

Produced without a Rust/Android toolchain or network access, so this has
NOT been compiled. Treat it as a careful draft, not a verified build.

## What to do with this
Copy these into your WhiteAestherMobile fork, overwriting the matching paths:
- native/aether/aether/   (replaces the whole folder)
- native/aether/UPSTREAM.md
- native/rust-toolchain.toml

native/aether/quiche/ and native/android-bridge/ are NOT included here --
untouched, not part of this bump.

## What changed
- All of native/aether/aether/src/*.rs replaced with upstream Aether
  v1.9.0, EXCEPT ffi.rs (still deliberately excluded, per the existing
  comment in lib.rs) and socketprotect.rs (WhiteDNS-only, carried over
  unchanged).
- Reapplied by hand on top of the fresh 1.9.0 files (since these don't
  exist upstream at all):
  - lib.rs: `mod socketprotect;`, the `pub fn set_socket_protector` hook,
    the `pub use error::{..}` re-export, and ~990 lines of the
    embedded/JNI-facing API (EmbeddedConfig, export/import_identity,
    prepare/scan/test/run_embedded, run_gool, the WG-anchor hunting
    helpers).
  - masque_h2.rs, quic.rs, upstream.rs (3 sites), wg_prober.rs (the whole
    ProbeTally diagnostics block): the socketprotect call sites.
- Cargo.toml: version 1.9.0, rust-version 1.91 (upstream raised this --
  native/rust-toolchain.toml bumped to match, or the build fails outright),
  smoltcp 0.12 -> 0.14. crate-type stays ["lib"] (unchanged, intentional).
- Cargo.lock: left as-is. It will need `cargo update`/a fresh build to
  pick up smoltcp 0.14 -- that needs network, which this environment
  doesn't have.

## Highest-risk spot, check this first if the build fails
lib.rs's transplanted block (~990 lines) calls into masque.rs, prober.rs,
wireguard.rs, netstack.rs, account.rs -- all of which ALSO changed between
1.8.0 and 1.9.0 (real changes, not just formatting). Brace-balance and
syntax look fine, but nothing here confirms the transplanted calls still
match those files' current signatures -- only a real compile can. If it
fails, that mismatch is almost certainly where.

## If you have real git history for this repo (not just a ZIP)
Safer than trusting this by-hand version: add CluvexStudio/Aether as a
remote, fetch v1.9.0, and rebase/cherry-pick WhiteDNS's own commits to
native/aether/aether/src/{lib.rs,masque_h2.rs,quic.rs,upstream.rs,
wg_prober.rs} onto it. Git + the compiler will catch exactly what broke,
file by file, instead of relying on a manual reapplication.
