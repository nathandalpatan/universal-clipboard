# universal-clipboard — working notes for Claude

## Repo shape
- Rust workspace at the root (`crates/*`): `ucb-core`, `ucb-crypto`, `ucb-discovery`,
  `ucb-clipboard`, `ucb-sync`, `ucb-files`, `ucb-history`, `ucb-daemon` (bin name: `ucb`).
- `apps/ucb-gui/` is a **separate** Tauri cargo workspace (its own `target/`).
- CI: [.github/workflows/ci.yml](.github/workflows/ci.yml) runs on every push/PR —
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  release build, plus a Windows compile-check and a macOS GUI check.
  [.github/workflows/release.yml](.github/workflows/release.yml) runs on `v*` tags.

## Development workflow (act like a developer — never push to `main`)
Work happens on feature branches and lands on `main` through pull requests. The
`/ship` command (`.claude/commands/ship.md`) automates the full loop:

> branch → run the test gates → commit → push → open a PR

Do the same by hand when not using `/ship`:
1. Branch off `main` (`feat/…` or `fix/…`). Never commit new work directly on `main`.
2. Run the gates that CI runs and make them green **before** committing:
   - `cargo test --workspace`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - If `apps/ucb-gui` changed: from `apps/ucb-gui`, `cargo clippy --all-targets -- -D warnings` and `cargo test`.
3. Commit with a why-focused message, ending with the `Co-Authored-By` trailer.
4. `git push -u origin <branch>` then `gh pr create --base main`.
5. Red tests = stop. Do not open a PR on a failing build.

## Notes
- `gh` must be authenticated (`gh auth login`) for PR creation to work.
- The GUI ships build output under `apps/ucb-gui/dist/` (tracked, not gitignored).
