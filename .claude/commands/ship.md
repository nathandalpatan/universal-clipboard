---
description: Branch → test → commit → push → open a PR, like a developer would
---

You are shipping the current work as a proper pull request. Act like a careful
developer: never push straight to `main`, and never open a PR if the tests are
red. Work through these steps in order and stop early (reporting why) if any
gate fails.

Optional argument (`$ARGUMENTS`): a short description of the change / desired
branch topic. If empty, infer it from the diff.

## 1. Assess the working tree
- Run `git status` and `git branch --show-current`.
- If there are no changes to ship (clean tree, nothing ahead of `origin/main`),
  say so and stop.

## 2. Get onto a feature branch
- If the current branch is `main`, create and switch to a new branch named
  `feat/<slug>` (or `fix/<slug>`), where `<slug>` is a kebab-case summary of the
  change (from `$ARGUMENTS` or the diff). Never commit new work onto `main`.
- If already on a non-`main` feature branch, keep using it.

## 3. Run the test gates (must be green before continuing)
Run the same checks CI runs (see `.github/workflows/ci.yml`). These can be slow —
run them in the background and wait for completion:
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- GUI (only if `apps/ucb-gui` was touched): from `apps/ucb-gui`,
  `cargo clippy --all-targets -- -D warnings` and `cargo test`.

If any gate fails: stop, show the failure, and do NOT commit or push. Offer to
fix it.

## 4. Commit
- Stage the relevant files and commit with a clear message: a concise subject
  line, then a body explaining the *why*. End the message with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## 5. Push
- `git push -u origin <branch>`.

## 6. Open the PR
- Use `gh pr create --base main --head <branch>` with a title and a body that
  includes: a **Summary** of what changed and why, a **Test plan** section
  listing which gates you ran and that they passed, and this footer:
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- If `gh` is not installed or not authenticated, stop and tell the user to run
  `gh auth login` (or `brew install gh` first), then print the exact
  `gh pr create` command so they can finish it themselves.

## 7. Report
- Print the PR URL and a one-line summary of the test results.
