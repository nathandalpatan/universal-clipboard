---
description: Branch → test → commit → push → open a PR, like a developer would
---

You are a careful developer delivering a change end to end as a pull request:
if the change isn't written yet, implement it; then branch → test → commit →
push → open a PR. Never push straight to `main`, and never open a PR if the
tests are red. Work through these steps in order and stop early (reporting why)
if any gate fails.

Argument (`$ARGUMENTS`): a plain-English description of what to fix or build
(e.g. "fix the vague rate-limit error message"). It may be empty.

## 1. Decide the mode
- Run `git status` and `git branch --show-current`.
- **If there are already uncommitted changes**, ship those. Use `$ARGUMENTS`
  (or the diff) to name the branch and write the PR.
- **If the tree is clean and `$ARGUMENTS` describes a task**, implement it
  first: explore the relevant crates, make the change, then continue.
- **If the tree is clean and `$ARGUMENTS` is empty**, there's nothing to do —
  say so and stop.

## 2. Get onto a feature branch
- If the current branch is `main`, create and switch to a new branch named
  `feat/<slug>` (or `fix/<slug>`), where `<slug>` is a kebab-case summary of the
  change (from `$ARGUMENTS` or the diff). Never commit new work onto `main`.
- If already on a non-`main` feature branch, keep using it.
- (Do this before or right after editing — just never leave new commits on `main`.)

## 3. Sync with `main` (so the branch isn't stale)
A branch created before a fix landed on `main` will keep failing CI (and can't
merge — `main` requires branches to be up to date) until it pulls `main` in.
Do this *before* running the gates so they test the real merged result:
- `git fetch origin`
- `git merge origin/main --no-edit` (prefer merge over rebase — the branch may
  already be pushed).
- If there are conflicts, resolve them, `git add` the files, and
  `git commit --no-edit`. If a conflict is non-trivial or ambiguous, stop and
  ask rather than guessing.

## 4. Run the test gates (must be green before continuing)
Run the same checks CI runs (see `.github/workflows/ci.yml`). These can be slow —
run them in the background and wait for completion:
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- GUI (only if `apps/ucb-gui` was touched): from `apps/ucb-gui`,
  `cargo clippy --all-targets -- -D warnings` and `cargo test`.

If any gate fails: stop, show the failure, and do NOT commit or push. Offer to
fix it.

## 5. Commit
- Stage the relevant files and commit with a clear message: a concise subject
  line, then a body explaining the *why*. End the message with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## 6. Push
- `git push -u origin <branch>`.

## 7. Open the PR
- Use `gh pr create --base main --head <branch>` with a title and a body that
  includes: a **Summary** of what changed and why, a **Test plan** section
  listing which gates you ran and that they passed, and this footer:
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- If `gh` is not installed or not authenticated, stop and tell the user to run
  `gh auth login` (or `brew install gh` first), then print the exact
  `gh pr create` command so they can finish it themselves.

## 8. Report
- Print the PR URL and a one-line summary of the test results.
