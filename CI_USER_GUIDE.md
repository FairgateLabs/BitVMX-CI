# BitVMX CI — User Guide

This guide covers everything you need to know to work with the BitVMX CI system: what each workflow does, how to trigger them, and how to customize their behavior.

---

## Overview

The CI system is built around three workflow files:

| Workflow | File | Trigger |
|---|---|---|
| **CI Template** | `ci_local_template.yml` | Called by other workflows (not triggered directly) |
| **Nightly Build** | `ci_nightly_build.yml` | Every day at 03:00 UTC / Manual |
| **Weekly Build** | `ci_weekly_build.yml` | Every Thursday at 00:00 UTC / Manual |

The Nightly and Weekly workflows are consumers of the Template — they pass different input combinations to control what gets built and tested.

---

## Workflow: CI Template (`ci_local_template.yml`)

This is the core workflow that contains all the build, test, and reporting logic. It is designed to be called via `workflow_call` from other workflows, but it also supports `workflow_dispatch` for manual one-off runs.

### What it does (step by step)

1. **Disk cleanup** — Removes large pre-installed tools (`dotnet`, Android SDK, GHC, Boost) to free space before the build.
2. **SSH + Git authentication** — Configures SSH agent and Git token auth for accessing private repositories.
3. **Checkout workspace** — Clones `rust-bitvmx-workspace` at the branch extracted from the PR title (format: `[branch-name] PR title`). Falls back to `main` if no branch prefix is found.
4. **Override all submodules branch** *(optional)* — If `submodules_branch` is provided, every submodule in the workspace that has that branch available is re-cloned at that branch.
5. **Checkout current repository** *(optional)* — Unless `use_workspace_submodule: true`, the submodule being tested is re-cloned at the PR branch.
6. **Override submodules from PR description** — Reads the PR body for `Override: <repo>:<branch>` lines and re-clones those specific submodules. See [PR-level overrides](#pr-level-submodule-overrides) below.
7. **Reorganize workspace** — Flattens the workspace structure so all submodules are siblings at the runner root.
8. **Install Rust toolchain** — Installs Rust `1.86.0` with `llvm-tools-preview`.
9. **Install cargo-llvm-cov** *(if coverage enabled)* — Installs the coverage tool.
10. **Lint with rustfmt** — Runs `cargo fmt --all -- --check`. Failures are reported but do not fail the build.
11. **Lint with Clippy** *(optional)* — Runs `cargo clippy --all-targets --all-features`. Failures are reported but do not fail the build.
12. **Caching** — Caches the Rust toolchain, Cargo registry, and the submodule's `target/` directory to speed up subsequent runs.
13. **Docker setup** *(optional)* — Builds a Docker image and runs `docker-compose` if `docker_required` is `true`.
14. **Build CPU emulator** *(optional)* — Runs `scripts/build-emulator.sh` inside the submodule.
15. **Build gnova binary** *(optional)* — Builds the `gnova` binary from `rust-bitvmx-gc`.
16. **Run tests** — Runs `cargo test` (or `cargo llvm-cov` if coverage is enabled). Supports optional Cargo features and single-threaded mode.
17. **Run integration tests** *(optional)* — Runs a list of `#[ignore]`d tests by name, each with `--include-ignored --test-threads=1`.
18. **Post coverage comment** — On pull requests, posts (or updates) a coverage report comment with line, function, and branch coverage percentages.
19. **Slack notification** — Sends a pass/fail notification to Slack at the end of every run.

---

### Inputs reference

#### Required inputs

| Input | Type | Description |
|---|---|---|
| `repo` | string | Full `org/repo` path of the workspace repository (e.g. `FairgateLabs/rust-bitvmx-workspace`) |
| `submodule_path` | string | Directory name of the submodule to test (e.g. `rust-bitvmx-client`) |
| `cargo_lock_path` | string | Relative path to the `Cargo.lock` file (used for cache keys) |
| `target_path` | string | Relative path to the `target/` directory (used for caching) |

#### Optional inputs

| Input | Type | Default | Description |
|---|---|---|---|
| `clippy` | boolean | `false` | Run `cargo clippy` linting |
| `build_cpu` | boolean | `false` | Build the BitVMX-CPU emulator via `scripts/build-emulator.sh` |
| `build_gnova` | boolean | `false` | Build the `gnova` binary from `rust-bitvmx-gc` |
| `docker_required` | boolean | `false` | Build Docker image and run docker-compose |
| `dockerfile_path` | string | — | Path to the `Dockerfile` (relative to the submodule root) |
| `docker_compose_path` | string | — | Path to the `docker-compose.yml` (relative to the submodule root) |
| `cargo_features` | string | — | Space or comma-separated Cargo features to enable during tests |
| `single_thread_tests` | boolean | `false` | Run tests with `--test-threads=1` |
| `measure_coverage` | boolean | `true` | Measure code coverage with `cargo-llvm-cov`. Set to `false` to skip |
| `coverage_exclude` | string | — | Comma or space-separated regex patterns to exclude paths from coverage (e.g. `tests/,benches/`) |
| `use_workspace_submodule` | boolean | `false` | Use the submodule as pinned in the workspace instead of checking out the PR branch |
| `submodules_branch` | string | `''` | Override **all** workspace submodules to this branch (e.g. `dev`). Submodules without that branch are left as pinned |
| `integration_tests` | string | `''` | Space-separated list of `#[ignore]`d test names to run as integration tests (e.g. `test_full test_all`) |

#### Required secrets

| Secret | Description |
|---|---|
| `REPO_ACCESS_TOKEN` | GitHub token with read access to all involved repositories |
| `SSH_PRIVATE_KEY` | SSH private key for Git submodule access |

#### Optional secrets

| Secret | Description |
|---|---|
| `SLACK_WEBHOOK_URL` | Incoming webhook URL for Slack build notifications |

---

## Workflow: Nightly Build (`ci_nightly_build.yml`)

Runs every day at **03:00 UTC** (midnight Argentina time). Can also be triggered manually from the Actions tab.

### What it builds

Currently configured for a single matrix entry:

| Submodule | Clippy | CPU Build | gnova Build | Docker | Integration Tests |
|---|---|---|---|---|---|
| `rust-bitvmx-client` | Yes | Yes | Yes | Yes | `test_full`, `test_all` |

### Behavior

- Uses the submodule **as pinned in the workspace** (`use_workspace_submodule: true`).
- Overrides **all submodules** to the `dev` branch (`submodules_branch: 'dev'`).
- Runs integration tests (`test_full` and `test_all`) which are normally marked `#[ignore]`.
- Sends a Slack notification on completion.

### Manual trigger

Go to **Actions → Nightly Build → Run workflow** in the GitHub UI.

---

## Workflow: Weekly Build (`ci_weekly_build.yml`)

Runs every **Thursday at 00:00 UTC**. Can also be triggered manually.

### What it builds

| Submodule | Clippy | CPU Build | gnova Build | Docker | Integration Tests |
|---|---|---|---|---|---|
| `rust-bitvmx-client` | Yes | Yes | No | Yes | None |

### Behavior

- Uses the submodule **as pinned in the workspace** (`use_workspace_submodule: true`).
- Overrides **all submodules** to the `dev` branch (`submodules_branch: 'dev'`).
- Does **not** build the gnova binary.
- Does **not** run integration tests.
- Sends a Slack notification on completion.

### Manual trigger

Go to **Actions → Weekly Build → Run workflow** in the GitHub UI.

---

## PR-level Submodule Overrides

When opening or updating a Pull Request, you can override the branch used for any workspace submodule by adding `Override:` lines to the PR body:

```
Override: rust-bitvmx-protocol:my-feature-branch
Override: rust-bitvmx-cpu:experimental
```

**Rules:**
- The format must be exactly `Override: <repo-name>:<branch-name>` (case-insensitive keyword).
- The repo name must match an existing directory in the workspace.
- If the clone fails, the CI job will fail — double-check branch names before pushing.
- Multiple overrides can be listed, one per line.

---

## Workspace Branch Selection (PR Title Convention)

The template determines which **workspace branch** to clone based on the PR title. If the title starts with a branch name in square brackets, that branch is used:

```
[dev] Fix transaction signing logic
```

→ Clones `rust-bitvmx-workspace` at branch `dev`.

If the PR title has no `[...]` prefix, the workspace is cloned from `main`.

---

## Coverage Reports

When `measure_coverage` is enabled (default), the CI:

1. Runs tests via `cargo llvm-cov` and produces a `coverage-summary.json`.
2. Posts a comment on the PR with a table like:

| Metric | Covered / Total | % |
|---|---|---|
| Lines | 1234/1500 | 82.3% |
| Functions | 320/400 | 80.0% |
| Branches | 210/300 | 70.0% |

The comment is updated (not duplicated) on subsequent pushes to the same PR.

**Color legend:**
- Green (>=80%) / Yellow (>=60%) / Red (<60%)

To exclude paths from coverage (e.g. test fixtures, benchmarks):

```yaml
coverage_exclude: 'tests/,benches/,examples/'
```

To disable coverage entirely and run a plain `cargo test`:

```yaml
measure_coverage: false
```

---

## Rust Toolchain

The template pins Rust to version **`1.86.0`** with the `llvm-tools-preview` component. This is managed via `dtolnay/rust-toolchain`.

---

## Caching Strategy

Three layers of caching are used to speed up builds:

| Cache | Key |
|---|---|
| Rust toolchain (`~/.rustup`, `~/.cargo/bin`) | OS + `rust-toolchain` file hash |
| Cargo registry (`~/.cargo/registry`, `~/.cargo/git`) | OS + `Cargo.lock` hash |
| Submodule `target/` directory | OS + submodule name + `Cargo.lock` hash |
| Docker layers (`/tmp/.buildx-cache`) | OS + commit SHA |

---

## Adding a New Submodule to Nightly or Weekly

To add a new submodule to either scheduled workflow, add an entry to the `matrix.include` list in the respective file:

```yaml
matrix:
include:
    - submodule: rust-bitvmx-client        # existing entry
    clippy: true
    build_cpu: true
    ...

    - submodule: rust-bitvmx-my-new-repo   # new entry
    clippy: true
    build_cpu: false
    build_gnova: false
    dockerfile_path: tests/docker/Dockerfile
    docker_compose_path: tests/docker/docker-compose.yml
```

Then reference any matrix variables that have been added in the `with:` block of the `uses:` call.

---

## Required Repository Secrets

The following secrets must be configured in the repository (or organization) for the workflows to function:

| Secret | Where used | Notes |
|---|---|---|
| `REPO_ACCESS_TOKEN` | All workflows | GitHub PAT or App token with `repo` read scope |
| `SSH_PRIVATE_KEY` | All workflows | SSH key registered on GitHub for submodule access |
| `SLACK_WEBHOOK_URL` | All workflows | Optional — Slack Incoming Webhook URL |
