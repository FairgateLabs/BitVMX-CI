# Cargo Supply-Chain Policy

This composite action provides a reusable dependency-admission gate for Rust repositories. It scans every tracked `Cargo.lock` before Cargo tooling executes and applies these checks:

1. Reject the compromised releases and attacker-controlled crate names from the August 2026 [`arrayref` incident](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/).
2. Compare every tracked lockfile with the pull request base and reject newly resolved crates.io releases until they meet a minimum age. The shared policy lives in repository-root `cooldown.toml`; the fallback is 14 days.
3. Reject newly resolved crates.io releases that are yanked, deleted, or missing a publication timestamp.
4. Optionally install and run `cargo-deny` and `cargo-vet` using their native project configuration.

Direct and transitive crates.io dependencies are treated identically. Git, path, and alternate-registry dependencies do not have crates.io publication timestamps, so the age check does not apply to them; `cargo-deny` source policy can cover that gap.

## Consumer workflow

Copy [`examples/audit.yml`](examples/audit.yml) into the consuming repository and replace `PINNED_COMMIT_SHA` with an immutable commit from this repository. The checkout must use full history because the action reads the pull request base commit.

The minimum consumer step is:

```yaml
- uses: FairgateLabs/BitVMX-CI/actions/cargo-supply-chain@PINNED_COMMIT_SHA
  with:
    base-ref: ${{ github.event.pull_request.base.sha }}
```

The action requires a tracked `Cargo.lock`. The core checks need no Rust installation. If `cargo-deny` or `cargo-vet` is enabled, the runner must also have Rust and Cargo available.

`base-ref` defaults to `HEAD`. This still scans every current lockfile for incident packages but finds no newly resolved versions, which is useful on scheduled, tag, or post-merge runs. Pull request workflows should always pass the base SHA so the age gate can evaluate lockfile changes.

## Shared age policy: cooldown.toml

Commit [`examples/cooldown.toml`](examples/cooldown.toml) as `cooldown.toml` at the consuming repository's root. The action reads this file directly. It **does not install or run cargo-cooldown**, resolve dependencies, or rewrite lockfiles. Developers can independently use the same file with cargo-cooldown.

```toml
[registry]
global-min-publish-age = "14 days"

[cooldown]
incompatible-publish-age = "deny"
lockfile-baseline = "floor"
```

`registry.global-min-publish-age` must be explicit when the file exists, avoiding reliance on different tool defaults. Durations use `"0"` or an integer followed by `second(s)`, `minute(s)`, `hour(s)`, `day(s)`, `week(s)`, or `month(s)`; a month is exactly 30 days. Sub-day precision is preserved. `registry.min-publish-age`, if present, replaces the global value for crates.io, matching cargo-cooldown. Zero disables only the age waiting period, not metadata or incident checks.

The action supports this subset of [cargo-cooldown configuration](https://github.com/dertin/cargo-cooldown/blob/main/docs/configuration.md):

- `[registry]`: `global-min-publish-age` and optional crates.io `min-publish-age`.
- `[[allow.exact]]`: `crate` and `version`.
- `[[allow.package]]`: `crate` and `min-publish-age`.
- `[cooldown]`: `incompatible-publish-age` (`deny`, `fallback`, `allow`), `lockfile-baseline` (`floor`, `ignore`), and optional `fallback-accept` (`prompt`, `auto`). These values are validated for developer compatibility but **never change CI behavior**. CI always rejects violations and uses the PR base as its lockfile baseline.

Other keys fail closed with an error, including named registry policies, registry skips, clock overrides, legacy cooldown-minute settings, and global allow rules. The age gate remains crates.io-only. The checker reads only the repository-root file, not member files, user configuration, or cargo-cooldown environment overrides. Use the shared root policy for consistent developer and CI age rules.

### Age exceptions

An exact rule bypasses the waiting period for one crate version:

```toml
# Reviewed urgent fix: explain why this version is needed here.
[[allow.exact]]
crate = "example-crate"
version = "1.2.3"
```

A package rule lowers the waiting period for all versions of that crate:

```toml
[[allow.package]]
crate = "example-crate"
min-publish-age = "1 day"
```

Use `"0"` to exempt a package from waiting. Package rules can only reduce the configured age, and exact rules take precedence. Crate names and versions are literal matches, not patterns or semver ranges; duplicate package rules are rejected. Prefer exact exceptions because package rules also affect future releases. Use comments for reasons; custom fields such as `reason` or `expires` are not part of the shared schema.

Exceptions apply only to the matching package, never its transitive dependencies. The checker reports applied age reductions. Incident bans, yanked/deleted releases, missing or invalid publication timestamps, network failures, cargo-deny, and cargo-vet remain enforced independently.

### PR policy enforcement and migration

For every package, the checker evaluates its required age independently under the base and current policy, including exceptions, then enforces the larger duration. This prevents a PR from lowering its own age requirement or authorizing its own exception. Merge an exception-only PR first, then update the dependency in a subsequent PR. Removing or narrowing an exception takes effect immediately.

If `cooldown.toml` is absent, the checker accepts the legacy `[age].minimum-days` in `.cargo-supply-chain.toml`, falling back to 14 days if that setting is also absent. This compatibility applies independently to each revision, so an older base commit remains protected during migration. Having both `cooldown.toml` and `[age]` in the same revision is an error: move the age setting rather than duplicating it. An empty or malformed `cooldown.toml` is an error, not a fallback.

The command-line minimum-age override is for controlled testing and only tightens policy, including for excepted packages. The `minimum_age_days` action output is the effective default age in days (possibly fractional), not the age for every excepted package.

## Optional cargo-deny and cargo-vet configuration

The action reads `.cargo-supply-chain.toml` at the repository root for optional tool integration. Use the `config-path` input to change this file's repository-relative location; it does not change the fixed root `cooldown.toml` location. Start from [`examples/cargo-supply-chain.toml`](examples/cargo-supply-chain.toml):

```toml
schema-version = 1

[cargo-deny]
enabled = false
config = "deny.toml"
manifests = ["Cargo.toml"]
checks = ["advisories", "bans", "licenses", "sources"]

[cargo-vet]
enabled = false
manifests = ["Cargo.toml"]
locked = true
```

Both integrations remain disabled if this optional file is absent. Unknown keys, invalid values, unsafe paths, and missing metadata fail closed.

For pull requests, current and base integration settings are combined:

- An optional layer runs if either version enables it.
- Enabled cargo-deny checks and manifests are combined.
- `cargo-vet --locked` remains enabled if required by either policy.

A policy-only relaxation takes effect on subsequent pull requests. Put the workflow, `cooldown.toml`, and `.cargo-supply-chain.toml` under security-team `CODEOWNERS` review.

## cargo-deny

When enabled, the action installs `cargo-deny` 0.20.2 and runs the selected checks for every configured manifest with `--locked`. The project remains responsible for its native `deny.toml`. Supported checks are `advisories`, `bans`, `licenses`, and `sources`.

This layer is the recommended first opt-in because it can enforce trusted registries and Git sources, known crate bans, acceptable licenses, and RustSec advisories.

## cargo-vet

When enabled, the action installs `cargo-vet` 0.10.0 and checks every configured manifest. `locked = true` is the default so CI cannot update imported audits.

Each consuming project must initialize and commit its own `supply-chain/` directory before enabling this layer. Audits, exemptions, imports, and trust decisions remain project-owned rather than being hidden in this wrapper.

## Local development

Run the dependency-free test suite from this directory. Python 3.11 or newer uses `tomllib`; Python 3.9 and 3.10 can use the compatible `tomli` package.

```bash
cd actions/cargo-supply-chain/scripts
python3 -m unittest discover -p 'test_*.py'
```

To exercise the core checker in a consuming repository:

```bash
python3 path/to/cargo_supply_chain.py check \
  --base-ref origin/main \
  --config .cargo-supply-chain.toml
```

Network or crates.io metadata failures fail closed. The checker fetches only newly resolved crate names from the official sparse index and retries transient failures.

## Release and update policy

Consumers should pin the action to a full commit SHA. This avoids silently executing changed CI code, but it also means incident-denylist updates are not automatic. Configure Dependabot for GitHub Actions or another controlled update process so repositories receive reviewed action updates promptly.
