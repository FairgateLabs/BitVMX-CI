# Cargo Supply-Chain Policy

This composite action provides a reusable dependency-admission gate for Rust repositories. It scans every tracked `Cargo.lock` before Cargo tooling executes and applies these checks:

1. Reject the compromised releases and attacker-controlled crate names from the August 2026 [`arrayref` incident](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/).
2. Compare every tracked lockfile with the pull request base and reject newly resolved crates.io releases until they meet a minimum age. The default is seven days.
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

## Optional configuration

The action looks for `.cargo-supply-chain.toml` at the repository root. The file is optional: when it is absent, the seven-day age gate and the incident denylist remain active while `cargo-deny` and `cargo-vet` remain disabled.

Use the `config-path` action input to choose another repository-relative location. Start from [`examples/cargo-supply-chain.toml`](examples/cargo-supply-chain.toml):

```toml
schema-version = 1

[age]
minimum-days = 7

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

Unknown keys, invalid values, unsafe paths, and missing metadata fail closed. The precedence is built-in defaults, then the optional TOML. The script also accepts a command-line minimum-age override for controlled testing, but it can only make the effective policy stricter.

For pull requests, current and base policies are combined so that a PR cannot weaken its own checks:

- The larger minimum age wins.
- An optional layer runs if either version of the policy enables it.
- Enabled `cargo-deny` checks and manifests are combined.
- `cargo-vet --locked` remains enabled if required by either policy.

A policy-only relaxation can therefore be reviewed and merged, but takes effect only on subsequent pull requests. Put the workflow and policy file under security-team `CODEOWNERS` review.

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
