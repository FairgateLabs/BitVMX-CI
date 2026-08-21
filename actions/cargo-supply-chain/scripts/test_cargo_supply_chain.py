from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cargo_supply_chain import (
    CARGO_DENY_CHECKS,
    CargoDenyPolicy,
    CargoVetPolicy,
    CheckError,
    Package,
    Policy,
    crate_index_path,
    effective_policy,
    incident_packages,
    newly_resolved_packages,
    packages_from_lockfile,
    parse_index,
    parse_policy,
    policy_violation,
    run_cargo_deny,
    run_cargo_vet,
    write_github_outputs,
)

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def lockfile(*packages: tuple[str, str, str | None]) -> bytes:
    entries = ["version = 4"]
    for name, version, source in packages:
        entries.extend(
            ["", "[[package]]", f'name = "{name}"', f'version = "{version}"']
        )
        if source is not None:
            entries.append(f'source = "{source}"')
    return "\n".join(entries).encode()


class ConfigTests(unittest.TestCase):
    def test_empty_config_uses_seven_day_default(self) -> None:
        self.assertEqual(parse_policy(b"", "policy.toml"), Policy())

    def test_all_options_are_parsed(self) -> None:
        policy = parse_policy(
            b"""
schema-version = 1

[age]
minimum-days = 14

[cargo-deny]
enabled = true
config = "policy/deny.toml"
manifests = ["Cargo.toml", "cli/Cargo.toml"]
checks = ["bans", "sources"]

[cargo-vet]
enabled = true
manifests = ["Cargo.toml"]
locked = false
""",
            "policy.toml",
        )

        self.assertEqual(policy.minimum_age_days, 14)
        self.assertEqual(
            policy.cargo_deny,
            CargoDenyPolicy(
                enabled=True,
                config="policy/deny.toml",
                manifests=("Cargo.toml", "cli/Cargo.toml"),
                checks=("bans", "sources"),
            ),
        )
        self.assertEqual(
            policy.cargo_vet,
            CargoVetPolicy(enabled=True, manifests=("Cargo.toml",), locked=False),
        )

    def test_unknown_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(CheckError, "unknown key"):
            parse_policy(b"unexpected = true", "policy.toml")

    def test_invalid_minimum_age_is_rejected(self) -> None:
        with self.assertRaisesRegex(CheckError, "at least 1"):
            parse_policy(b"[age]\nminimum-days = 0", "policy.toml")

    def test_paths_cannot_escape_repository(self) -> None:
        with self.assertRaisesRegex(CheckError, "within the repository"):
            parse_policy(
                b'[cargo-deny]\nconfig = "../deny.toml"',
                "policy.toml",
            )

    def test_pr_policy_cannot_weaken_base_policy(self) -> None:
        base = Policy(
            minimum_age_days=14,
            cargo_deny=CargoDenyPolicy(
                enabled=True,
                checks=("bans", "sources"),
            ),
            cargo_vet=CargoVetPolicy(enabled=True, locked=True),
        )
        current = Policy(
            minimum_age_days=3,
            cargo_deny=CargoDenyPolicy(enabled=False),
            cargo_vet=CargoVetPolicy(enabled=False, locked=False),
        )

        merged = effective_policy(current, base)

        self.assertEqual(merged.minimum_age_days, 14)
        self.assertTrue(merged.cargo_deny.enabled)
        self.assertEqual(merged.cargo_deny.checks, ("bans", "sources"))
        self.assertTrue(merged.cargo_vet.enabled)
        self.assertTrue(merged.cargo_vet.locked)

    def test_stricter_current_policy_applies_immediately(self) -> None:
        current = Policy(
            minimum_age_days=10,
            cargo_deny=CargoDenyPolicy(enabled=True, checks=("bans",)),
        )
        merged = effective_policy(current, Policy())

        self.assertEqual(merged.minimum_age_days, 10)
        self.assertTrue(merged.cargo_deny.enabled)
        self.assertEqual(merged.cargo_deny.checks, ("bans",))


class LockfileTests(unittest.TestCase):
    def test_only_crates_io_packages_are_age_gated(self) -> None:
        contents = lockfile(
            ("registry", "1.2.3", CRATES_IO),
            ("git-package", "2.0.0", "git+https://example.com/repo#abc"),
            ("workspace-package", "3.0.0", None),
        )

        self.assertEqual(
            packages_from_lockfile(contents, "Cargo.lock"),
            {Package("registry", "1.2.3")},
        )

    def test_new_direct_and_transitive_versions_in_every_lockfile_are_detected(
        self,
    ) -> None:
        base = {
            "Cargo.lock": lockfile(("root", "1.0.0", CRATES_IO)),
            "cli/Cargo.lock": lockfile(("cli", "1.0.0", CRATES_IO)),
        }
        current = {
            "Cargo.lock": lockfile(("root", "1.1.0", CRATES_IO)),
            "cli/Cargo.lock": lockfile(
                ("cli", "1.0.0", CRATES_IO),
                ("transitive", "2.0.0", CRATES_IO),
            ),
        }

        self.assertEqual(
            newly_resolved_packages(current, base),
            {
                Package("root", "1.1.0"): {"Cargo.lock"},
                Package("transitive", "2.0.0"): {"cli/Cargo.lock"},
            },
        )

    def test_arrayref_incident_packages_are_rejected_from_any_lockfile(self) -> None:
        current = {
            "Cargo.lock": lockfile(("arrayref", "0.3.10", CRATES_IO)),
            "guest/Cargo.lock": lockfile(
                ("proc-macro1", "9.9.9", "git+https://example.com/repo#abc")
            ),
        }

        self.assertEqual(
            incident_packages(current),
            {
                Package("arrayref", "0.3.10"): {"Cargo.lock"},
                Package("proc-macro1", "9.9.9"): {"guest/Cargo.lock"},
            },
        )


class IndexTests(unittest.TestCase):
    def test_index_paths_follow_cargo_layout(self) -> None:
        self.assertEqual(crate_index_path("a"), "1/a")
        self.assertEqual(crate_index_path("ab"), "2/ab")
        self.assertEqual(crate_index_path("AbC"), "3/a/abc")
        self.assertEqual(crate_index_path("Serde"), "se/rd/serde")

    def test_index_records_are_keyed_by_version(self) -> None:
        contents = b"\n".join(
            [
                b'{"name":"demo","vers":"1.0.0","yanked":false}',
                b'{"name":"demo","vers":"1.1.0","yanked":true}',
            ]
        )
        self.assertEqual(set(parse_index(contents, "demo")), {"1.0.0", "1.1.0"})


class AgePolicyTests(unittest.TestCase):
    NOW = datetime(2026, 8, 21, 12, tzinfo=timezone.utc)
    MINIMUM_AGE = timedelta(days=7)
    PACKAGE = Package("demo", "1.2.3")

    def test_exactly_seven_days_old_is_allowed(self) -> None:
        record = {"pubtime": "2026-08-14T12:00:00Z", "yanked": False}
        self.assertIsNone(
            policy_violation(self.PACKAGE, record, self.NOW, self.MINIMUM_AGE)
        )

    def test_recent_release_is_rejected(self) -> None:
        record = {"pubtime": "2026-08-15T12:00:00Z", "yanked": False}
        violation = policy_violation(
            self.PACKAGE, record, self.NOW, self.MINIMUM_AGE
        )
        self.assertIn("not eligible until", violation or "")

    def test_yanked_release_is_rejected(self) -> None:
        record = {"pubtime": "2020-01-01T00:00:00Z", "yanked": True}
        self.assertEqual(
            policy_violation(self.PACKAGE, record, self.NOW, self.MINIMUM_AGE),
            "is yanked on crates.io",
        )

    def test_deleted_release_is_rejected(self) -> None:
        self.assertIn(
            "missing from the crates.io index",
            policy_violation(self.PACKAGE, None, self.NOW, self.MINIMUM_AGE) or "",
        )

    def test_missing_publication_time_is_rejected(self) -> None:
        with self.assertRaisesRegex(CheckError, "no publication time"):
            policy_violation(
                self.PACKAGE,
                {"yanked": False},
                self.NOW,
                self.MINIMUM_AGE,
            )


class OptionalToolTests(unittest.TestCase):
    def test_cargo_deny_uses_argument_list_for_every_manifest(self) -> None:
        policy = Policy(
            cargo_deny=CargoDenyPolicy(
                enabled=True,
                config="deny.toml",
                manifests=("Cargo.toml", "cli/Cargo.toml"),
                checks=CARGO_DENY_CHECKS,
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cli").mkdir()
            (root / "Cargo.toml").touch()
            (root / "cli/Cargo.toml").touch()
            previous = Path.cwd()
            os.chdir(root)
            try:
                with patch("cargo_supply_chain.subprocess.run") as run:
                    run_cargo_deny(policy)
            finally:
                os.chdir(previous)

        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                "cargo",
                "deny",
                "--manifest-path",
                "Cargo.toml",
                "--config",
                "deny.toml",
                "--locked",
                "check",
                *CARGO_DENY_CHECKS,
            ],
        )

    def test_cargo_vet_is_locked_by_default(self) -> None:
        policy = Policy(cargo_vet=CargoVetPolicy(enabled=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").touch()
            previous = Path.cwd()
            os.chdir(root)
            try:
                with patch("cargo_supply_chain.subprocess.run") as run:
                    run_cargo_vet(policy)
            finally:
                os.chdir(previous)

        run.assert_called_once_with(
            ["cargo", "vet", "--manifest-path", "Cargo.toml", "--locked"],
            check=True,
        )

    def test_github_outputs_expose_effective_policy(self) -> None:
        policy = Policy(
            minimum_age_days=9,
            cargo_deny=CargoDenyPolicy(enabled=True),
            cargo_vet=CargoVetPolicy(enabled=False),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            write_github_outputs(str(output), policy)
            self.assertEqual(
                output.read_text(),
                "minimum_age_days=9\n"
                "cargo_deny_enabled=true\n"
                "cargo_vet_enabled=false\n",
            )


if __name__ == "__main__":
    unittest.main()
