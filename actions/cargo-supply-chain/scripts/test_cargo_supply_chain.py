from __future__ import annotations

import os
import io
import subprocess
import sys
from contextlib import redirect_stdout, redirect_stderr
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cargo_supply_chain import (
    CARGO_DENY_CHECKS,
    AgePolicy,
    check_package_ages,
    load_policy,
    main,
    parse_cooldown,
    parse_duration,
    resolve_policy,
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

        self.assertEqual(policy.minimum_age, timedelta(days=14))
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
            age_policies=(AgePolicy(timedelta(days=14)),),
            cargo_deny=CargoDenyPolicy(
                enabled=True,
                checks=("bans", "sources"),
            ),
            cargo_vet=CargoVetPolicy(enabled=True, locked=True),
        )
        current = Policy(
            age_policies=(AgePolicy(timedelta(days=3)),),
            cargo_deny=CargoDenyPolicy(enabled=False),
            cargo_vet=CargoVetPolicy(enabled=False, locked=False),
        )

        merged = effective_policy(current, base)

        self.assertEqual(merged.minimum_age, timedelta(days=14))
        self.assertTrue(merged.cargo_deny.enabled)
        self.assertEqual(merged.cargo_deny.checks, ("bans", "sources"))
        self.assertTrue(merged.cargo_vet.enabled)
        self.assertTrue(merged.cargo_vet.locked)

    def test_stricter_current_policy_applies_immediately(self) -> None:
        current = Policy(
            age_policies=(AgePolicy(timedelta(days=10)),),
            cargo_deny=CargoDenyPolicy(enabled=True, checks=("bans",)),
        )
        merged = effective_policy(current, Policy())

        self.assertEqual(merged.minimum_age, timedelta(days=10))
        self.assertTrue(merged.cargo_deny.enabled)
        self.assertEqual(merged.cargo_deny.checks, ("bans",))


class CooldownConfigTests(unittest.TestCase):
    HEADER = '[registry]\nglobal-min-publish-age = "7 days"\n'
    PACKAGE = Package("demo", "1.2.3")

    def parse(self, extra: str = "") -> AgePolicy:
        return parse_cooldown((self.HEADER + extra).encode())

    def test_duration_units_and_zero(self) -> None:
        for unit, seconds in (
            ("second", 1),
            ("minute", 60),
            ("hour", 3600),
            ("day", 86400),
            ("week", 604800),
            ("month", 2592000),
        ):
            for suffix in ("", "s"):
                with self.subTest(unit=unit, suffix=suffix):
                    self.assertEqual(
                        parse_duration(f" 2 {unit}{suffix} ", "test"),
                        timedelta(seconds=2 * seconds),
                    )
        self.assertEqual(parse_duration("0", "test"), timedelta(0))

    def test_invalid_durations_fail_closed(self) -> None:
        for value in (
            True,
            7,
            "",
            "7d",
            "-1 days",
            "1.5 hours",
            "1 day 2 hours",
            "1 DAY",
            "1 year",
            "18446744073709551616 seconds",
            "999999999999999999999999 months",
        ):
            with self.subTest(value=value), self.assertRaises(CheckError):
                parse_duration(value, "test")

    def test_crates_io_override_replaces_global_in_either_direction(self) -> None:
        for days in (0, 3, 14):
            with self.subTest(days=days):
                age = self.parse(f'min-publish-age = "{days} days"\n')
                self.assertEqual(age.minimum_age, timedelta(days=days))

    def test_exact_exception_does_not_exempt_other_versions_or_dependencies(
        self,
    ) -> None:
        age = self.parse('[[allow.exact]]\ncrate = "demo"\nversion = "1.2.3"\n')
        self.assertEqual(age.required_age(self.PACKAGE), timedelta(0))
        self.assertEqual(age.required_age(Package("demo", "1.2.4")), timedelta(days=7))
        self.assertEqual(
            age.required_age(Package("transitive", "1.2.3")), timedelta(days=7)
        )

    def test_package_exceptions_only_reduce_age(self) -> None:
        for duration, expected in (
            ("1 hour", timedelta(hours=1)),
            ("0", timedelta(0)),
            ("14 days", timedelta(days=7)),
        ):
            with self.subTest(duration=duration):
                age = self.parse(
                    f'[[allow.package]]\ncrate = "demo"\nmin-publish-age = "{duration}"\n'
                )
                self.assertEqual(age.required_age(self.PACKAGE), expected)

    def test_exact_exception_takes_precedence_over_package(self) -> None:
        age = self.parse(
            '[[allow.package]]\ncrate = "demo"\nmin-publish-age = "1 day"\n[[allow.exact]]\ncrate = "demo"\nversion = "1.2.3"\n'
        )
        self.assertEqual(age.required_age(self.PACKAGE), timedelta(0))

    def test_resolver_settings_are_validated_but_never_weaken_ci(self) -> None:
        for mode in ("deny", "fallback", "allow"):
            for baseline in ("floor", "ignore"):
                age = self.parse(
                    f'[cooldown]\nincompatible-publish-age = "{mode}"\nlockfile-baseline = "{baseline}"\nfallback-accept = "auto"\n'
                )
                self.assertEqual(age.required_age(self.PACKAGE), timedelta(days=7))

    def test_invalid_and_unsupported_configuration_fails_closed(self) -> None:
        cases = (
            '[cooldown]\nincompatible-publish-age = "off"',
            '[cooldown]\nlockfile-baseline = "anything"',
            "[cooldown]\nfallback-accept = true",
            "[cooldown]\nunknown = true",
            "[allow]\nexact = {}",
            "[allow]\npackage = [1]",
            '[[allow.exact]]\ncrate = "demo"',
            '[[allow.exact]]\ncrate = "*"\nversion = "1.2.3"',
            '[[allow.exact]]\ncrate = "demo"\nversion = 1',
            '[[allow.package]]\ncrate = "demo"',
            '[[allow.package]]\ncrate = "demo"\nmin-publish-age = "0"\nreason = "unsupported"',
            '[[allow.package]]\ncrate = "demo"\nmin-publish-age = "0"\n[[allow.package]]\ncrate = "demo"\nmin-publish-age = "1 day"',
            "[allow.global]\nminutes = 0",
            '[registries.internal]\nmin-publish-age = "0"',
        )
        for extra in cases:
            with self.subTest(extra=extra), self.assertRaises(CheckError):
                self.parse(extra)
        for contents in (
            b"",
            b"skip_registries = []",
            b"now = '2030-01-01'",
            b"registry = 7",
            b"[broken",
            b"\xff",
        ):
            with self.subTest(contents=contents), self.assertRaises(CheckError):
                parse_cooldown(contents)

    def test_each_revision_is_evaluated_before_taking_stricter_age(self) -> None:
        exact = self.parse('[[allow.exact]]\ncrate = "demo"\nversion = "1.2.3"\n')
        normal = self.parse()
        package = self.parse(
            '[[allow.package]]\ncrate = "demo"\nmin-publish-age = "1 day"\n'
        )
        for base, current, expected in (
            (normal, exact, 7),
            (exact, normal, 7),
            (exact, exact, 0),
            (exact, package, 1),
            (package, exact, 1),
        ):
            with self.subTest(base=base, current=current):
                policy = effective_policy(
                    Policy(age_policies=(current,)), Policy(age_policies=(base,))
                )
                self.assertEqual(
                    policy.required_age(self.PACKAGE), timedelta(days=expected)
                )
        # An exception in the stricter global policy must be evaluated before
        # comparing against the other revision's unexcepted shorter default.
        base = AgePolicy(timedelta(days=14), frozenset({self.PACKAGE}))
        policy = effective_policy(
            Policy(age_policies=(normal,)), Policy(age_policies=(base,))
        )
        self.assertEqual(policy.required_age(self.PACKAGE), timedelta(days=7))

    def test_exceptions_do_not_bypass_metadata_failures(self) -> None:
        policy = Policy(age_policies=(AgePolicy(exact=frozenset({self.PACKAGE})),))
        now = datetime.now(timezone.utc)
        for record in (
            None,
            {"yanked": True},
            {"yanked": False},
            {"pubtime": "invalid"},
        ):
            indexes = (
                {"demo": {"1.2.3": record}} if record is not None else {"demo": {}}
            )
            with self.subTest(record=record), patch(
                "cargo_supply_chain.fetch_indexes", return_value=(indexes, {})
            ):
                self.assertEqual(
                    check_package_ages({self.PACKAGE: {"Cargo.lock"}}, policy, now), 1
                )
        with patch(
            "cargo_supply_chain.fetch_indexes",
            return_value=({}, {"demo": "network failure"}),
        ):
            self.assertEqual(
                check_package_ages({self.PACKAGE: {"Cargo.lock"}}, policy, now), 1
            )


class RepositoryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.previous = Path.cwd()
        self.addCleanup(os.chdir, self.previous)
        os.chdir(self.directory.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Policy test")
        Path("Cargo.lock").write_bytes(lockfile(("old", "1.0.0", CRATES_IO)))
        Path(".cargo-supply-chain.toml").write_text("[age]\nminimum-days = 7\n")
        self.commit()
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def commit(self) -> None:
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "test policy")

    def migrate(self, days: int = 7, extra: str = "") -> None:
        Path(".cargo-supply-chain.toml").write_text("schema-version = 1\n")
        Path("cooldown.toml").write_text(
            f'[registry]\nglobal-min-publish-age = "{days} days"\n' + extra
        )

    def test_legacy_migration_preserves_base_age(self) -> None:
        self.migrate(3)
        policy = resolve_policy(".cargo-supply-chain.toml", self.base)
        self.assertEqual(
            policy.required_age(Package("demo", "1.0.0")), timedelta(days=7)
        )

    def test_duplicate_age_sources_are_rejected(self) -> None:
        Path("cooldown.toml").write_text(CooldownConfigTests.HEADER)
        with self.assertRaisesRegex(CheckError, r"remove \[age\]"):
            load_policy(".cargo-supply-chain.toml")

    def test_deleting_cooldown_cannot_relax_base_policy(self) -> None:
        self.migrate(14)
        self.commit()
        Path("cooldown.toml").unlink()
        policy = resolve_policy(".cargo-supply-chain.toml", "HEAD")
        self.assertEqual(
            policy.required_age(Package("demo", "1.0.0")), timedelta(days=14)
        )

    def test_missing_files_preserve_seven_day_default(self) -> None:
        Path(".cargo-supply-chain.toml").unlink()
        self.assertEqual(load_policy(".cargo-supply-chain.toml"), Policy())

    def test_override_cannot_be_bypassed_by_exceptions(self) -> None:
        self.migrate(extra='[[allow.exact]]\ncrate = "demo"\nversion = "1.0.0"\n')
        self.commit()
        policy = resolve_policy(".cargo-supply-chain.toml", "HEAD", 10)
        self.assertEqual(
            policy.required_age(Package("demo", "1.0.0")), timedelta(days=10)
        )

    def run_checker(self, base: str) -> int:
        record = {"pubtime": datetime.now(timezone.utc).isoformat(), "yanked": False}
        indexes = {
            "demo": {"1.0.0": record},
            "transitive": {"1.0.0": record},
            "arrayref": {"0.3.10": record},
        }
        lock_path = Path(self.directory.name) / "Cargo.lock"
        original_lock = lock_path.read_bytes()
        with patch.object(sys, "argv", ["checker", "check", "--base-ref", base]), patch(
            "cargo_supply_chain.fetch_indexes", return_value=(indexes, {})
        ), patch(
            "cargo_supply_chain.subprocess.run", wraps=subprocess.run
        ) as commands, redirect_stdout(
            io.StringIO()
        ), redirect_stderr(
            io.StringIO()
        ):
            result = main()
        self.assertEqual(lock_path.read_bytes(), original_lock)
        self.assertTrue(
            all(call.args[0][0] == "git" for call in commands.call_args_list)
        )
        return result

    def test_exception_must_land_before_dependency_and_does_not_cover_transitives(
        self,
    ) -> None:
        self.migrate(extra='[[allow.exact]]\ncrate = "demo"\nversion = "1.0.0"\n')
        # Policy-only change can land; adding the fresh dependency in the same
        # PR cannot use that new exception.
        self.assertEqual(self.run_checker(self.base), 0)
        original = Path("Cargo.lock").read_bytes()
        Path("Cargo.lock").write_bytes(lockfile(("demo", "1.0.0", CRATES_IO)))
        self.assertEqual(self.run_checker(self.base), 1)
        Path("Cargo.lock").write_bytes(original)
        self.commit()
        approved_base = self.git("rev-parse", "HEAD")
        Path("Cargo.lock").write_bytes(lockfile(("demo", "1.0.0", CRATES_IO)))
        self.assertEqual(self.run_checker(approved_base), 0)
        Path("Cargo.lock").write_bytes(
            lockfile(("demo", "1.0.0", CRATES_IO), ("transitive", "1.0.0", CRATES_IO))
        )
        self.assertEqual(self.run_checker(approved_base), 1)

    def test_approved_exception_cannot_override_incident_denylist(self) -> None:
        self.migrate(extra='[[allow.exact]]\ncrate = "arrayref"\nversion = "0.3.10"\n')
        self.commit()
        Path("Cargo.lock").write_bytes(lockfile(("arrayref", "0.3.10", CRATES_IO)))
        self.assertEqual(self.run_checker("HEAD"), 1)

    def test_checker_resolves_config_at_repo_root_from_nested_directory(self) -> None:
        self.migrate()
        Path("nested").mkdir()
        os.chdir("nested")
        self.assertEqual(self.run_checker(self.base), 0)


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
        violation = policy_violation(self.PACKAGE, record, self.NOW, self.MINIMUM_AGE)
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
            age_policies=(AgePolicy(timedelta(days=9)),),
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
