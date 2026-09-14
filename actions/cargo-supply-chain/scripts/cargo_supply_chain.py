#!/usr/bin/env python3
"""Enforce reusable Cargo dependency supply-chain policy."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import quote

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11, used by some local development hosts.
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULT_MINIMUM_AGE_DAYS = 14
CONFIG_SCHEMA_VERSION = 1
COOLDOWN_CONFIG_PATH = "cooldown.toml"
CRATES_IO_INDEXES = {
    "https://github.com/rust-lang/crates.io-index",
    "https://index.crates.io",
}
INDEX_BASE_URL = "https://index.crates.io"
USER_AGENT = (
    "FairgateLabs-BitVMX-CI-cargo-supply-chain/1.0 "
    "(+https://github.com/FairgateLabs/BitVMX-CI)"
)
COMPROMISED_RELEASES = {
    ("append-only-vec", "0.1.9"),
    ("arrayref", "0.3.10"),
    ("internment", "0.8.7"),
}
MALICIOUS_CRATES = {
    "aovine",
    "arone",
    "aronenao",
    "proc-macro-en",
    "proc-macro1",
    "tinymember",
}
CARGO_DENY_CHECKS = ("advisories", "bans", "licenses", "sources")


class CheckError(Exception):
    """An operational or configuration error that must fail closed."""


@dataclass(frozen=True, order=True)
class Package:
    name: str
    version: str

    def __str__(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(frozen=True)
class CargoDenyPolicy:
    enabled: bool = False
    config: str = "deny.toml"
    manifests: tuple[str, ...] = ("Cargo.toml",)
    checks: tuple[str, ...] = CARGO_DENY_CHECKS


@dataclass(frozen=True)
class CargoVetPolicy:
    enabled: bool = False
    manifests: tuple[str, ...] = ("Cargo.toml",)
    locked: bool = True


@dataclass(frozen=True)
class AgePolicy:
    minimum_age: timedelta = timedelta(days=DEFAULT_MINIMUM_AGE_DAYS)
    exact: frozenset[Package] = frozenset()
    packages: tuple[tuple[str, timedelta], ...] = ()

    def required_age(self, package: Package) -> timedelta:
        if package in self.exact:
            return timedelta(0)
        for name, minimum_age in self.packages:
            if name == package.name:
                return min(self.minimum_age, minimum_age)
        return self.minimum_age


@dataclass(frozen=True)
class Policy:
    # Keep each revision's age rules separate: merging allowlists would let a
    # PR authorize its own exceptions or broaden an already-approved exception.
    age_policies: tuple[AgePolicy, ...] = (AgePolicy(),)
    cargo_deny: CargoDenyPolicy = CargoDenyPolicy()
    cargo_vet: CargoVetPolicy = CargoVetPolicy()

    @property
    def minimum_age(self) -> timedelta:
        return max(age.minimum_age for age in self.age_policies)

    def required_age(self, package: Package) -> timedelta:
        return max(age.required_age(package) for age in self.age_policies)


def reject_unknown_keys(
    table: Mapping[str, Any], allowed: set[str], location: str
) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise CheckError(f"unknown key(s) in {location}: {', '.join(unknown)}")


def table_value(root: Mapping[str, Any], key: str, location: str) -> Mapping[str, Any]:
    value = root.get(key, {})
    if not isinstance(value, dict):
        raise CheckError(f"{location}.{key} must be a TOML table")
    return value


def boolean_value(table: Mapping[str, Any], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise CheckError(f"{key} must be a boolean")
    return value


def repository_path(value: object, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise CheckError(f"{location} must be a non-empty string")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise CheckError(f"{location} must stay within the repository: {value}")
    return path.as_posix()


def path_list(value: object, location: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise CheckError(f"{location} must be a non-empty array")
    paths = tuple(repository_path(item, location) for item in value)
    if len(paths) != len(set(paths)):
        raise CheckError(f"{location} contains duplicate paths")
    return paths


def parse_toml(contents: bytes, path: str) -> Mapping[str, Any]:
    try:
        return tomllib.loads(contents.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CheckError(f"failed to parse {path}: {error}") from error


def parse_duration(value: object, location: str) -> timedelta:
    """Match cargo-cooldown's `0` / integer + singular or plural unit syntax."""
    if not isinstance(value, str):
        raise CheckError(f"{location} must be a duration string")
    value = value.strip()
    if value == "0":
        return timedelta(0)
    parts = value.split()
    units = {
        "second": 1,
        "minute": 60,
        "hour": 3600,
        "day": 86400,
        "week": 604800,
        "month": 2592000,
    }
    if (
        len(parts) != 2
        or re.fullmatch(r"[+]?[0-9]+", parts[0]) is None
        or parts[1] not in {unit + suffix for unit in units for suffix in ("", "s")}
    ):
        raise CheckError(
            f"{location}: invalid duration; expected 0 or N seconds/minutes/hours/days/weeks/months"
        )
    try:
        seconds = int(parts[0]) * units[parts[1].removesuffix("s")]
        if seconds > 2**64 - 1:
            raise OverflowError
        return timedelta(seconds=seconds)
    except (ValueError, OverflowError) as error:
        raise CheckError(f"{location}: duration is too large") from error


def parse_cooldown(contents: bytes, path: str = COOLDOWN_CONFIG_PATH) -> AgePolicy:
    root = parse_toml(contents, path)
    # This is deliberately a supported subset, not a second Cargo resolver.
    # Unsupported policy knobs must fail closed rather than silently diverge.
    reject_unknown_keys(root, {"registry", "cooldown", "allow"}, path)
    registry = table_value(root, "registry", path)
    reject_unknown_keys(
        registry, {"global-min-publish-age", "min-publish-age"}, f"{path} [registry]"
    )
    if "global-min-publish-age" not in registry:
        raise CheckError(f"{path} must set registry.global-min-publish-age explicitly")
    minimum_age = parse_duration(
        registry["global-min-publish-age"], f"{path} registry.global-min-publish-age"
    )
    if "min-publish-age" in registry:
        minimum_age = parse_duration(
            registry["min-publish-age"], f"{path} registry.min-publish-age"
        )

    cooldown = table_value(root, "cooldown", path)
    choices = {
        "incompatible-publish-age": ("deny", "fallback", "allow"),
        "lockfile-baseline": ("floor", "ignore"),
        "fallback-accept": ("prompt", "auto"),
    }
    reject_unknown_keys(cooldown, set(choices), f"{path} [cooldown]")
    for key, value in cooldown.items():
        if value not in choices[key]:
            raise CheckError(
                f"{path} cooldown.{key} must be one of: {', '.join(choices[key])}"
            )
    # The validated resolver settings above never change CI's rejection or base
    # comparison behavior, even when a developer selects fallback/allow/ignore.
    allow = table_value(root, "allow", path)
    reject_unknown_keys(allow, {"exact", "package"}, f"{path} [allow]")
    exact: set[Package] = set()
    packages: dict[str, timedelta] = {}
    for kind in ("exact", "package"):
        entries = allow.get(kind, [])
        if not isinstance(entries, list):
            raise CheckError(f"{path} allow.{kind} must be an array of tables")
        for entry in entries:
            location = f"{path} [[allow.{kind}]]"
            if not isinstance(entry, dict):
                raise CheckError(f"{location} must be a table")
            required = {"crate", "version" if kind == "exact" else "min-publish-age"}
            reject_unknown_keys(entry, required, location)
            if not required <= entry.keys():
                raise CheckError(f"{location} requires {', '.join(sorted(required))}")
            name = entry["crate"]
            if (
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9_-]+", name) is None
            ):
                raise CheckError(
                    f"{location}.crate must be a crate name, not a pattern"
                )
            if kind == "exact":
                version = entry["version"]
                if (
                    not isinstance(version, str)
                    or not version
                    or version.strip() != version
                ):
                    raise CheckError(
                        f"{location}.version must be a non-empty exact version string"
                    )
                exact.add(Package(name, version))
            else:
                if name in packages:
                    raise CheckError(f"{location}: duplicate package rule for {name}")
                packages[name] = parse_duration(
                    entry["min-publish-age"], f"{location}.min-publish-age"
                )
    return AgePolicy(minimum_age, frozenset(exact), tuple(packages.items()))


def parse_policy(contents: bytes, path: str) -> Policy:
    root = parse_toml(contents, path)
    reject_unknown_keys(
        root,
        {"schema-version", "age", "cargo-deny", "cargo-vet"},
        path,
    )
    schema_version = root.get("schema-version", CONFIG_SCHEMA_VERSION)
    if type(schema_version) is not int or schema_version != CONFIG_SCHEMA_VERSION:
        raise CheckError(f"{path} schema-version must be {CONFIG_SCHEMA_VERSION}")

    age = table_value(root, "age", path)
    reject_unknown_keys(age, {"minimum-days"}, f"{path} [age]")
    minimum_age_days = age.get("minimum-days", DEFAULT_MINIMUM_AGE_DAYS)
    if type(minimum_age_days) is not int or minimum_age_days < 1:
        raise CheckError(f"{path} age.minimum-days must be an integer of at least 1")

    deny = table_value(root, "cargo-deny", path)
    reject_unknown_keys(
        deny,
        {"enabled", "config", "manifests", "checks"},
        f"{path} [cargo-deny]",
    )
    deny_checks_value = deny.get("checks", list(CARGO_DENY_CHECKS))
    if not isinstance(deny_checks_value, list) or not deny_checks_value:
        raise CheckError(f"{path} cargo-deny.checks must be a non-empty array")
    if not all(isinstance(check, str) for check in deny_checks_value):
        raise CheckError(f"{path} cargo-deny.checks must contain only strings")
    unknown_checks = sorted(set(deny_checks_value) - set(CARGO_DENY_CHECKS))
    if unknown_checks:
        raise CheckError(
            f"unsupported cargo-deny check(s) in {path}: {', '.join(unknown_checks)}"
        )
    deny_checks = tuple(
        check for check in CARGO_DENY_CHECKS if check in deny_checks_value
    )
    cargo_deny = CargoDenyPolicy(
        enabled=boolean_value(deny, "enabled", False),
        config=repository_path(deny.get("config", "deny.toml"), "cargo-deny.config"),
        manifests=path_list(
            deny.get("manifests", ["Cargo.toml"]), "cargo-deny.manifests"
        ),
        checks=deny_checks,
    )

    vet = table_value(root, "cargo-vet", path)
    reject_unknown_keys(
        vet,
        {"enabled", "manifests", "locked"},
        f"{path} [cargo-vet]",
    )
    cargo_vet = CargoVetPolicy(
        enabled=boolean_value(vet, "enabled", False),
        manifests=path_list(
            vet.get("manifests", ["Cargo.toml"]), "cargo-vet.manifests"
        ),
        locked=boolean_value(vet, "locked", True),
    )

    return Policy(
        age_policies=(AgePolicy(timedelta(days=minimum_age_days)),),
        cargo_deny=cargo_deny,
        cargo_vet=cargo_vet,
    )


def ensure_base_ref(base_ref: str) -> None:
    try:
        subprocess.run(
            ["git", "rev-parse", "--verify", f"{base_ref}^{{commit}}"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as error:
        raise CheckError(f"base revision does not exist locally: {base_ref}") from error


def read_base_file(base_ref: str, path: str) -> bytes | None:
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{base_ref}:{path}"],
        capture_output=True,
    )
    if exists.returncode != 0:
        return None
    try:
        return subprocess.run(
            ["git", "show", f"{base_ref}:{path}"],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise CheckError(f"failed to read {path} at {base_ref}") from error


def load_policy(path: str, base_ref: str | None = None) -> Policy:
    def read(path: str) -> bytes | None:
        if base_ref is not None:
            return read_base_file(base_ref, path)
        config = Path(path)
        return config.read_bytes() if config.exists() else None

    contents = read(path)
    location = f"{path} at {base_ref}" if base_ref else path
    policy = parse_policy(contents, location) if contents is not None else Policy()
    cooldown = read(COOLDOWN_CONFIG_PATH)
    if cooldown is not None:
        if contents is not None and "age" in parse_toml(contents, location):
            raise CheckError(f"{location}: remove [age] when using root cooldown.toml")
        location = (
            f"{COOLDOWN_CONFIG_PATH} at {base_ref}"
            if base_ref
            else COOLDOWN_CONFIG_PATH
        )
        return replace(policy, age_policies=(parse_cooldown(cooldown, location),))
    # Legacy fallback lets consumers migrate without changing the base policy.
    return policy


def ordered_union(first: Sequence[str], second: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*first, *second)))


def effective_policy(current: Policy, base: Policy) -> Policy:
    """Prevent a PR from weakening its own dependency policy."""

    deny_enabled = current.cargo_deny.enabled or base.cargo_deny.enabled
    if current.cargo_deny.enabled:
        deny_config = current.cargo_deny.config
    else:
        deny_config = base.cargo_deny.config
    deny_manifests = ordered_union(
        base.cargo_deny.manifests if base.cargo_deny.enabled else (),
        current.cargo_deny.manifests if current.cargo_deny.enabled else (),
    )
    deny_checks = tuple(
        check
        for check in CARGO_DENY_CHECKS
        if (
            (base.cargo_deny.enabled and check in base.cargo_deny.checks)
            or (current.cargo_deny.enabled and check in current.cargo_deny.checks)
        )
    )

    vet_enabled = current.cargo_vet.enabled or base.cargo_vet.enabled
    vet_manifests = ordered_union(
        base.cargo_vet.manifests if base.cargo_vet.enabled else (),
        current.cargo_vet.manifests if current.cargo_vet.enabled else (),
    )

    return Policy(
        age_policies=tuple(dict.fromkeys((*base.age_policies, *current.age_policies))),
        cargo_deny=CargoDenyPolicy(
            enabled=deny_enabled,
            config=deny_config,
            manifests=deny_manifests or current.cargo_deny.manifests,
            checks=deny_checks or current.cargo_deny.checks,
        ),
        cargo_vet=CargoVetPolicy(
            enabled=vet_enabled,
            manifests=vet_manifests or current.cargo_vet.manifests,
            locked=(
                current.cargo_vet.locked
                or (base.cargo_vet.enabled and base.cargo_vet.locked)
            ),
        ),
    )


def resolve_policy(
    config_path: str,
    base_ref: str,
    minimum_age_override: int | None = None,
) -> Policy:
    repository_path(config_path, "config path")
    current = load_policy(config_path)
    base = load_policy(config_path, base_ref)
    policy = effective_policy(current, base)
    if minimum_age_override is not None:
        if minimum_age_override < 1:
            raise CheckError("minimum age override must be at least 1")
        policy = replace(
            policy,
            age_policies=(
                *policy.age_policies,
                AgePolicy(timedelta(days=minimum_age_override)),
            ),
        )
    return policy


def is_crates_io_source(source: object) -> bool:
    if not isinstance(source, str) or not source.startswith("registry+"):
        return False
    return source.removeprefix("registry+").rstrip("/") in CRATES_IO_INDEXES


def package_fields(contents: bytes, path: str) -> list[dict[str, object]]:
    try:
        lockfile = contents.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CheckError(f"failed to parse {path}: {error}") from error

    packages: list[dict[str, object]] = []
    for block in lockfile.split("[[package]]")[1:]:
        fields: dict[str, object] = {}
        for line in block.splitlines():
            key, separator, value = line.partition(" = ")
            if separator and key in {"name", "version", "source"}:
                try:
                    fields[key] = json.loads(value)
                except json.JSONDecodeError as error:
                    raise CheckError(f"failed to parse {path}: {error}") from error
        if not isinstance(fields.get("name"), str) or not isinstance(
            fields.get("version"), str
        ):
            raise CheckError(f"package is missing a name or version in {path}")
        packages.append(fields)
    return packages


def packages_from_lockfile(contents: bytes, path: str) -> set[Package]:
    return {
        Package(fields["name"], fields["version"])
        for fields in package_fields(contents, path)
        if is_crates_io_source(fields.get("source"))
    }


def all_packages_from_lockfile(contents: bytes, path: str) -> set[Package]:
    return {
        Package(fields["name"], fields["version"])
        for fields in package_fields(contents, path)
    }


def tracked_lockfiles() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "*Cargo.lock"],
        check=True,
        capture_output=True,
    )
    paths = [path for path in result.stdout.decode().split("\0") if path]
    if not paths:
        raise CheckError("no tracked Cargo.lock files found")
    return paths


def load_current_lockfiles(paths: Sequence[str]) -> dict[str, bytes]:
    return {path: Path(path).read_bytes() for path in paths}


def load_base_lockfiles(base_ref: str, paths: Sequence[str]) -> dict[str, bytes]:
    lockfiles: dict[str, bytes] = {}
    for path in paths:
        contents = read_base_file(base_ref, path)
        if contents is not None:
            lockfiles[path] = contents
    return lockfiles


def newly_resolved_packages(
    current_lockfiles: Mapping[str, bytes],
    base_lockfiles: Mapping[str, bytes],
) -> dict[Package, set[str]]:
    new_packages: dict[Package, set[str]] = {}
    for path, contents in current_lockfiles.items():
        current = packages_from_lockfile(contents, path)
        base = packages_from_lockfile(base_lockfiles.get(path, b""), path)
        for package in current - base:
            new_packages.setdefault(package, set()).add(path)
    return new_packages


def incident_packages(
    current_lockfiles: Mapping[str, bytes],
) -> dict[Package, set[str]]:
    violations: dict[Package, set[str]] = {}
    for path, contents in current_lockfiles.items():
        for package in all_packages_from_lockfile(contents, path):
            if (
                package.name,
                package.version,
            ) in COMPROMISED_RELEASES or package.name in MALICIOUS_CRATES:
                violations.setdefault(package, set()).add(path)
    return violations


def crate_index_path(name: str) -> str:
    lowered = name.lower()
    if len(lowered) == 1:
        return f"1/{lowered}"
    if len(lowered) == 2:
        return f"2/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"


def parse_index(contents: bytes, name: str) -> dict[str, dict[str, Any]]:
    versions: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(contents.splitlines(), start=1):
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CheckError(
                f"invalid crates.io index entry for {name} on line {line_number}"
            ) from error
        record_name = record.get("name")
        if (
            isinstance(record_name, str)
            and record_name.lower() == name.lower()
            and isinstance(record.get("vers"), str)
        ):
            versions[record["vers"]] = record
    return versions


def fetch_index(name: str) -> dict[str, dict[str, Any]]:
    path = quote(crate_index_path(name), safe="/")
    request = urllib.request.Request(
        f"{INDEX_BASE_URL}/{path}",
        headers={"Accept": "text/plain", "User-Agent": USER_AGENT},
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return parse_index(response.read(), name)
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code != 429 and error.code < 500:
                break
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
        if attempt < 2:
            time.sleep(2**attempt)
    raise CheckError(f"failed to fetch crates.io metadata for {name}: {last_error}")


def fetch_indexes(
    names: set[str],
) -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, str]]:
    indexes: dict[str, dict[str, dict[str, Any]]] = {}
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(names))) as executor:
        futures = {executor.submit(fetch_index, name): name for name in names}
        for future in as_completed(futures):
            name = futures[future]
            try:
                indexes[name] = future.result()
            except CheckError as error:
                errors[name] = str(error)
    return indexes, errors


def parse_pubtime(value: object, package: Package) -> datetime:
    if not isinstance(value, str):
        raise CheckError(f"crates.io metadata has no publication time for {package}")
    try:
        published = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CheckError(f"invalid publication time for {package}: {value}") from error
    if published.tzinfo is None:
        raise CheckError(f"publication time has no timezone for {package}: {value}")
    return published


def policy_violation(
    package: Package,
    record: Mapping[str, Any] | None,
    now: datetime,
    minimum_age: timedelta,
) -> str | None:
    if record is None:
        return "is missing from the crates.io index (it may have been deleted)"
    if record.get("yanked") is True:
        return "is yanked on crates.io"
    published = parse_pubtime(record.get("pubtime"), package)
    try:
        eligible_at = published + minimum_age
    except OverflowError as error:
        raise CheckError(
            f"minimum age exceeds supported datetime range for {package}"
        ) from error
    if now < eligible_at:
        return (
            f"was published at {published.isoformat()} and is not eligible until "
            f"{eligible_at.isoformat()}"
        )
    return None


def emit_error(path: str, message: str) -> None:
    print(f"::error file={path}::{message}", flush=True)


def check_incidents(packages: Mapping[Package, set[str]]) -> int:
    for package, paths in sorted(packages.items()):
        emit_error(
            sorted(paths)[0],
            f"package from the arrayref supply-chain attack detected: {package}",
        )
    return len(packages)


def check_package_ages(
    packages: Mapping[Package, set[str]], policy: Policy, now: datetime
) -> int:
    if not packages:
        print("No newly resolved crates.io package versions found.")
        return 0
    print(
        f"Checking {len(packages)} newly resolved crates.io package version(s) "
        f"against a {policy.minimum_age.total_seconds() / 86400:g}-day default minimum age."
    )
    indexes, index_errors = fetch_indexes({package.name for package in packages})
    failures = 0
    for package, paths in sorted(packages.items()):
        minimum_age = policy.required_age(package)
        if minimum_age < policy.minimum_age:
            print(
                f"Age exception applied to {package}: {minimum_age.total_seconds():g} seconds minimum (metadata and incident checks still apply)."
            )
        try:
            violation = index_errors.get(package.name)
            if violation is None:
                violation = policy_violation(
                    package,
                    indexes[package.name].get(package.version),
                    now,
                    minimum_age,
                )
        except CheckError as error:
            violation = str(error)
        if violation is not None:
            emit_error(sorted(paths)[0], f"{package} {violation}")
            failures += 1
    return failures


def write_github_outputs(path: str | None, policy: Policy) -> None:
    if path is None:
        return
    with Path(path).open("a", encoding="utf-8") as output:
        output.write(
            f"minimum_age_days={policy.minimum_age.total_seconds() / 86400:g}\n"
        )
        output.write(f"cargo_deny_enabled={str(policy.cargo_deny.enabled).lower()}\n")
        output.write(f"cargo_vet_enabled={str(policy.cargo_vet.enabled).lower()}\n")


def validate_manifest_paths(manifests: Sequence[str], tool: str) -> None:
    missing = [manifest for manifest in manifests if not Path(manifest).is_file()]
    if missing:
        raise CheckError(f"{tool} manifest path(s) do not exist: {', '.join(missing)}")


def run_cargo_deny(policy: Policy) -> None:
    if not policy.cargo_deny.enabled:
        print("cargo-deny is disabled.")
        return
    validate_manifest_paths(policy.cargo_deny.manifests, "cargo-deny")
    for manifest in policy.cargo_deny.manifests:
        command = [
            "cargo",
            "deny",
            "--manifest-path",
            manifest,
            "--config",
            policy.cargo_deny.config,
            "--locked",
            "check",
            *policy.cargo_deny.checks,
        ]
        print(f"Running cargo-deny for {manifest}.", flush=True)
        subprocess.run(command, check=True)


def run_cargo_vet(policy: Policy) -> None:
    if not policy.cargo_vet.enabled:
        print("cargo-vet is disabled.")
        return
    validate_manifest_paths(policy.cargo_vet.manifests, "cargo-vet")
    for manifest in policy.cargo_vet.manifests:
        command = ["cargo", "vet", "--manifest-path", manifest]
        if policy.cargo_vet.locked:
            command.append("--locked")
        print(f"Running cargo-vet for {manifest}.", flush=True)
        subprocess.run(command, check=True)


def add_policy_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--config", default=".cargo-supply-chain.toml")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="run incident and package-age checks")
    add_policy_arguments(check)
    check.add_argument("--minimum-age-days", type=int)
    check.add_argument("--github-output")

    deny = subparsers.add_parser("run-cargo-deny")
    add_policy_arguments(deny)

    vet = subparsers.add_parser("run-cargo-vet")
    add_policy_arguments(vet)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        ensure_base_ref(args.base_ref)
        repository_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        os.chdir(repository_root)
        policy = resolve_policy(
            args.config,
            args.base_ref,
            getattr(args, "minimum_age_days", None),
        )
        if args.command == "run-cargo-deny":
            run_cargo_deny(policy)
            return 0
        if args.command == "run-cargo-vet":
            run_cargo_vet(policy)
            return 0

        paths = tracked_lockfiles()
        current = load_current_lockfiles(paths)
        base = load_base_lockfiles(args.base_ref, paths)
        incident_failures = check_incidents(incident_packages(current))
        age_failures = check_package_ages(
            newly_resolved_packages(current, base),
            policy,
            datetime.now(timezone.utc),
        )
        write_github_outputs(args.github_output, policy)
        failures = incident_failures + age_failures
        if failures:
            print(f"Rejected {failures} Cargo package version(s).", file=sys.stderr)
            return 1
        print("Cargo dependency supply-chain policy passed.")
        return 0
    except (CheckError, OSError, subprocess.CalledProcessError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
