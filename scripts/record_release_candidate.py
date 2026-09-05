#!/usr/bin/env python3
"""Record a release firmware artifact without exposing per-device USB values."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True

from public_tree import repository_root, sha256_file
from security_profiles import SecurityProfileError, select_candidate_profile


class CandidateError(RuntimeError):
    """A release-candidate provenance requirement was not met."""


def git_output(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def command_output(root: Path, *args: str) -> str:
    return subprocess.run(
        list(args),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_features(root: Path, mcu: str, raw_features: str) -> tuple[list[str], set[str]]:
    features = sorted(set(filter(None, raw_features.split(","))))
    if not features or any(re.fullmatch(r"[a-z0-9-]+", item) is None for item in features):
        raise CandidateError("features must be a comma-separated list of Cargo feature names")

    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    feature_graph = cargo.get("features", {})
    known = set(feature_graph)
    unknown = set(features) - known
    if unknown:
        raise CandidateError(f"unknown Cargo features: {', '.join(sorted(unknown))}")

    expanded = set(features)
    pending = list(features)
    while pending:
        current = pending.pop()
        for dependency in feature_graph[current]:
            if dependency in known and dependency not in expanded:
                expanded.add(dependency)
                pending.append(dependency)

    required = {"ctaphid-bringup", "fido-stack", f"mcu-{mcu}"}
    missing = required - expanded
    if missing:
        raise CandidateError(f"missing release features: {', '.join(sorted(missing))}")

    forbidden = {
        "development-provisioning",
        "firmware-diagnostics",
        "storage-provisioning",
    }
    selected_forbidden = forbidden & expanded
    if selected_forbidden:
        raise CandidateError(
            f"release candidate enables forbidden features: {', '.join(sorted(selected_forbidden))}"
        )

    other_mcu = "mcu-esp32s3" if mcu == "esp32s2" else "mcu-esp32s2"
    if other_mcu in expanded:
        raise CandidateError("release candidate selects more than one MCU")
    return features, expanded


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mcu", required=True, choices=("esp32s2", "esp32s3"))
    parser.add_argument("--features", required=True)
    parser.add_argument("--security-profile", required=True)
    args = parser.parse_args()

    root = repository_root(__file__)
    artifact = args.artifact.expanduser().resolve()
    output = args.output.expanduser().resolve()

    try:
        if is_within(artifact, root) or is_within(output, root):
            raise CandidateError("artifact and manifest must stay outside the source repository")
        if not artifact.is_file() or artifact.is_symlink():
            raise CandidateError("artifact must be an existing regular file")
        if output.exists():
            raise CandidateError("output manifest already exists")
        if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise CandidateError("source tree is dirty")

        features, expanded_features = validate_features(root, args.mcu, args.features)
        security_profile = select_candidate_profile(
            root,
            args.security_profile,
            args.mcu,
            expanded_features,
        )
        feature_argument = ",".join(features)
        command = [
            "./tools/cargo-esp",
            "build",
            "--locked",
            "--release",
            "--no-default-features",
            "--features",
            feature_argument,
        ]
        manifest = {
            "schema": 1,
            "kind": "rissokey-firmware-candidate",
            "generated_at": datetime.now(UTC).isoformat(),
            "source": {
                "commit": git_output(root, "rev-parse", "HEAD"),
                "tree": git_output(root, "rev-parse", "HEAD^{tree}"),
                "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
                "partition_table_sha256": sha256_file(root / "partitions.csv"),
                "rust_toolchain_sha256": sha256_file(root / "rust-toolchain.toml"),
                "cargo_esp_wrapper_sha256": sha256_file(root / "tools/cargo-esp"),
            },
            "build": {
                "mcu": args.mcu,
                "profile": "release",
                "binary": "rissokey",
                "features": features,
                "command": command,
                "required_environment": [
                    "RISSO_KEY_MCU",
                    "RISSO_KEY_USB_PID",
                    "RISSO_KEY_USB_SERIAL",
                    "RISSO_KEY_USB_VID",
                ],
                "environment_values_recorded": False,
                "cargo_version": command_output(root, "cargo", "-vV"),
                "rustc_version": command_output(root, "rustc", "-vV"),
            },
            "security_profile": {
                "artifact_recording_allowed": security_profile[
                    "artifact_recording_allowed"
                ],
                "blocking_conditions": security_profile["blocking_conditions"],
                "id": args.security_profile,
                "profile_sha256": sha256_file(root / "policy/security-profiles.json"),
                "release_eligible": security_profile["release_eligible"],
                "security": security_profile["security"],
                "status": security_profile["status"],
            },
            "artifact": {
                "file": artifact.name,
                "size": artifact.stat().st_size,
                "sha256": sha256_file(artifact),
            },
        }

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (
        CandidateError,
        SecurityProfileError,
        OSError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"release candidate manifest failed: {error}", file=sys.stderr)
        return 1

    print(f"recorded release candidate manifest at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
