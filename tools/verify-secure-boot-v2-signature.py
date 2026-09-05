#!/usr/bin/env python3
"""Verify an externally signed Secure Boot V2 image using a public key."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_common import is_within, sha256_file


EXPECTED_ESPTOOL_VERSION = "5.4.0"


class VerificationError(RuntimeError):
    """A Secure Boot V2 signature-verification requirement was not met."""


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    root = repository_root()
    image = args.image.expanduser().resolve()
    public_key = args.public_key.expanduser().resolve()
    output = args.output.expanduser().resolve()

    try:
        if is_within(image, root) or is_within(public_key, root) or is_within(output, root):
            raise VerificationError("image, public key, and evidence must stay outside Git")
        for path, label in ((image, "image"), (public_key, "public key")):
            if not path.is_file() or path.is_symlink():
                raise VerificationError(f"{label} must be an existing regular file")
        if output.exists():
            raise VerificationError("output evidence already exists")

        key_data = public_key.read_bytes()
        if b"PRIVATE KEY" in key_data:
            raise VerificationError("--public-key must not contain private key material")
        if b"BEGIN PUBLIC KEY" not in key_data and b"BEGIN RSA PUBLIC KEY" not in key_data:
            raise VerificationError("--public-key must be a PEM public key")

        tool_version = importlib.metadata.version("esptool")
        if tool_version != EXPECTED_ESPTOOL_VERSION:
            raise VerificationError(
                f"esptool must be {EXPECTED_ESPTOOL_VERSION}; found {tool_version}"
            )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "espsecure",
                "verify-signature",
                "--version",
                "2",
                "--keyfile",
                str(public_key),
                str(image),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        combined_output = result.stdout + result.stderr
        success_markers = (
            "Signature is valid",
            "verification successful using the supplied key",
        )
        if not any(marker in combined_output for marker in success_markers):
            raise VerificationError("espsecure did not report a valid signature")

        evidence = {
            "generated_at": datetime.now(UTC).isoformat(),
            "image": {
                "file": image.name,
                "sha256": sha256_file(image),
                "size": image.stat().st_size,
            },
            "kind": "rissokey-secure-boot-v2-signature-verification",
            "private_key_loaded": False,
            "public_key": {
                "file": public_key.name,
                "sha256": sha256_file(public_key),
            },
            "schema": 1,
            "secure_boot_version": 2,
            "tool": {
                "name": "espsecure",
                "package": "esptool",
                "version": tool_version,
            },
            "verified": True,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (
        VerificationError,
        OSError,
        subprocess.CalledProcessError,
        importlib.metadata.PackageNotFoundError,
    ) as error:
        print(f"Secure Boot V2 verification failed: {error}", file=sys.stderr)
        return 1

    print(f"verified Secure Boot V2 signature and recorded {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
