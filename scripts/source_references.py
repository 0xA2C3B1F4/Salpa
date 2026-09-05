"""Check local document links and declared Rust source files in a public file set.

This is a structural guard, not a replacement for compiling and testing the
actual export. Dynamic build inputs and external URLs are not followed.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


def missing_references(root: Path, paths: list[PurePosixPath]) -> list[str]:
    root = root.resolve()
    selected = {root / path for path in paths}
    failures = []

    def require_file(origin: PurePosixPath, target: Path) -> None:
        resolved = target.resolve()
        if not resolved.is_relative_to(root) or resolved not in selected or not resolved.is_file():
            reference = target.relative_to(root) if target.is_relative_to(root) else "outside export"
            failures.append(f"{origin}: missing public reference {reference}")

    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    for binary in manifest.get("bin", []):
        if "path" in binary:
            require_file(PurePosixPath("Cargo.toml"), root / binary["path"])

    for relative in paths:
        if relative.parts[0] == "third_party":
            continue
        path = root / relative
        if relative.suffix not in {".md", ".rs"}:
            continue
        text = path.read_text(encoding="utf-8")
        if relative.suffix == ".md":
            # Ignore fenced examples. Inline links use CommonMark destinations
            # without a title; angle-bracket destinations may contain spaces.
            text = re.sub(r"(?ms)^```.*?^```[^\n]*$", "", text)
            for link in re.findall(r"\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)", text):
                url = urlsplit(link.strip("<>"))
                if url.scheme or url.netloc or not url.path:
                    continue
                require_file(relative, path.parent / unquote(url.path))
        elif relative.suffix == ".rs":
            # Inline modules have braces and need no separate file. Explicit
            # #[path] overrides are resolved relative to their source file.
            pattern = r'(?P<attrs>(?:\s*#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>\w+)\s*;'
            for match in re.finditer(pattern, text):
                explicit = re.search(r'\bpath\s*=\s*"([^"]+)"', match['attrs'])
                if explicit:
                    require_file(relative, path.parent / explicit[1])
                    continue
                base = path.parent if path.name in {"lib.rs", "main.rs", "mod.rs", "build.rs"} else path.with_suffix("")
                candidates = [base / f"{match['name']}.rs", base / match['name'] / "mod.rs"]
                if not any(candidate in selected and candidate.is_file() for candidate in candidates):
                    require_file(relative, candidates[0])
    return sorted(set(failures))
