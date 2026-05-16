"""Archive decompression — .tar.gz, .gz, nested archive handling.

Single module for all archive extraction logic.
Used by pipeline.py when processing uploaded log files.
"""

from pathlib import Path
import tarfile
import gzip
import shutil
import re


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract tar into dest with ZIP SLIP protection.

    Validates each member name contains no '..' path traversal before extracting.
    Raises ValueError if any member would escape the destination directory.
    """
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        if '..' in member.name or member.name.startswith('/'):
            raise ValueError(f"Unsafe path in archive: {member.name}")
        member_path = (dest / member.name).resolve()
        if not member_path.is_relative_to(dest_resolved):
            raise ValueError(f"Path traversal attempt: {member.name}")
    tar.extractall(dest)


def decompress_if_needed(path: Path, job_id: str) -> tuple[Path, list[Path]]:
    """Decompress .tar.gz, .gz, or nested tar files.

    Returns (primary_path, all_extracted_paths).
    Handles:
      - .tar.gz  → extract all; recurse into any inner .tar/.tar.gz found
      - Plain .gz → decompress to plain file (handles .log.gz, .txt.gz, etc.)
      - Nested tar → after extracting a tar.gz, check for inner .tar/.tar.gz members
                      and extract those too (one level of recursion)
    """
    if path.suffix.lower() == ".gz":
        if path.stem.endswith(".tar"):
            # It's a .tar.gz — extract all
            extract_dir = path.parent / f"{job_id}_extract"
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
            extract_dir.mkdir()
            with tarfile.open(path, "r:gz") as tar:
                _safe_extract(tar, extract_dir)
            # Recurse into any inner tar files (tar inside tar.gz)
            all_files = _extract_inner_archives(extract_dir, job_id)
            return extract_dir, all_files
        else:
            # Plain .gz — decompress to plain file so parsers can read it directly
            decompressed = path.parent / f"{job_id}_{path.stem}"
            with gzip.open(path, "rb") as f_in:
                with decompressed.open("wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return decompressed, [decompressed]
    return path, [path]


def _extract_inner_archives(extract_dir: Path, job_id: str) -> list:
    """Find and extract any .tar / .tar.gz members inside an extracted directory.

    One level of recursion only (no deep nesting).
    Returns flat list of all extracted file paths (top-level + inner archive contents).
    """
    all_files: list = []
    # Include top-level files from the outer tar.gz extraction
    for p in extract_dir.iterdir():
        if p.is_file():
            all_files.append(p)

    for p in extract_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix == ".tar":
            sub_dir = extract_dir / f"{job_id}_inner_{p.stem}"
            sub_dir.mkdir(exist_ok=True)
            with tarfile.open(p, "r:") as tar:
                _safe_extract(tar, sub_dir)
            all_files.extend(p for p in sub_dir.rglob("*") if p.is_file())
            all_files.append(p)
        elif p.suffix == ".gz" and p.stem.endswith(".tar"):
            sub_dir = extract_dir / f"{job_id}_inner_{p.stem}"
            sub_dir.mkdir(exist_ok=True)
            with tarfile.open(p, "r:gz") as tar:
                _safe_extract(tar, sub_dir)
            all_files.extend(p for p in sub_dir.rglob("*") if p.is_file())
            all_files.append(p)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique
