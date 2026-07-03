# integrity/hash_checker.py
# Computes and verifies SHA-256 hashes for file integrity monitoring (FIM).


import hashlib
import os
import logging
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db

logger = logging.getLogger(__name__)

# In-memory baseline cache {filepath: hash}
_baseline_cache: dict[str, str] = {}


def compute_hash(filepath: str, chunk_size: int = 65536) -> str | None:
    # Compute SHA-256 of file in chunks
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError) as e:
        logger.warning("Cannot hash %s: %s", filepath, e)
        return None


def store_baseline(filepath: str) -> str | None:
    # Calculate and store baseline hash of a file
    file_hash = compute_hash(filepath)
    if file_hash is None:
        return None

    filename = os.path.basename(filepath)
    _baseline_cache[filepath] = file_hash

    db.insert_integrity_check(
        filename=filename,
        filepath=filepath,
        original_hash=file_hash,
        current_hash=file_hash,
        status="NEW"
    )
    logger.info("Baseline stored for %s: %s", filename, file_hash[:12])
    return file_hash


def verify_integrity(filepath: str) -> dict:
    # Compare current hash to stored baseline
    filename = os.path.basename(filepath)

    # File has been deleted
    if not os.path.exists(filepath):
        original = _baseline_cache.get(filepath)
        result = {
            "status": "DELETED",
            "original_hash": original,
            "current_hash": None,
            "filename": filename,
            "filepath": filepath,
        }
        db.insert_integrity_check(
            filename=filename,
            filepath=filepath,
            original_hash=original,
            current_hash=None,
            status="DELETED"
        )
        return result

    current_hash = compute_hash(filepath)

    # First time we're seeing this file — establish baseline
    if filepath not in _baseline_cache:
        # Try to load from DB
        baseline_row = db.get_integrity_baseline(filepath)
        if baseline_row:
            _baseline_cache[filepath] = baseline_row["original_hash"]
        else:
            # Brand new file
            if current_hash:
                _baseline_cache[filepath] = current_hash
            result = {
                "status": "NEW",
                "original_hash": current_hash,
                "current_hash": current_hash,
                "filename": filename,
                "filepath": filepath,
            }
            if current_hash:
                db.insert_integrity_check(
                    filename=filename,
                    filepath=filepath,
                    original_hash=current_hash,
                    current_hash=current_hash,
                    status="NEW"
                )
            return result

    original_hash = _baseline_cache[filepath]

    if current_hash == original_hash:
        status = "MATCH"
    else:
        status = "MISMATCH"
        logger.warning(
            "INTEGRITY MISMATCH: %s | was=%s | now=%s",
            filename, original_hash[:12], (current_hash or "")[:12]
        )

    db.insert_integrity_check(
        filename=filename,
        filepath=filepath,
        original_hash=original_hash,
        current_hash=current_hash,
        status=status
    )

    return {
        "status": status,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "filename": filename,
        "filepath": filepath,
    }


def update_baseline(filepath: str) -> str | None:
    # Update baseline to current file hash
    new_hash = compute_hash(filepath)
    if new_hash:
        _baseline_cache[filepath] = new_hash
        logger.info("Baseline updated for %s", os.path.basename(filepath))
    return new_hash


def is_sensitive_file(filepath: str) -> bool:
    # Check if file matches sensitive policies
    filename = os.path.basename(filepath).lower()
    if filename.startswith("~$"):
        return False
        
    ext = os.path.splitext(filename)[1].lower()

    if filename in {f.lower() for f in config.SENSITIVE_FILENAMES}:
        return True
    if ext in config.SENSITIVE_EXTENSIONS:
        return True
    for keyword in config.SENSITIVE_KEYWORDS:
        if keyword in filename:
            return True
    return False
