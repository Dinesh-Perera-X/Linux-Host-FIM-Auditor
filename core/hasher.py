import hashlib
import os
from typing import Optional, Dict, Any

class IntegrityHasher:
    """
    Computes cryptographic SHA-256 digests and extracts POSIX metadata
    (permissions, owner UID, group GID, file size, modification time).
    """

    @staticmethod
    def calculate_sha256(filepath: str, block_size: int = 65536) -> Optional[str]:
        """Calculates SHA-256 hash in blocks to efficiently handle large system binaries."""
        if not os.path.exists(filepath) or os.path.isdir(filepath):
            return None
        try:
            hasher = hashlib.sha256()
            with open(filepath, "rb") as f:
                for block in iter(lambda: f.read(block_size), b""):
                    hasher.update(block)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None

    @classmethod
    def get_file_metadata(cls, filepath: str) -> Optional[Dict[str, Any]]:
        """Extracts complete POSIX security attributes and checksum."""
        if not os.path.exists(filepath):
            return None
        try:
            stat_info = os.stat(filepath)
            sha256 = cls.calculate_sha256(filepath)
            return {
                "filepath": os.path.abspath(filepath),
                "sha256": sha256,
                "size_bytes": stat_info.st_size,
                "permissions_octal": oct(stat_info.st_mode & 0o777),
                "uid": stat_info.st_uid,
                "gid": stat_info.st_gid,
                "mtime": stat_info.st_mtime,
                "is_dir": os.path.isdir(filepath)
            }
        except (PermissionError, FileNotFoundError):
            return None
