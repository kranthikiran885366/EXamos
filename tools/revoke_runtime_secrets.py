#!/usr/bin/env python3
"""Overwrite and unlink ExamOS tmpfs secret files after key holders stop.

This revokes runtime files. It cannot guarantee physical RAM scrubbing after
power loss, erase a TPM's persistent objects, or wipe other processes' memory.
"""
import os
import stat
import sys

DIRECTORY = "/run/examos/secrets"
MAX_SECRET_BYTES = 65536
MAX_SECRET_FILES = 64


def revoke_open_directory(directory_fd: int, owner: int) -> int:
    metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner or metadata.st_mode & 0o077:
        raise ValueError("secret directory must be private and owned by the service authority")
    names = os.listdir(directory_fd)
    if len(names) > MAX_SECRET_FILES:
        raise ValueError("unexpected secret inventory size")
    handles = []
    try:
        # Validate every file before modifying any. Keep descriptors so a name
        # swap cannot redirect the overwrite into a different inode.
        for name in names:
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=directory_fd)
            handles.append((name, fd))
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1:
                raise ValueError("unexpected secret file type, ownership or hardlink")
            if info.st_size > MAX_SECRET_BYTES:
                raise ValueError("secret file exceeds the revocation bound")
        for name, fd in handles:
            remaining = os.fstat(fd).st_size
            zeroes = bytes(4096)
            while remaining:
                written = os.write(fd, zeroes[:min(remaining, len(zeroes))])
                if written <= 0:
                    raise OSError("short overwrite of runtime secret")
                remaining -= written
            os.fsync(fd)
            os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return len(handles)
    finally:
        for _, fd in handles:
            os.close(fd)


def main() -> int:
    try:
        try:
            fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return 0  # No unsealed secret files exist to revoke.
        try:
            count = revoke_open_directory(fd, 0)
        finally:
            os.close(fd)
        print(f"Revoked {count} runtime secret file(s)")
        return 0
    except (OSError, ValueError) as error:
        print(f"Runtime secret revocation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
