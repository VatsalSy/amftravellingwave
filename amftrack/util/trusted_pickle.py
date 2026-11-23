"""Load analysis pickles only after approval; approve the ones written here."""

import hashlib
import os
from pathlib import Path
import pickle
import re
from shutil import copyfileobj
import stat
from tempfile import SpooledTemporaryFile


def _trusted_digests():
    """Read SHA-256 values from a local manifest controlled by the operator."""
    manifest = Path.home() / ".config" / "amftrack" / "trusted-pickles.sha256"
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(manifest, flags), encoding="ascii") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("The trust manifest must be a regular file")
            if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
                raise ValueError("The trust manifest must be owner-only (mode 0600)")
            contents = source.read()
        digests = set()
        for line in contents.splitlines():
            entry = line.strip().lower()
            if not entry or entry.startswith("#"):
                continue
            if re.fullmatch(r"[0-9a-f]{64}", entry) is None:
                raise ValueError("Invalid SHA-256 entry in the trust manifest")
            digests.add(entry)
        return digests
    except OSError as error:
        raise ValueError(
            "Missing or unreadable local AMFTrack trust manifest: "
            "~/.config/amftrack/trusted-pickles.sha256"
        ) from error


class _HashingWriter:
    def __init__(self, stream, digest):
        self.stream = stream
        self.digest = digest

    def write(self, chunk):
        self.digest.update(chunk)
        return self.stream.write(chunk)


def load_trusted_pickle(path, *, loader=pickle.load):
    """Deserialize precisely the bytes whose SHA-256 an operator approved.

    Download endpoints, archive metadata and adjacent checksum files cannot
    establish trust. The private spool also protects against replacement
    between verification and deserialization.
    """
    digests = _trusted_digests()
    with open(path, "rb") as source, SpooledTemporaryFile(max_size=8 * 1024 * 1024) as verified:
        digest = hashlib.sha256()
        copyfileobj(source, _HashingWriter(verified, digest), length=1024 * 1024)
        if digest.hexdigest() not in digests:
            raise ValueError("Unapproved AMFTrack pickle; verify its source before adding its digest")
        verified.seek(0)
        return loader(verified)


def _enrol_digest(hexdigest):
    """Append one digest to the operator manifest, creating it owner-only."""
    manifest = Path.home() / ".config" / "amftrack" / "trusted-pickles.sha256"
    manifest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(manifest, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("The trust manifest must be a regular file")
        if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("The trust manifest must be owner-only (mode 0600)")
        # One short O_APPEND write, so concurrent jobs cannot interleave entries.
        os.write(descriptor, (hexdigest + "\n").encode("ascii"))
    finally:
        os.close(descriptor)


def dump_trusted_pickle(obj, path):
    """Pickle an object built by this process and approve the bytes written.

    Only call this on objects produced locally. The digest is taken from the
    serializer's output, not read back from the file, so a file replaced
    after the write is rejected on load.
    """
    digest = hashlib.sha256()
    with open(path, "wb") as target:
        pickle.dump(obj, _HashingWriter(target, digest))
    _enrol_digest(digest.hexdigest())
