"""Signing-key custody for the four v3.4.0 identities (PR-08).

The system has four principals and they must not share a key:

    agent                 executes the task, never signs evidence
    serving_authority     issues AuthorizationV2
    evaluator             measures the attempt, signs EvaluatorReceiptV2
    promotion_authority   promotes or revokes candidates

A seed that any process can read is not custody. This module keeps seeds
on disk with owner-only permissions, loads one only for the duration of a
single signature, and refuses a deployment where two roles share a key —
because a shared key means the evaluator can mint promotion evidence, and
"independent evaluation" stops meaning anything.

Nothing here ever returns a seed. ``CustodianKey`` carries a path and a
public key; ``sign`` reads the file, signs, and drops the buffer.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from . import signatures

AGENT = "agent"
SERVING_AUTHORITY = "serving_authority"
EVALUATOR = "evaluator"
PROMOTION_AUTHORITY = "promotion_authority"

ROLES = (AGENT, SERVING_AUTHORITY, EVALUATOR, PROMOTION_AUTHORITY)
SIGNING_ROLES = (SERVING_AUTHORITY, EVALUATOR, PROMOTION_AUTHORITY)

_GROUP_OTHER_BITS = 0o077


class CustodyError(RuntimeError):
    """A key-custody rule was violated; the deployment must not start."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class CustodianKey:
    """A public identity plus the path to its owner-only seed."""

    role: str
    key_id: str
    public_hex: str
    seed_path: Path

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise CustodyError("unknown_role", self.role)
        if not (isinstance(self.public_hex, str) and len(self.public_hex) == 64):
            raise CustodyError("public_key_invalid", self.role)

    def __repr__(self) -> str:  # never leak the path into logs
        return (f"CustodianKey(role={self.role!r}, key_id={self.key_id!r},"
                f" public_hex={self.public_hex[:8]}…)")


class KeyCustody:
    """Enrolls one owner-only seed per role and signs on demand."""

    def __init__(self, root: str | Path, *,
                 require_distinct_identities: bool = True) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._require_distinct = bool(require_distinct_identities)
        self._keys: dict[str, CustodianKey] = {}

    # -- enrollment ---------------------------------------------------- #
    def enroll(self, role: str, seed_path: str | Path) -> CustodianKey:
        """Register an existing seed file, enforcing custody rules."""
        if role not in SIGNING_ROLES:
            raise CustodyError("role_cannot_sign", role)
        path = Path(seed_path)
        self._check_seed_file(path)
        seed = path.read_bytes()
        if len(seed) != 32:
            raise CustodyError("seed_malformed", role)
        public = signatures.public_key(seed).hex()
        key_id = role + "-" + public[:24]
        key = CustodianKey(role=role, key_id=key_id, public_hex=public,
                           seed_path=path)
        self._register(key)
        return key

    def create(self, role: str, *, filename: str | None = None) -> CustodianKey:
        """Generate a fresh seed with owner-only permissions."""
        if role not in SIGNING_ROLES:
            raise CustodyError("role_cannot_sign", role)
        path = self.root / (filename or f"{role}.seed")
        if path.exists():
            raise CustodyError("seed_already_exists", role)
        seed, public = signatures.generate_keypair()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(seed)
        finally:
            del seed
        os.chmod(path, 0o600)
        key = CustodianKey(role=role, key_id=role + "-" + public.hex()[:24],
                           public_hex=public.hex(), seed_path=path)
        self._register(key)
        return key

    def _register(self, key: CustodianKey) -> None:
        if key.role in self._keys:
            raise CustodyError("role_already_enrolled", key.role)
        if self._require_distinct:
            for existing in self._keys.values():
                if existing.public_hex == key.public_hex:
                    raise CustodyError(
                        "identities_share_a_key",
                        f"{existing.role}={key.role}")
        self._keys[key.role] = key

    # -- use ----------------------------------------------------------- #
    def key(self, role: str) -> CustodianKey:
        key = self._keys.get(role)
        if key is None:
            raise CustodyError("role_not_enrolled", role)
        return key

    def sign(self, role: str, message: bytes) -> bytes:
        """Sign one message; the seed is referenced only inside this call.

        Python bytes are immutable, so the rebinding below drops this
        reference rather than wiping the buffer; the guarantee is that the
        seed is never returned, never stored on the object, and never
        logged, not that the memory is zeroed.
        """
        key = self.key(role)
        self._check_seed_file(key.seed_path)
        seed = key.seed_path.read_bytes()
        try:
            if len(seed) != 32:
                raise CustodyError("seed_malformed", role)
            return signatures.sign(seed, message)
        finally:
            seed = b"\x00" * 32
            del seed

    def public(self, role: str) -> str:
        return self.key(role).public_hex

    def trusted_keys(self, *roles: str) -> dict[str, str]:
        """Map key id -> public hex for the roles a verifier trusts."""
        out: dict[str, str] = {}
        for role in roles:
            key = self.key(role)
            out[key.key_id] = key.public_hex
        return out

    # -- reporting ----------------------------------------------------- #
    def custody_report(self) -> dict:
        """Machine-readable custody state for release qualification.

        Reports roles, key ids and file modes. It never reports a seed and
        never reports a full public key beyond what is already public.
        """
        roles = []
        for role in ROLES:
            key = self._keys.get(role)
            if key is None:
                roles.append({"role": role, "enrolled": False})
                continue
            mode = stat.S_IMODE(key.seed_path.stat().st_mode)
            roles.append({
                "role": role,
                "enrolled": True,
                "key_id": key.key_id,
                "public_prefix": key.public_hex[:16],
                "seed_mode": oct(mode),
                "owner_only": mode & _GROUP_OTHER_BITS == 0,
            })
        distinct = len({k.public_hex for k in self._keys.values()}) == \
            len(self._keys)
        return {
            "schema_version": 1,
            "roles": roles,
            "enrolled_count": len(self._keys),
            "distinct_identities": distinct,
            "ready": distinct and EVALUATOR in self._keys
            and SERVING_AUTHORITY in self._keys,
        }

    @staticmethod
    def _check_seed_file(path: Path) -> None:
        try:
            info = path.stat()
        except OSError as exc:
            raise CustodyError("seed_unreadable", str(path)) from exc
        if not stat.S_ISREG(info.st_mode):
            raise CustodyError("seed_not_a_regular_file", str(path))
        if info.st_size != 32:
            raise CustodyError("seed_malformed", str(path))
        if info.st_mode & _GROUP_OTHER_BITS:
            # A group- or world-readable seed has no custody at all.
            raise CustodyError("seed_permissions_too_open", oct(
                stat.S_IMODE(info.st_mode)))
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            # Mode bits are not the whole story: a 0600 file owned by a
            # different principal is still not this principal's seed.
            raise CustodyError("seed_owner_mismatch", str(info.st_uid))


def four_identity_custody(root: str | Path) -> KeyCustody:
    """Create a fresh, distinct key for each signing role under ``root``."""
    custody = KeyCustody(root)
    for role in SIGNING_ROLES:
        custody.create(role)
    return custody


__all__ = [
    "AGENT",
    "CustodianKey",
    "CustodyError",
    "EVALUATOR",
    "KeyCustody",
    "PROMOTION_AUTHORITY",
    "ROLES",
    "SERVING_AUTHORITY",
    "SIGNING_ROLES",
    "four_identity_custody",
]
