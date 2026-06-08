"""
Age encryption utilities for SubIO.

Aligns with mihomo's ``component/age/age.go`` API pattern:
- decrypt_bytes: auto-detect age-encrypted data, decrypt with secret keys,
  pass through non-encrypted data unchanged.
- encrypt_bytes: encrypt data with public keys, outputing age armor format.
- generate_x25519_keypair: generate a new X25519 key pair.
- verify / convert helpers for key management.

Uses ``pyrage`` (Rust ``rage`` bindings) for full compatibility with the
Go ``age`` library used by mihomo.
"""

from typing import Optional, Tuple

import pyrage
from pyrage import x25519
from pyrage.pyrage import DecryptError

# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

AGE_ARMOR_HEADER = "-----BEGIN AGE ENCRYPTED FILE-----"
"""PEM-armor header used to detect age-encrypted content (fast path)."""

AGE_BINARY_INTRO = "age-encryption.org/v1"
"""Binary age file intro string (fallback detection)."""


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def is_age_encrypted(data: bytes | str) -> bool:
    """Check whether *data* looks like age-encrypted content.

    Returns ``True`` if the data starts with the age armor header or the
    binary age intro string.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return data.startswith(AGE_ARMOR_HEADER.encode()) or data.startswith(
        AGE_BINARY_INTRO.encode()
    )


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------


def decrypt_bytes(data: bytes, *secret_keys: str) -> bytes:
    """Decrypt age-encrypted *data* using one or more *secret_keys*.

    If *data* is not age-encrypted it is returned unchanged (pass-through),
    ensuring backward compatibility with existing plain-text subscriptions.

    Parameters
    ----------
    data:
        The raw bytes to (possibly) decrypt.
    *secret_keys:
        One or more age secret key strings (``AGE-SECRET-KEY-1...``).
        At least one key must match a recipient in the encrypted data.

    Returns
    -------
    bytes:
        The decrypted plaintext, or the original *data* if it was not
        age-encrypted.

    Raises
    ------
    DecryptError:
        If *data* is age-encrypted but none of the provided keys can
        decrypt it.
    """
    if not is_age_encrypted(data):
        return data

    identities = _parse_identities(*secret_keys)
    if not identities:
        raise DecryptError("No valid secret keys provided for decryption")

    try:
        return pyrage.decrypt(data, identities)
    except DecryptError:
        raise
    except Exception as exc:
        raise DecryptError(f"Decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def encrypt_bytes(
    data: bytes | str, *public_keys: str, armored: bool = True
) -> bytes:
    """Encrypt *data* with one or more age *public_keys*.

    Parameters
    ----------
    data:
        The plaintext to encrypt (``bytes`` or ``str``).
    *public_keys:
        One or more age public key strings (``age1...``).
    armored:
        If ``True`` (the default), output the PEM-armored age format
        compatible with mihomo's config decryption.

    Returns
    -------
    bytes:
        The age-encrypted ciphertext.

    Raises
    ------
    ValueError:
        If *public_keys* is empty or none of them can be parsed.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    recipients = _parse_recipients(*public_keys)
    if not recipients:
        raise ValueError("No valid public keys provided for encryption")

    return pyrage.encrypt(data, recipients, armored=armored)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_x25519_keypair() -> Tuple[str, str]:
    """Generate a new X25519 key pair.

    Returns
    -------
    tuple[str, str]:
        ``(secret_key, public_key)`` where *secret_key* is an
        ``AGE-SECRET-KEY-1...`` string and *public_key* is an
        ``age1...`` string.
    """
    identity = x25519.Identity.generate()
    public_key = str(identity.to_public())
    return str(identity), public_key


# ---------------------------------------------------------------------------
# Key conversion
# ---------------------------------------------------------------------------


def secret_key_to_public(secret_key: str) -> str:
    """Extract the public key from an age *secret_key* string.

    Returns
    -------
    str:
        The corresponding public key (``age1...``).

    Raises
    ------
    ValueError:
        If *secret_key* cannot be parsed as a valid age identity.
    """
    identity = x25519.Identity.from_str(secret_key)
    return str(identity.to_public())


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_secret_key(secret_key: str) -> Optional[str]:
    """Validate a secret key string.

    Returns
    -------
    str | None:
        An error message if the key is invalid, or ``None`` if it is valid.
    """
    try:
        x25519.Identity.from_str(secret_key)
        return None
    except Exception as exc:
        return str(exc)


def verify_public_key(public_key: str) -> Optional[str]:
    """Validate a public key string.

    Returns
    -------
    str | None:
        An error message if the key is invalid, or ``None`` if it is valid.
    """
    try:
        x25519.Recipient.from_str(public_key)
        return None
    except Exception as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_identities(*secret_keys: str):
    """Parse secret key strings into pyrage Identity objects.

    Invalid keys are silently skipped.
    """
    identities = []
    for sk in secret_keys:
        if not sk or not isinstance(sk, str):
            continue
        try:
            identities.append(x25519.Identity.from_str(sk))
        except Exception:
            continue
    return identities


def _parse_recipients(*public_keys: str):
    """Parse public key strings into pyrage Recipient objects.

    Invalid keys are silently skipped.
    """
    recipients = []
    for pk in public_keys:
        if not pk or not isinstance(pk, str):
            continue
        try:
            recipients.append(x25519.Recipient.from_str(pk))
        except Exception:
            continue
    return recipients
