"""Minimal Python binding for mls-rs (Messaging Layer Security, RFC 9420).

A synchronous, byte-oriented API: create groups, manage membership, process
messages and export group secrets. Cryptographic state stays in Rust.

Read the README's security section before using this in an application:
BasicCredential identities are unverified labels unless you pass a verifier,
storage is in-memory unless you pass a file (which is not encrypted), and this
release is not post-quantum secure.
"""

from ._mls_py import (
    DEFAULT_CIPHER_SUITE,
    DEFAULT_MAX_MESSAGE_SIZE,
    ERROR_CODES,
    SUPPORTED_CIPHER_SUITES,
    Client,
    Event,
    Group,
    MlsError,
)

__all__ = [
    "Client",
    "Group",
    "Event",
    "MlsError",
    "SUPPORTED_CIPHER_SUITES",
    "DEFAULT_CIPHER_SUITE",
    "DEFAULT_MAX_MESSAGE_SIZE",
    "ERROR_CODES",
]

__version__ = "0.2.0"
