"""This module contains all the abstract base classes for the package"""

from abc import ABC, abstractmethod
from typing import Any

class AbstractKeyPair(ABC):
    """An abstract class to represent a keypair"""

    @property
    @abstractmethod
    def public_key_string(self) -> str:
        pass

    @property
    @abstractmethod
    def public_key(self) -> bytes:
        pass

    @property
    @abstractmethod
    def nickname(self) -> str:
        pass
    
    @nickname.setter
    @abstractmethod
    def nickname(self, name: str) -> None:
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def __hash__(self) -> int:
        """Hash the public key."""
        pass

    @abstractmethod
    def __eq__(self, other: Any) -> bool:
        """Compare the hashes of the public keys."""
        pass

    @abstractmethod
    def generate_keypair(self) -> None:
        pass

    @abstractmethod
    def from_key(self, file: str) -> None:
        pass

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def signature_valid(self, data: bytes, signature: bytes) -> bool:
        pass

    @abstractmethod
    def encrypt(self, data: bytes, receiver_public_key: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes, sender_public_key: bytes) -> bytes:
        pass


class AbstractKeyRing(ABC):
    """A keyring to hold a set of keys of the same type.

    The keyring is a class that can be used to hold set of keys under nicknames
    for easier use. All keys in storage are of the same type and inherit from
    the AbstractKeyPair class.
    """

    # PROPERTIES
    @property
    @abstractmethod
    def key_type(self) -> str:
        pass

    # DUNDER METHODS
    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def __hash__(self) -> int:
        pass

    @abstractmethod
    def __len__(self) -> int:
        pass

    @abstractmethod
    def __contains__(self, key: str) -> bool:
        pass

    @abstractmethod
    def __getitem__(self, key: str) -> str:
        """Get the public key string from the keyring using the nickname."""
        pass

    @abstractmethod
    def __setitem__(self, key: str, value: str) -> ...:
        """Set the public key string in the keyring using the nickname."""
        pass

    @abstractmethod
    def __delitem__(self, key: str) -> ...:
        """Delete the public key string from the keyring using the nickname."""
        pass

    # KEY METHODS
    @abstractmethod
    def get_key(self, index: int) -> str:
        pass

    @abstractmethod
    def set_key(self, name: str, key: str, force: bool = False) -> ...:
        pass

    @abstractmethod
    def generate_keypair(self, nickname: str) -> ...:
        pass

    @abstractmethod
    def from_key(self, file: str, nickname: str) -> ...:
        pass

    @abstractmethod
    def sign(self, nickname: str, data: bytes) -> bytes:
        pass

    @abstractmethod
    def signature_valid(self, nickname: str, data: bytes, signature: bytes) -> bool:
        pass

    @abstractmethod
    def encrypt(self, nickname: str, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, nickname: str, data: bytes) -> bytes:
        pass
