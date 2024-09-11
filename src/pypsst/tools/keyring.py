from abc import ABC, abstractmethod
from .rsa_tools import RsaKeyPair


class AbstractKeyRing(ABC):
    """A keyring to hold a set of keys of the same type.
    
    The keyring is a class that can be used to hold set of keys under nicknames
    for easier use. All keys in storage are 
    """
    # PROPERTIES
    @abstractmethod
    @property
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
    def __getitem__(self, key:str) -> str:
        pass

    @abstractmethod
    def __setitem__(self, key:str, value:str) -> ...:
        pass

    @abstractmethod
    def __delitem__(self, key:str, value: str) -> ...:
        pass

    # KEY METHODS
    @abstractmethod
    def get_key(self, index: int) -> str:
        pass

    @abstractmethod
    def set_key(self, name: str, key: str, force:bool=False) -> ...:
        pass