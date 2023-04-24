# -*- coding: utf-8 -*-
from Crypto.Hash import SHA256, SHA512
from typing import Union
import time
import uuid


class Utils:
    """Some utilities that are used in multiple classes."""

    @staticmethod
    def get_timestamp() -> bytes:
        """Returns the current timestamp."""
        return str(time.time()).encode()

    @staticmethod
    def get_id() -> bytes:
        """
        Returns a random id.
        
        Uses uuid4 to generate a random id.
        """
        return str(uuid.uuid4().hex).encode()

    @classmethod
    def hash_data(
        cls, data: bytes, finalize=True, type="sha256"
    ) -> Union[bytes, SHA256.SHA256Hash, SHA512.SHA512Hash]:
        """
        Hash the given data.
        
        Parameters
        ----------
        data : bytes
            The data to hash.
        finalize : bool, optional
            If True, the hash will be finalized and the hexdigest will be
            returned. If False, the hash object will be returned. The default
            is True.
        type : str, optional
            The type of hash to use. Can be sha256 or sha512. The default is
            sha256.

        Returns
        -------
        bytes or SHA256Hash or SHA512Hash
            The hash of the data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if type == "sha256":
            return cls.sha256(data, finalize)
        elif type == "sha512":
            return cls.sha512(data, finalize)
        else:
            raise ValueError(
                "Invalid hash type {}, should be sha256 or sha512.".format(type)
            )

    @staticmethod
    def sha256(data: bytes, finalize: bool = True) -> Union[bytes, SHA256.SHA256Hash]:
        """
        Hash the given data with SHA256.
        
        Parameters
        ----------
        data : bytes
            The data to hash.
        finalize : bool, optional
            If True, the hash will be finalized and the hexdigest will be
            returned. If False, the hash object will be returned. The default
            is True.

        Returns
        -------
        bytes or SHA256Hash
            The hash of the data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if finalize:
            hash_data = SHA256.new(data=data)
            return hash_data.hexdigest().encode()
        else:
            return SHA256.new(data=data)

    @staticmethod
    def sha512(data: bytes, finalize: bool = True) -> Union[bytes, SHA512.SHA512Hash]:
        """
        Hash the given data with SHA512.
        
        Parameters
        ----------
        data : bytes
            The data to hash.
        finalize : bool, optional
            If True, the hash will be finalized and the hexdigest will be
            returned. If False, the hash object will be returned. The default
            is True.

        Returns
        -------
        bytes or SHA512Hash
            The hash of the data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if finalize:
            hash_data = SHA512.new(data=data)
            return hash_data.hexdigest().encode()
        else:
            return SHA512.new(data=data)
